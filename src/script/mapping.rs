use std::path::Path;

use anyhow::Result;
use elf::{Elf64ProgramHeaderFlags, Elf64SectionFlags, PF_R, PF_W, PF_X, RawReg};

use crate::{
    input::{FileId, object::InputSection},
    script::{ast::*, pattern},
};

pub(crate) struct MappingInput<'a> {
    pub(crate) file_name: String,
    pub(crate) section: InputSection<'a>,
}

pub(crate) struct MappedOutputSection<'s> {
    pub(crate) name: String,
    pub(crate) address: Option<&'s Expr>,
    pub(crate) statements: Vec<MappedStatement<'s>>,
    flags: u64,
    pub(crate) align: u64,
    orphan: bool,
}

pub(crate) enum MappedStatement<'s> {
    Assignment(&'s Assignment),
    Input(usize),
}

pub(crate) enum MappedItem<'s> {
    Assignment(&'s Assignment),
    Output(MappedOutputSection<'s>),
}

impl MappedOutputSection<'_> {
    fn orphan_class(&self, inputs: &[MappingInput]) -> (Elf64SectionFlags, bool) {
        let nobits = self.statements.iter().all(|statement| match statement {
            MappedStatement::Input(index) => inputs[*index].section.data.is_none(),
            _ => true,
        });
        orphan_class(self.flags, nobits)
    }

    pub(crate) fn is_tls(&self) -> bool {
        Elf64SectionFlags::from_bits(self.flags).get(Elf64SectionFlags::SHF_TLS) != 0
    }

    pub(crate) fn permissions(&self) -> Elf64ProgramHeaderFlags {
        let flags = Elf64SectionFlags::from_bits(self.flags);
        Elf64ProgramHeaderFlags::from_bits(
            PF_R | if flags.get(Elf64SectionFlags::SHF_WRITE) != 0 {
                PF_W
            } else {
                0
            } | if flags.get(Elf64SectionFlags::SHF_EXECINSTR) != 0 {
                PF_X
            } else {
                0
            },
        )
    }

    pub(crate) fn has_contents(&self, inputs: &[MappingInput]) -> bool {
        self.statements.iter().any(|statement| match statement {
            MappedStatement::Input(index) => inputs[*index].section.size != 0,
            MappedStatement::Assignment(assignment) => assignment.name == ".",
        })
    }

    fn add_input(&mut self, index: usize, inputs: &[MappingInput]) {
        let section = &inputs[index].section;
        self.flags |= section.flags.to_raw();
        self.align = self.align.max(section.align.max(1));
        self.statements.push(MappedStatement::Input(index));
    }
}

// Archive display names are path/to/lib.a(member.o); file patterns match
// the member name, while ordinary objects match their path basename.
pub(crate) fn input_name(file_name: &str, file_id: FileId) -> &str {
    let name = if matches!(file_id, FileId::ArchiveMember { .. })
        && let Some((_, member)) = file_name.rsplit_once('(')
    {
        member.strip_suffix(')').unwrap_or(file_name)
    } else {
        file_name
    };
    Path::new(name)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(name)
}

pub(crate) fn map_sections<'s>(
    script: &'s Script,
    inputs: &[MappingInput],
) -> Result<Vec<MappedItem<'s>>> {
    let mut items = Vec::new();
    let mut assigned = vec![false; inputs.len()];
    for statement in &script.statements {
        match statement {
            Statement::Assignment(assignment) => items.push(MappedItem::Assignment(assignment)),
            Statement::Sections(statements) => {
                for statement in statements {
                    match statement {
                        SectionStatement::Assignment(assignment) => {
                            items.push(MappedItem::Assignment(assignment))
                        }
                        SectionStatement::Output(output) => {
                            let mut mapped = MappedOutputSection {
                                name: output.name.clone(),
                                address: output.address.as_ref(),
                                statements: Vec::new(),
                                flags: 0,
                                align: 1,
                                orphan: false,
                            };
                            let mut candidates = assigned.clone();
                            let mut matched_nonalloc = false;
                            for statement in &output.statements {
                                match statement {
                                    OutputStatement::Assignment(assignment) => mapped
                                        .statements
                                        .push(MappedStatement::Assignment(assignment)),
                                    OutputStatement::Input(rule) => {
                                        for index in select_inputs(rule, inputs, &candidates, &[]) {
                                            candidates[index] = true;
                                            if inputs[index]
                                                .section
                                                .flags
                                                .get(Elf64SectionFlags::SHF_ALLOC)
                                                != 0
                                            {
                                                mapped.add_input(index, inputs);
                                            } else {
                                                matched_nonalloc = true;
                                            }
                                        }
                                    }
                                    OutputStatement::Ignored(_) => {}
                                }
                            }
                            let writable = Elf64SectionFlags::from_bits(mapped.flags)
                                .get(Elf64SectionFlags::SHF_WRITE)
                                != 0;
                            if matches!(output.constraint, Some(SectionConstraint::ReadOnly))
                                && writable
                                || matches!(output.constraint, Some(SectionConstraint::ReadWrite))
                                    && !writable
                            {
                                continue;
                            }
                            assigned = candidates;
                            if output.info || output.name == "/DISCARD/" {
                                continue;
                            }
                            // Debug/comment sections at address zero do not participate
                            // in the allocated address space or define layout symbols.
                            if mapped.flags == 0
                                && (matched_nonalloc
                                    || matches!(
                                        output.address.as_ref().map(|expr| &expr.kind),
                                        Some(ExprKind::Number(0))
                                    ))
                            {
                                continue;
                            }
                            items.push(MappedItem::Output(mapped));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    for (index, input) in inputs.iter().enumerate() {
        if assigned[index] || input.section.flags.get(Elf64SectionFlags::SHF_ALLOC) == 0 {
            continue;
        }
        let flags = input.section.flags.to_raw();
        // Combine orphan fragments with the same name and attributes.
        let existing = items.iter_mut().find_map(|item| match item {
            MappedItem::Output(output)
                if output.orphan && output.name == input.section.name && output.flags == flags =>
            {
                Some(output)
            }
            _ => None,
        });
        if let Some(output) = existing {
            output.add_input(index, inputs);
        } else {
            pr_info!(
                "orphan section {} placed after the last output section with matching attributes",
                input.section.name
            );
            let class = orphan_class(flags, input.section.data.is_none());
            let matching = |item: &MappedItem| match item {
                MappedItem::Output(output) => output.orphan_class(inputs) == class,
                _ => false,
            };
            // Prefer the related section name (rodata.cst32 follows .rodata),
            // then fall back to the last output with the same memory attributes.
            let related = items.iter().rposition(|item| {
                let MappedItem::Output(output) = item else {
                    return false;
                };
                matching(item) && section_family(&output.name) == section_family(input.section.name)
            });
            let after = related
                .or_else(|| items.iter().rposition(matching))
                .map_or(items.len(), |index| index + 1);
            let mut output = MappedOutputSection {
                name: input.section.name.to_string(),
                address: None,
                statements: Vec::new(),
                flags: 0,
                align: 1,
                orphan: true,
            };
            output.add_input(index, inputs);
            items.insert(after, MappedItem::Output(output));
        }
    }
    Ok(items)
}

fn section_family(name: &str) -> &str {
    name.trim_start_matches('.').split('.').next().unwrap_or("")
}

fn orphan_class(flags: u64, nobits: bool) -> (Elf64SectionFlags, bool) {
    // MERGE and STRINGS describe the contents, not their memory permissions.
    // Keep TLS and zero-fill separate from ordinary initialized data.
    let flags = Elf64SectionFlags::from_bits(flags);
    let attributes = Elf64SectionFlags::new()
        .set(
            Elf64SectionFlags::SHF_ALLOC,
            flags.get(Elf64SectionFlags::SHF_ALLOC),
        )
        .set(
            Elf64SectionFlags::SHF_WRITE,
            flags.get(Elf64SectionFlags::SHF_WRITE),
        )
        .set(
            Elf64SectionFlags::SHF_EXECINSTR,
            flags.get(Elf64SectionFlags::SHF_EXECINSTR),
        )
        .set(
            Elf64SectionFlags::SHF_TLS,
            flags.get(Elf64SectionFlags::SHF_TLS),
        );
    (attributes, nobits)
}

fn select_inputs(
    rule: &InputSectionRule,
    inputs: &[MappingInput],
    assigned: &[bool],
    exclusions: &[String],
) -> Vec<usize> {
    match rule {
        InputSectionRule::Keep(rule) => select_inputs(rule, inputs, assigned, exclusions),
        InputSectionRule::ExcludeFile(patterns, rule) => {
            let mut excluded = exclusions.to_vec();
            excluded.extend_from_slice(patterns);
            select_inputs(rule, inputs, assigned, &excluded)
        }
        InputSectionRule::Sort(kind, rule) => {
            let mut selected = select_inputs(rule, inputs, assigned, exclusions);
            sort_inputs(&mut selected, *kind, inputs);
            selected
        }
        InputSectionRule::File {
            pattern: file,
            sections,
        } => {
            let mut selected = Vec::new();
            let mut used = assigned.to_vec();
            let mut exclusions = exclusions.to_vec();
            select_patterns(
                sections,
                file,
                inputs,
                &mut used,
                &mut exclusions,
                &mut selected,
            );
            selected
        }
    }
}

fn select_patterns(
    patterns: &[SectionPattern],
    file: &str,
    inputs: &[MappingInput],
    used: &mut [bool],
    exclusions: &mut Vec<String>,
    selected: &mut Vec<usize>,
) {
    let start = selected.len();
    for section_pattern in patterns {
        match section_pattern {
            SectionPattern::Glob(glob) => {
                for (index, input) in inputs.iter().enumerate() {
                    if !used[index]
                        && pattern::matches(file, &input.file_name)
                        && !exclusions
                            .iter()
                            .any(|excluded| pattern::matches(excluded, &input.file_name))
                        && pattern::matches(glob, input.section.name)
                    {
                        used[index] = true;
                        selected.push(index);
                    }
                }
            }
            SectionPattern::Sort(kind, patterns) => {
                let mut sorted = Vec::new();
                select_patterns(
                    patterns,
                    file,
                    inputs,
                    used,
                    &mut exclusions.clone(),
                    &mut sorted,
                );
                sort_inputs(&mut sorted, *kind, inputs);
                selected.extend(sorted);
            }
            SectionPattern::ExcludeFile(patterns) => exclusions.extend_from_slice(patterns),
            // SHN_COMMON allocation is deferred; it is not an input section.
            SectionPattern::Common => {}
        }
    }
    // Multiple unsorted globs in one input rule are a union. Preserve the
    // original object/section order rather than grouping matches by glob.
    if !patterns
        .iter()
        .any(|pattern| matches!(pattern, SectionPattern::Sort(_, _)))
    {
        selected[start..].sort_unstable();
    }
}

fn sort_inputs(selected: &mut [usize], kind: SortKind, inputs: &[MappingInput]) {
    match kind {
        SortKind::Name => selected.sort_by_key(|index| inputs[*index].section.name),
        SortKind::InitPriority => {
            selected.sort_by_key(|index| init_priority(inputs[*index].section.name))
        }
        SortKind::None => {}
    }
}

fn init_priority(name: &str) -> u32 {
    let priority = name
        .rsplit_once('.')
        .and_then(|(_, suffix)| suffix.parse::<u32>().ok())
        .unwrap_or(65535);
    if name.starts_with(".ctors.") || name.starts_with(".dtors.") {
        65535u32.saturating_sub(priority)
    } else {
        priority
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::parser;

    fn input(file: &str, name: &'static str, flags: u64, align: u64) -> MappingInput<'static> {
        MappingInput {
            file_name: input_name(
                file,
                if file.ends_with(')') {
                    FileId::ArchiveMember {
                        archive_index: 0,
                        member_index: 0,
                    }
                } else {
                    FileId::InputObject { input_index: 0 }
                },
            )
            .to_string(),
            section: InputSection {
                file_id: FileId::InputObject { input_index: 0 },
                idx: 1,
                name,
                flags: Elf64SectionFlags::from_bits(flags),
                section_type: elf::Elf64SectionType::SHT_PROGBITS,
                entry_size: 0,
                align,
                data: Some(std::borrow::Cow::Borrowed(&[1])),
                size: 1,
            },
        }
    }

    fn names<'a>(items: &'a [MappedItem<'_>]) -> Vec<&'a str> {
        items
            .iter()
            .filter_map(|item| match item {
                MappedItem::Output(output) => Some(output.name.as_str()),
                _ => None,
            })
            .collect()
    }

    fn members(output: &MappedOutputSection) -> Vec<usize> {
        output
            .statements
            .iter()
            .filter_map(|statement| match statement {
                MappedStatement::Input(index) => Some(*index),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn file_names_use_basename_or_archive_member() {
        assert_eq!(
            input_name(
                "/tmp/build/crtbeginT.o",
                FileId::InputObject { input_index: 0 }
            ),
            "crtbeginT.o"
        );
        assert_eq!(
            input_name(
                "/tmp/libgcc.a(init.o)",
                FileId::ArchiveMember {
                    archive_index: 0,
                    member_index: 0
                }
            ),
            "init.o"
        );
        assert_eq!(
            input_name(
                "/tmp/libgcc.a(path/init.o)",
                FileId::ArchiveMember {
                    archive_index: 0,
                    member_index: 0
                }
            ),
            "init.o"
        );
    }

    #[test]
    fn first_matching_rule_and_exclude_file() {
        let inputs = vec![
            input("/tmp/first.o", ".text", 6, 1),
            input("lib.a(last.o)", ".text", 6, 1),
        ];
        let script = parser::parse(
            "SECTIONS { .first : { *(.text EXCLUDE_FILE(last.o) .text) } .rest : { *(.text) } }",
        )
        .unwrap();
        // An exclusion only affects the subsequent patterns in its list.
        let items = map_sections(&script, &inputs).unwrap();
        let MappedItem::Output(first) = &items[0] else {
            panic!()
        };
        assert_eq!(members(first), vec![0, 1]);

        let script = parser::parse(
            "SECTIONS { .first : { *(EXCLUDE_FILE(last.o) .text) } .rest : { last.o(.text) } }",
        )
        .unwrap();
        let items = map_sections(&script, &inputs).unwrap();
        let MappedItem::Output(first) = &items[0] else {
            panic!()
        };
        let MappedItem::Output(rest) = &items[1] else {
            panic!()
        };
        assert_eq!(members(first), vec![0]);
        assert_eq!(members(rest), vec![1]);
    }

    #[test]
    fn unsorted_globs_preserve_input_order() {
        let inputs = vec![
            input("first.o", ".text", 6, 1),
            input("first.o", ".text.extra", 6, 1),
            input("last.o", ".text", 6, 1),
            input("last.o", ".text.extra", 6, 1),
        ];
        let script = parser::parse("SECTIONS { .text : { *(.text .text.*) } }").unwrap();
        let items = map_sections(&script, &inputs).unwrap();
        let MappedItem::Output(output) = &items[0] else {
            panic!()
        };
        assert_eq!(members(output), vec![0, 1, 2, 3]);
    }

    #[test]
    fn sorting_is_stable_and_scoped_to_its_wrapper() {
        let inputs = vec![
            input("b.o", ".init_array.100", 3, 8),
            input("a.o", ".init_array.20", 3, 8),
            input("c.o", ".init_array.20", 3, 8),
            input("d.o", ".init_array", 3, 8),
        ];
        for (sort, expected) in [
            ("SORT_BY_INIT_PRIORITY", vec![1, 2, 0, 3]),
            ("SORT_BY_NAME", vec![0, 1, 2, 3]),
            ("SORT_NONE", vec![0, 1, 2, 3]),
        ] {
            let script = parser::parse(&format!(
                "SECTIONS {{ .init_array : {{ KEEP(*({sort}(.init_array.*))) *(.init_array) }} }}"
            ))
            .unwrap();
            let items = map_sections(&script, &inputs).unwrap();
            let MappedItem::Output(output) = &items[0] else {
                panic!()
            };
            assert_eq!(members(output), expected);
        }
        assert_eq!(init_priority(".ctors.65515"), 20);
    }

    #[test]
    fn constraints_leave_inputs_for_the_next_rule() {
        let inputs = vec![input("a.o", ".data", 3, 1)];
        let script = parser::parse(
            "SECTIONS { .ro : ONLY_IF_RO { *(.data) } .rw : ONLY_IF_RW { *(.data) } }",
        )
        .unwrap();
        let items = map_sections(&script, &inputs).unwrap();
        assert_eq!(names(&items), vec![".rw"]);
    }
}
