use std::{
    cell::OnceCell,
    collections::{HashMap, HashSet},
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use elf::{
    Elf64ProgramHeaderFlags, Elf64SectionFlags, Elf64SymbolBinding, Elf64SymbolInfo,
    Elf64SymbolSectionIdx, ElfEndian, PF_R, PF_W, PF_X,
    write::{ELF_HEADER_SIZE, PROGRAM_HEADER_SIZE},
};

use crate::{
    input_id::FileId,
    parse::{ObjectFile, ObjectRelocation, ObjectSection, ObjectSymbol},
    script::{ast::*, eval, pattern},
};

pub(crate) const PAGE_SIZE: u64 = 0x1000;

pub struct SectionPlacement<'a> {
    pub name: String,
    pub flags: Elf64ProgramHeaderFlags,
    pub size: u64,
    pub align: u64,
    pub va: OnceCell<u64>,
    pub data: Option<Vec<u8>>,
    pub sections_data: Vec<(ObjectSection<'a>, u64 /* offset */)>,
}

pub struct ElfData {
    pub endianness: ElfEndian,
    pub header_vaddr: u64,
    pub sizeof_headers: u64,
    pub script_symbols: HashMap<String, u64>,
}

struct Input<'a> {
    file_name: String,
    section: ObjectSection<'a>,
}

struct MappedOutput<'s> {
    name: String,
    address: Option<&'s Expr>,
    statements: Vec<MappedStatement<'s>>,
    flags: u64,
    align: u64,
    orphan: bool,
}

enum MappedStatement<'s> {
    Assignment(&'s Assignment),
    Input(usize),
}

enum MappedItem<'s> {
    Assignment(&'s Assignment),
    Output(MappedOutput<'s>),
}

impl MappedOutput<'_> {
    fn permissions(&self) -> Elf64ProgramHeaderFlags {
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

    fn has_contents(&self, inputs: &[Input]) -> bool {
        self.statements.iter().any(|statement| match statement {
            MappedStatement::Input(index) => inputs[*index].section.size != 0,
            MappedStatement::Assignment(assignment) => assignment.name == ".",
        })
    }

    fn add_input(&mut self, index: usize, inputs: &[Input]) {
        let section = &inputs[index].section;
        self.flags |= section.flags.raw();
        self.align = self.align.max(section.align.max(1));
        self.statements.push(MappedStatement::Input(index));
    }
}

pub fn link<'a>(
    object_files: Vec<ObjectFile<'a>>,
    script: &Script,
) -> Result<(
    Vec<SectionPlacement<'a>>,
    Vec<ObjectSymbol<'a>>,
    Vec<ObjectRelocation>,
    ElfData,
)> {
    pr_debug!("Linking {} object files", object_files.len());
    let mut inputs = Vec::new();
    let mut symbols = Vec::new();
    let mut relocations = Vec::new();
    let mut endianness = None;
    for object in object_files {
        ensure!(
            endianness.is_none_or(|endian| endian == object.endian),
            "input files have different endianness"
        );
        endianness = Some(object.endian);
        for section in object.sections {
            ensure!(
                section.align == 0 || section.align.is_power_of_two(),
                "invalid alignment for section {} in {}",
                section.name,
                object.file_name
            );
            inputs.push(Input {
                file_name: input_name(&object.file_name, object.file_id).to_string(),
                section,
            });
        }
        symbols.extend(object.symbols);
        relocations.extend(object.relocations);
    }
    let items = map_sections(script, &inputs)?;
    // PT_LOAD groups plus PT_GNU_STACK. Reevaluate SIZEOF_HEADERS when the
    // actual number of groups differs from the initial estimate.
    let mut phnum = 2;
    for _ in 0..8 {
        let sizeof_headers = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE * phnum;
        let mut layout = Layout::new(&symbols, sizeof_headers);
        let sections = layout.place(&items, &inputs)?;
        let actual_phnum = load_segment_count(&sections) + 1;
        if actual_phnum == phnum {
            let elf_data = ElfData {
                endianness: endianness.context("no object files to link")?,
                header_vaddr: layout
                    .header_vaddr
                    .context("script places no allocatable output sections")?,
                sizeof_headers,
                script_symbols: layout.script_symbols,
            };
            return Ok((sections, symbols, relocations, elf_data));
        }
        phnum = actual_phnum;
    }
    bail!("script layout did not converge after updating SIZEOF_HEADERS")
}

// Archive display names are path/to/lib.a(member.o); file patterns match
// the member name, while ordinary objects match their path basename.
fn input_name(file_name: &str, file_id: FileId) -> &str {
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

fn map_sections<'s>(script: &'s Script, inputs: &[Input]) -> Result<Vec<MappedItem<'s>>> {
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
                            let mut mapped = MappedOutput {
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
        let flags = input.section.flags.raw();
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
                "orphan section {} placed after the last output section with matching flags",
                input.section.name
            );
            let after = items
                .iter()
                .rposition(
                    |item| matches!(item, MappedItem::Output(output) if output.flags == flags),
                )
                .map_or(items.len(), |index| index + 1);
            let mut output = MappedOutput {
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

fn select_inputs(
    rule: &InputSection,
    inputs: &[Input],
    assigned: &[bool],
    exclusions: &[String],
) -> Vec<usize> {
    match rule {
        InputSection::Keep(rule) => select_inputs(rule, inputs, assigned, exclusions),
        InputSection::ExcludeFile(patterns, rule) => {
            let mut excluded = exclusions.to_vec();
            excluded.extend_from_slice(patterns);
            select_inputs(rule, inputs, assigned, &excluded)
        }
        InputSection::Sort(kind, rule) => {
            let mut selected = select_inputs(rule, inputs, assigned, exclusions);
            sort_inputs(&mut selected, *kind, inputs);
            selected
        }
        InputSection::File {
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
    inputs: &[Input],
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

fn sort_inputs(selected: &mut [usize], kind: SortKind, inputs: &[Input]) {
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

struct Layout<'a, 's> {
    context: eval::Context,
    section_symbols: HashMap<(FileId, u16), Vec<&'s ObjectSymbol<'a>>>,
    definitions: HashSet<&'a str>,
    references: HashSet<&'a str>,
    script_symbols: HashMap<String, u64>,
    header_vaddr: Option<u64>,
}

impl<'a, 's> Layout<'a, 's> {
    fn new(symbols: &'s [ObjectSymbol<'a>], sizeof_headers: u64) -> Self {
        let mut section_symbols: HashMap<_, Vec<_>> = HashMap::new();
        let mut definitions = HashSet::new();
        let mut references = HashSet::new();
        let mut context = eval::Context {
            sizeof_headers,
            ..Default::default()
        };
        for symbol in symbols {
            if symbol.name.is_empty()
                || symbol.info.get_enum(Elf64SymbolInfo::st_bind)
                    == Some(Elf64SymbolBinding::STB_LOCAL)
            {
                continue;
            }
            if let Elf64SymbolSectionIdx::Index(idx) = symbol.section_idx {
                section_symbols
                    .entry((symbol.file_id, idx))
                    .or_default()
                    .push(symbol);
            }
            if symbol.section_idx == Elf64SymbolSectionIdx::Undefined {
                references.insert(symbol.name);
            } else {
                definitions.insert(symbol.name);
                if symbol.section_idx == Elf64SymbolSectionIdx::AbsoluteSymbols {
                    context
                        .symbols
                        .insert(symbol.name.to_string(), symbol.value);
                }
            }
        }
        Self {
            context,
            section_symbols,
            definitions,
            references,
            script_symbols: HashMap::new(),
            header_vaddr: None,
        }
    }

    fn assign(&mut self, assignment: &Assignment) -> Result<()> {
        if assignment.kind != AssignmentKind::Define
            && (self.definitions.contains(assignment.name.as_str())
                || !self.references.contains(assignment.name.as_str())
                || self.script_symbols.contains_key(&assignment.name))
        {
            return Ok(());
        }
        ensure!(
            assignment.name == "." || !self.definitions.contains(assignment.name.as_str()),
            "{}: multiple definition of symbol: {} in input and linker script",
            assignment.location,
            assignment.name
        );
        let value = eval::evaluate(&assignment.value, &self.context)?;
        if assignment.name == "." {
            self.context.dot = value;
        } else {
            self.context.symbols.insert(assignment.name.clone(), value);
            self.script_symbols.insert(assignment.name.clone(), value);
        }
        Ok(())
    }

    fn place(
        &mut self,
        items: &[MappedItem],
        inputs: &[Input<'a>],
    ) -> Result<Vec<SectionPlacement<'a>>> {
        let mut sections = Vec::new();
        let mut previous_flags = Elf64ProgramHeaderFlags::from_bits(PF_R);
        let mut previous_end = 0;
        for (item_index, item) in items.iter().enumerate() {
            self.context.next_section_alignment = items[item_index + 1..]
                .iter()
                .find_map(|item| match item {
                    MappedItem::Output(output) if output.has_contents(inputs) => Some(output.align),
                    _ => None,
                })
                .unwrap_or(1);
            match item {
                MappedItem::Assignment(assignment) => self.assign(assignment)?,
                MappedItem::Output(output) => {
                    let mut va = match output.address {
                        Some(address) => eval::evaluate(address, &self.context)?,
                        None => align(self.context.dot, output.align)?,
                    };
                    if output.statements.is_empty() {
                        continue;
                    }
                    if self.header_vaddr.is_none() {
                        let first_address = if self.context.dot >= self.context.sizeof_headers {
                            self.context.dot.min(va)
                        } else {
                            va
                        };
                        let base = first_address
                            .checked_sub(self.context.sizeof_headers)
                            .context(
                                "no space for mapped ELF headers before the first output section",
                            )?
                            / PAGE_SIZE
                            * PAGE_SIZE;
                        self.header_vaddr = Some(base);
                        previous_end = base + self.context.sizeof_headers;
                    }
                    let flags = output.permissions();
                    if output.has_contents(inputs) {
                        let minimum = if flags == previous_flags {
                            previous_end
                        } else {
                            align(previous_end, PAGE_SIZE)?
                        };
                        if output.address.is_some() {
                            ensure!(
                                va >= minimum,
                                "output section {} at {va:#x} overlaps a previous section or shares a page with different permissions",
                                output.name
                            );
                        } else {
                            va = align(va.max(minimum), output.align)?;
                        }
                    }
                    self.context.dot = va;
                    let mut section = SectionPlacement {
                        name: output.name.clone(),
                        flags,
                        size: 0,
                        align: output.align,
                        va: OnceCell::from(va),
                        data: None,
                        sections_data: Vec::new(),
                    };
                    for statement in &output.statements {
                        match statement {
                            MappedStatement::Assignment(assignment) => {
                                let old_dot = self.context.dot;
                                self.assign(assignment)?;
                                ensure!(
                                    self.context.dot >= old_dot,
                                    "location counter moves backwards in output section {}",
                                    output.name
                                );
                            }
                            MappedStatement::Input(index) => {
                                let input = &inputs[*index].section;
                                self.context.dot = align(self.context.dot, input.align.max(1))?;
                                let offset = self.context.dot - va;
                                if let Some(data) = input.data {
                                    ensure!(
                                        data.len() as u64 == input.size,
                                        "input section {} data length does not match size",
                                        input.name
                                    );
                                    let output_data = section.data.get_or_insert_with(Vec::new);
                                    output_data.resize(
                                        usize::try_from(offset)
                                            .context("output section too large")?,
                                        0,
                                    );
                                    output_data.extend_from_slice(data);
                                }
                                for symbol in self
                                    .section_symbols
                                    .get(&(input.file_id, input.idx))
                                    .into_iter()
                                    .flatten()
                                {
                                    self.context.symbols.insert(
                                        symbol.name.to_string(),
                                        self.context
                                            .dot
                                            .checked_add(symbol.value)
                                            .context("symbol address exceeds u64")?,
                                    );
                                }
                                self.context.dot = self
                                    .context
                                    .dot
                                    .checked_add(input.size)
                                    .context("output section address exceeds u64")?;
                                section.sections_data.push((input.clone(), offset));
                            }
                        }
                    }
                    section.size = self.context.dot - va;
                    if section.size != 0 {
                        ensure!(
                            va >= previous_end,
                            "output section {} overlaps a previous section",
                            output.name
                        );
                        ensure!(
                            flags == previous_flags || va >= align(previous_end, PAGE_SIZE)?,
                            "output section {} shares a page with different permissions",
                            output.name
                        );
                        previous_end = self.context.dot;
                        previous_flags = flags;
                    }
                    pr_debug!(
                        "Output section {} at {va:#x}, size {:#x}",
                        section.name,
                        section.size
                    );
                    sections.push(section);
                }
            }
        }
        Ok(sections)
    }
}

fn align(value: u64, alignment: u64) -> Result<u64> {
    value
        .checked_next_multiple_of(alignment)
        .context("aligned address exceeds u64")
}

pub(crate) fn load_segment_count(sections: &[SectionPlacement]) -> u64 {
    let mut count = 1; // Mapped headers are the first read-only load.
    let mut flags = Elf64ProgramHeaderFlags::from_bits(PF_R);
    for section in sections.iter().filter(|section| section.size != 0) {
        if section.flags != flags {
            count += 1;
            flags = section.flags;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{input_id::FileId, script::parser};
    use elf::Elf64SectionType;

    fn input(file: &str, name: &'static str, flags: u64, align: u64) -> Input<'static> {
        Input {
            file_name: input_name(
                file,
                if file.ends_with(')') {
                    FileId::ArchiveMember {
                        archive_idx: 0,
                        member_idx: 0,
                    }
                } else {
                    FileId::Object(0)
                },
            )
            .to_string(),
            section: ObjectSection {
                file_id: FileId::Object(0),
                idx: 1,
                name,
                ty: Elf64SectionType::SHT_PROGBITS,
                flags: Elf64SectionFlags::from_bits(flags),
                align,
                data: Some(&[1]),
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

    fn members(output: &MappedOutput) -> Vec<usize> {
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
            input_name("/tmp/build/crtbeginT.o", FileId::Object(0)),
            "crtbeginT.o"
        );
        assert_eq!(
            input_name(
                "/tmp/libgcc.a(init.o)",
                FileId::ArchiveMember {
                    archive_idx: 0,
                    member_idx: 0
                }
            ),
            "init.o"
        );
        assert_eq!(
            input_name(
                "/tmp/libgcc.a(path/init.o)",
                FileId::ArchiveMember {
                    archive_idx: 0,
                    member_idx: 0
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

    #[test]
    fn orphans_follow_the_last_output_with_the_same_flags() {
        let inputs = vec![
            input("a.o", ".text", 6, 16),
            input("a.o", ".rodata", 2, 8),
            input("a.o", ".data", 3, 8),
            input("a.o", ".extra", 6, 32),
            input("b.o", ".extra", 6, 16),
            input("a.o", ".other", 2, 8),
        ];
        let script = parser::parse("SECTIONS { . = 0x400000 + SIZEOF_HEADERS; .text : { *(.text) } .rodata : { *(.rodata) } .data : { *(.data) } }").unwrap();
        let items = map_sections(&script, &inputs).unwrap();
        assert_eq!(
            names(&items),
            vec![".text", ".extra", ".rodata", ".other", ".data"]
        );
        let MappedItem::Output(extra) = &items[2] else {
            panic!()
        };
        assert_eq!(members(extra), vec![3, 4]);
        let mut layout = Layout::new(&[], 64 + 56 * 5);
        let sections = layout.place(&items, &inputs).unwrap();
        let text = &sections[0];
        let extra = &sections[1];
        let rodata = &sections[2];
        assert_eq!(*extra.va.get().unwrap() % 32, 0);
        assert_eq!(
            *extra.va.get().unwrap(),
            (*text.va.get().unwrap() + 1).next_multiple_of(32)
        );
        assert_eq!(*rodata.va.get().unwrap() % PAGE_SIZE, 0);
        assert_eq!(load_segment_count(&sections), 4);
    }

    #[test]
    fn info_discard_and_nonalloc_outputs_do_not_change_dot() {
        let inputs = vec![
            input("a.o", ".debug_info", 0, 1),
            input("a.o", ".ignored", 2, 1),
            input("a.o", ".drop", 2, 1),
            input("a.o", ".text", 6, 1),
        ];
        let script = parser::parse("SECTIONS { . = 0x401000; .debug_info 0 : { *(.debug_info) } .info 0 (INFO) : { *(.ignored) } /DISCARD/ : { *(.drop) } .text : { *(.text) } }").unwrap();
        let items = map_sections(&script, &inputs).unwrap();
        assert_eq!(names(&items), vec![".text"]);
        let mut layout = Layout::new(&[], 232);
        let sections = layout.place(&items, &inputs).unwrap();
        assert_eq!(*sections[0].va.get().unwrap(), 0x401000);
    }

    #[test]
    fn rejects_explicit_sections_sharing_a_page_with_different_permissions() {
        let inputs = vec![input("a.o", ".text", 6, 1), input("a.o", ".data", 3, 1)];
        let script = parser::parse("SECTIONS { . = 0x400000 + SIZEOF_HEADERS; .text 0x401000 : { *(.text) } .data 0x401001 : { *(.data) } }").unwrap();
        let items = map_sections(&script, &inputs).unwrap();
        let mut layout = Layout::new(&[], 232);
        let error = layout.place(&items, &inputs).err().unwrap();
        assert!(
            error
                .to_string()
                .contains("shares a page with different permissions")
        );
    }

    #[test]
    fn next_section_alignment_and_sequential_assignments() {
        let inputs = vec![
            input("a.o", ".rodata", 2, 64),
            input("a.o", ".data", 3, 128),
        ];
        let script = parser::parse("SECTIONS { . = 0x400000 + SIZEOF_HEADERS; before = .; alignment = ALIGNOF(NEXT_SECTION); .rodata : { start = .; next_alignment = ALIGNOF(NEXT_SECTION); *(.rodata) . = ALIGN(16); finish = .; } after = .; .data : { *(.data) } }").unwrap();
        let items = map_sections(&script, &inputs).unwrap();
        let mut layout = Layout::new(&[], 176);
        let sections = layout.place(&items, &inputs).unwrap();
        assert_eq!(layout.script_symbols["before"], 0x4000b0);
        assert_eq!(layout.script_symbols["alignment"], 64);
        assert_eq!(layout.script_symbols["next_alignment"], 128);
        assert_eq!(layout.script_symbols["start"], 0x4000c0);
        assert_eq!(layout.script_symbols["finish"], 0x4000d0);
        assert_eq!(layout.script_symbols["after"], 0x4000d0);
        assert_eq!(sections[0].size, 16);
    }
}
