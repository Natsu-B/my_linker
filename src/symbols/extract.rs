use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};

use crate::input::{
    FileId, InputFile, LoadedInputs,
    object::{self, ObjectFile},
};

fn update_symbol_sets(
    object: &ObjectFile<'_>,
    defined: &mut HashSet<String>,
    unresolved: &mut HashMap<String, Option<FileId>>,
) {
    for symbol in &object.symbols {
        if symbol.name.is_empty() {
            continue;
        }

        if matches!(
            symbol.info.get_enum(elf::Elf64SymbolInfo::st_type),
            Some(elf::Elf64SymbolType::STT_FILE | elf::Elf64SymbolType::STT_SECTION)
        ) {
            continue;
        }

        match symbol.section_idx {
            elf::Elf64SymbolSectionIdx::Undefined => {
                if symbol.info.get_enum(elf::Elf64SymbolInfo::st_bind)
                    == Some(elf::Elf64SymbolBinding::STB_GLOBAL)
                    && !defined.contains(symbol.name)
                {
                    unresolved
                        .entry(symbol.name.to_string())
                        .or_insert(Some(object.file_id));
                }
            }
            _ => {
                if matches!(
                    symbol.info.get_enum(elf::Elf64SymbolInfo::st_bind),
                    Some(elf::Elf64SymbolBinding::STB_GLOBAL | elf::Elf64SymbolBinding::STB_WEAK)
                ) {
                    defined.insert(symbol.name.to_string());
                    unresolved.remove(symbol.name);
                }
            }
        }
    }
}

/// Why a member entered the link, in armap extraction order.
#[derive(Clone)]
pub(crate) struct ArchiveExtraction {
    pub(crate) member: String,
    pub(crate) symbol: String,
    // ENTRY can request a member without a referencing object.
    pub(crate) referencer: Option<FileId>,
}

pub(crate) struct ExtractedObjects<'a> {
    pub(crate) files: Vec<ObjectFile<'a>>,
    pub(crate) extractions: Vec<ArchiveExtraction>,
}

pub(crate) fn extract_archive_members<'a>(
    inputs: LoadedInputs<'a>,
    entry_name: &str,
) -> Result<ExtractedObjects<'a>> {
    let mut files = Vec::new();
    let mut extractions = Vec::new();
    let mut defined = HashSet::new();
    // ENTRY is an archive extraction root, like GNU ld's -u option.
    let mut unresolved = HashMap::from([(entry_name.to_string(), None)]);
    for input in inputs.files {
        match input {
            InputFile::Object(object) => {
                update_symbol_sets(&object, &mut defined, &mut unresolved);
                files.push(object);
            }
            InputFile::Archive(mut archive) => {
                // BFD scans the armap in full passes. New references can pull
                // later entries during this pass; earlier entries must wait
                // until the next pass. Undefined weak references never extract.
                loop {
                    let mut loaded = false;
                    for entry in &archive.entries {
                        let member_index = entry.member_index;
                        if archive.extracted[member_index] || !unresolved.contains_key(entry.symbol)
                        {
                            continue;
                        }
                        let member = &archive.members[member_index];
                        let display_name = format!("{}({})", archive.file_name, member.name);
                        let file_id = FileId::ArchiveMember {
                            archive_index: archive.archive_index,
                            member_index,
                        };
                        let object = object::parse(member.bytes, display_name.clone(), file_id)
                            .with_context(|| {
                                format!("failed to parse archive member {display_name}")
                            })?;
                        extractions.push(ArchiveExtraction {
                            member: display_name,
                            symbol: entry.symbol.to_string(),
                            referencer: unresolved[entry.symbol],
                        });
                        archive.extracted[member_index] = true;
                        update_symbol_sets(&object, &mut defined, &mut unresolved);
                        files.push(object);
                        loaded = true;
                    }
                    if !loaded {
                        break;
                    }
                }
            }
        }
    }
    Ok(ExtractedObjects { files, extractions })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestSymbol, build_rel_object};
    use elf::{Elf64SymbolBinding, Elf64SymbolType};

    fn symbol(
        name: &'static str,
        binding: Elf64SymbolBinding,
        section_idx: u16,
    ) -> TestSymbol<'static> {
        TestSymbol {
            name,
            binding,
            section_idx,
            ty: Elf64SymbolType::STT_NOTYPE,
            value: 0,
            size: 0,
        }
    }

    fn extract_names(root: &[u8], archive: &[u8]) -> Vec<String> {
        let root = object::parse(
            root,
            "root.o".to_string(),
            FileId::InputObject { input_index: 0 },
        )
        .unwrap();
        let archive =
            crate::input::archive::index::index_archive(archive, "libtest.a".to_string(), 1)
                .unwrap();
        extract_archive_members(
            LoadedInputs {
                files: vec![InputFile::Object(root), InputFile::Archive(archive)],
            },
            "_start",
        )
        .unwrap()
        .files
        .into_iter()
        .map(|object| object.file_name)
        .collect()
    }

    #[test]
    fn finishes_each_pass_before_restarting_for_new_references() {
        use Elf64SymbolBinding::STB_GLOBAL as Global;
        let root = build_rel_object(
            &[
                symbol("_start", Global, 2),
                symbol("root", Global, 0),
                symbol("late", Global, 0),
            ],
            &[],
        );
        let early = build_rel_object(&[symbol("early", Global, 2)], &[]);
        let middle = build_rel_object(
            &[symbol("root", Global, 2), symbol("early", Global, 0)],
            &[],
        );
        let late = build_rel_object(&[symbol("late", Global, 2)], &[]);
        // Physical member order deliberately differs from the armap order.
        let members = [
            ("late.o/", late.as_slice()),
            ("early.o/", early.as_slice()),
            ("middle.o/", middle.as_slice()),
        ];
        let archive = crate::test_utils::build_indexed_archive(
            &members,
            &[("early", 1), ("root", 2), ("late", 0)],
        );
        assert_eq!(
            extract_names(&root, &archive),
            [
                "root.o",
                "libtest.a(middle.o)",
                "libtest.a(late.o)",
                "libtest.a(early.o)"
            ]
        );
    }

    #[test]
    fn fallback_index_uses_member_then_symbol_order_with_full_passes() {
        use Elf64SymbolBinding::STB_GLOBAL as Global;
        let root = build_rel_object(
            &[symbol("_start", Global, 2), symbol("root", Global, 0)],
            &[],
        );
        let early = build_rel_object(&[symbol("early", Global, 2)], &[]);
        let middle = build_rel_object(
            &[
                symbol("root", Global, 2),
                symbol("early", Global, 0),
                symbol("later", Global, 0),
            ],
            &[],
        );
        let later = build_rel_object(&[symbol("later", Global, 2)], &[]);
        let archive = crate::test_utils::build_archive(&[
            ("early.o/", &early),
            ("middle.o/", &middle),
            ("later.o/", &later),
        ]);
        assert_eq!(
            extract_names(&root, &archive),
            [
                "root.o",
                "libtest.a(middle.o)",
                "libtest.a(later.o)",
                "libtest.a(early.o)"
            ]
        );
    }

    #[test]
    fn weak_references_do_not_extract_but_strong_references_can_select_weak_definitions() {
        use Elf64SymbolBinding::{STB_GLOBAL as Global, STB_WEAK as Weak};
        let member = build_rel_object(
            &[symbol("optional", Weak, 2), symbol("alias", Global, 2)],
            &[],
        );
        let archive = crate::test_utils::build_indexed_archive(
            &[("optional.o/", &member)],
            &[("optional", 0), ("alias", 0)],
        );
        for binding in [Weak, Global] {
            let root = build_rel_object(
                &[
                    symbol("_start", Global, 2),
                    symbol("optional", binding, 0),
                    symbol("alias", Weak, 0),
                ],
                &[],
            );
            let names = extract_names(&root, &archive);
            if binding == Weak {
                assert_eq!(names, ["root.o"]);
            } else {
                // Multiple armap entries must never load a member twice.
                assert_eq!(names, ["root.o", "libtest.a(optional.o)"]);
            }
        }
    }

    #[test]
    fn already_defined_symbols_do_not_pull_another_member() {
        use Elf64SymbolBinding::STB_GLOBAL as Global;
        let root = build_rel_object(
            &[symbol("_start", Global, 2), symbol("existing", Global, 2)],
            &[],
        );
        let member = build_rel_object(&[symbol("existing", Global, 2)], &[]);
        let archive = crate::test_utils::build_indexed_archive(
            &[("duplicate.o/", &member)],
            &[("existing", 0)],
        );
        assert_eq!(extract_names(&root, &archive), ["root.o"]);
    }

    #[test]
    fn weak_references_do_not_add_or_remove_archive_extraction_roots() {
        let object = |binding| {
            build_rel_object(
                &[TestSymbol {
                    name: "optional",
                    binding,
                    ty: Elf64SymbolType::STT_NOTYPE,
                    section_idx: 0,
                    value: 0,
                    size: 0,
                }],
                &[],
            )
        };
        let weak = object(Elf64SymbolBinding::STB_WEAK);
        let strong = object(Elf64SymbolBinding::STB_GLOBAL);
        let weak = object::parse(
            &weak,
            "weak.o".to_string(),
            FileId::InputObject { input_index: 0 },
        )
        .unwrap();
        let strong = object::parse(
            &strong,
            "strong.o".to_string(),
            FileId::InputObject { input_index: 1 },
        )
        .unwrap();
        let mut defined = HashSet::new();
        let mut unresolved = HashMap::new();
        update_symbol_sets(&weak, &mut defined, &mut unresolved);
        assert_eq!(unresolved, HashMap::new());
        update_symbol_sets(&strong, &mut defined, &mut unresolved);
        update_symbol_sets(&weak, &mut defined, &mut unresolved);
        assert_eq!(
            unresolved,
            HashMap::from([("optional".to_string(), Some(strong.file_id))])
        );
    }
}
