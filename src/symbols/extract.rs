use std::collections::HashSet;

use anyhow::{Context, Result};

use crate::input::{
    FileId, InputFile,
    object::{self, ObjectFile},
};

fn update_symbol_sets(
    object: &ObjectFile<'_>,
    defined: &mut HashSet<String>,
    unresolved: &mut HashSet<String>,
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
                    unresolved.insert(symbol.name.to_string());
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

pub(crate) fn extract_archive_members<'a>(
    parse_result: Vec<Result<InputFile<'a>>>,
    entry_name: &str,
) -> Result<Vec<ObjectFile<'a>>> {
    let mut has_err = 0;
    let mut parsed = Vec::new();
    let mut defined = HashSet::new();
    // ENTRY is an archive extraction root, like GNU ld's -u option.
    let mut unresolved = HashSet::from([entry_name.to_string()]);

    for parse_result in parse_result {
        match parse_result {
            Ok(InputFile::Object(object_file)) => {
                pr_debug!(
                    "file:{}: parsed successfully\nresult: {:#?}",
                    object_file.file_name,
                    object_file
                );
                update_symbol_sets(&object_file, &mut defined, &mut unresolved);
                parsed.push(object_file);
            }
            Ok(InputFile::Archive(mut archive_state)) => {
                pr_debug!(
                    "file:{}: indexed archive with {} member(s)",
                    archive_state.file_name,
                    archive_state.members.len()
                );

                let mut archive_error = None;
                loop {
                    let mut unresolved_symbols =
                        unresolved.iter().map(String::as_str).collect::<Vec<_>>();
                    unresolved_symbols.sort_unstable();

                    let mut next_member_idx = None;
                    for symbol in unresolved_symbols {
                        if let Some(&member_index) = archive_state.by_symbol.get(symbol)
                            && !archive_state.extracted[member_index]
                        {
                            next_member_idx = Some(member_index);
                            break;
                        }
                    }

                    let Some(member_index) = next_member_idx else {
                        break;
                    };

                    archive_state.extracted[member_index] = true;
                    let member = &archive_state.members[member_index];
                    let display_name = format!("{}({})", archive_state.file_name, member.name);
                    let file_id = FileId::ArchiveMember {
                        archive_index: archive_state.archive_index,
                        member_index,
                    };
                    let object_file =
                        match object::parse(member.bytes, display_name.clone(), file_id)
                            .with_context(|| {
                                format!("failed to parse archive member {display_name}")
                            }) {
                            Ok(object_file) => object_file,
                            Err(err) => {
                                archive_error = Some(err);
                                break;
                            }
                        };

                    pr_debug!(
                        "file:{}: extracted archive member successfully\nresult: {:#?}",
                        object_file.file_name,
                        object_file
                    );
                    update_symbol_sets(&object_file, &mut defined, &mut unresolved);
                    parsed.push(object_file);
                }

                if let Some(err) = archive_error {
                    debugs_or!(pr_err!("{:?}", err), pr_err!("{}", err));
                    has_err += 1;
                }
            }
            Err(err) => {
                debugs_or!(pr_err!("{:?}", err), pr_err!("{}", err));
                has_err += 1;
            }
        }
    }

    anyhow::ensure!(has_err == 0, "{} file(s) failed to parse", has_err);
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestSymbol, build_rel_object};
    use elf::{Elf64SymbolBinding, Elf64SymbolType};

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
        let mut unresolved = HashSet::new();
        update_symbol_sets(&weak, &mut defined, &mut unresolved);
        assert_eq!(unresolved, HashSet::new());
        update_symbol_sets(&strong, &mut defined, &mut unresolved);
        update_symbol_sets(&weak, &mut defined, &mut unresolved);
        assert_eq!(unresolved, HashSet::from(["optional".to_string()]));
    }
}
