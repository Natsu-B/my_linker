use std::collections::HashSet;

use anyhow::{Context, Result};

use crate::{
    archive_index::ArchiveState,
    input_id::FileId,
    parse::{self, ObjectFile},
};

pub enum FileType<'a> {
    Object(ObjectFile<'a>),
    Archive(ArchiveState<'a>),
}

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
                if !defined.contains(symbol.name) {
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

pub fn resolve_symbols(parse_result: Vec<Result<FileType<'_>>>) -> Result<Vec<ObjectFile<'_>>> {
    let mut has_err = 0;
    let mut parsed = Vec::new();
    let mut defined = HashSet::new();
    let mut unresolved = HashSet::new();

    for parse_result in parse_result {
        match parse_result {
            Ok(FileType::Object(object_file)) => {
                pr_debug!(
                    "file:{}: parsed successfully\nresult: {:#?}",
                    object_file.file_name,
                    object_file
                );
                update_symbol_sets(&object_file, &mut defined, &mut unresolved);
                parsed.push(object_file);
            }
            Ok(FileType::Archive(mut archive_state)) => {
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
                        if let Some(&member_idx) = archive_state.by_symbol.get(symbol)
                            && !archive_state.extracted[member_idx]
                        {
                            next_member_idx = Some(member_idx);
                            break;
                        }
                    }

                    let Some(member_idx) = next_member_idx else {
                        break;
                    };

                    archive_state.extracted[member_idx] = true;
                    let member = &archive_state.members[member_idx];
                    let display_name = format!("{}({})", archive_state.file_name, member.name);
                    let file_id = FileId::ArchiveMember {
                        archive_idx: archive_state.archive_idx,
                        member_idx,
                    };
                    let object_file =
                        match parse::parse(member.bytes, display_name.clone(), file_id)
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
