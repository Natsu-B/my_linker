use std::collections::HashMap;

use anyhow::{Context, Result};
use elf::{Elf64SymbolBinding, Elf64SymbolInfo, Elf64SymbolSectionIdx, Elf64SymbolType};

use crate::input::{FileId, object};

use super::reader::ArchiveReader;

pub(crate) struct MemberInfo<'a> {
    pub(crate) name: String,
    pub(crate) bytes: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ArchiveEntry<'a> {
    pub(crate) symbol: &'a str,
    pub(crate) member_index: usize,
}

pub(crate) struct ArchiveState<'a> {
    pub(crate) file_name: String,
    pub(crate) archive_index: usize,
    pub(crate) members: Vec<MemberInfo<'a>>,
    pub(crate) entries: Vec<ArchiveEntry<'a>>,
    pub(crate) extracted: Vec<bool>,
}

pub(crate) fn index_archive<'a>(
    bytes: &'a [u8],
    file_name: String,
    archive_index: usize,
) -> Result<ArchiveState<'a>> {
    let reader = ArchiveReader::new(bytes)
        .with_context(|| format!("failed to parse archive: {file_name}"))?;
    let long_names = reader.long_name_table()?;
    let mut members: Vec<MemberInfo<'a>> = Vec::new();
    let armap = reader.symbol_table()?;
    let mut entries = Vec::new();
    let mut member_offsets = HashMap::new();

    for (member_index, member) in reader.object_members().enumerate() {
        let member =
            member.with_context(|| format!("failed to read archive member in {file_name}"))?;
        let name = member
            .resolved_name(long_names)
            .with_context(|| format!("failed to resolve archive member name in {file_name}"))?;
        let member_bytes = member
            .object_bytes()
            .with_context(|| format!("failed to read object bytes for {file_name}({name})"))?;
        member_offsets.insert(member.header_offset(), member_index);
        // Archives without an armap use the same member/symbol traversal order
        // that an archiver would use to build one.
        if armap.is_none() {
            let object = parse_member_object(member_bytes, &name, archive_index, member_index)
                .with_context(|| format!("failed to parse archive member {name}"))?;
            for symbol in collect_defined_symbols(&object) {
                entries.push(ArchiveEntry {
                    symbol,
                    member_index,
                });
            }
        }

        members.push(MemberInfo {
            name,
            bytes: member_bytes,
        });
    }

    if let Some(armap) = armap {
        for symbol in armap {
            let member_index = *member_offsets.get(&symbol.member_offset).with_context(|| {
                format!(
                    "archive symbol {} refers to invalid member offset {:#x}",
                    symbol.name, symbol.member_offset
                )
            })?;
            entries.push(ArchiveEntry {
                symbol: symbol.name,
                member_index,
            });
        }
    }
    let extracted = vec![false; members.len()];

    Ok(ArchiveState {
        file_name,
        archive_index,
        members,
        entries,
        extracted,
    })
}

fn parse_member_object<'a>(
    bytes: &'a [u8],
    member_name: &str,
    archive_index: usize,
    member_index: usize,
) -> Result<object::ObjectFile<'a>> {
    object::parse(
        bytes,
        member_name.to_string(),
        FileId::ArchiveMember {
            archive_index,
            member_index,
        },
    )
}

fn collect_defined_symbols<'a>(object: &object::ObjectFile<'a>) -> Vec<&'a str> {
    let mut defined = Vec::new();

    for symbol in &object.symbols {
        if symbol.name.is_empty() || symbol.section_idx == Elf64SymbolSectionIdx::Undefined {
            continue;
        }

        if matches!(
            symbol.info.get_enum(Elf64SymbolInfo::st_type),
            Some(Elf64SymbolType::STT_FILE | Elf64SymbolType::STT_SECTION)
        ) {
            continue;
        }

        if matches!(
            symbol.info.get_enum(Elf64SymbolInfo::st_bind),
            Some(Elf64SymbolBinding::STB_GLOBAL | Elf64SymbolBinding::STB_WEAK)
        ) {
            defined.push(symbol.name);
        }
    }

    defined
}

#[cfg(test)]
mod tests {
    use super::{ArchiveEntry, index_archive, parse_member_object};
    use crate::{
        input::FileId,
        test_utils::{TestRelocation, TestSymbol, build_archive, build_rel_object},
    };
    use elf::{Elf64SymbolBinding, Elf64SymbolType};

    #[test]
    fn armap_entries_must_point_to_member_headers() {
        let object = build_rel_object(&[], &[]);
        let mut archive =
            crate::test_utils::build_indexed_archive(&[("member.o/", &object)], &[("symbol", 0)]);
        // Corrupt the first offset to point into the armap rather than a member.
        archive[72..76].copy_from_slice(&8u32.to_be_bytes());
        let error = index_archive(&archive, "bad.a".to_string(), 0)
            .err()
            .unwrap();
        assert!(error.to_string().contains("invalid member offset"));
    }

    #[test]
    fn indexes_single_member_archive() {
        let object = build_rel_object(
            &[TestSymbol {
                name: "foo",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let archive = build_archive(&[("foo.o/", &object)]);

        let state = index_archive(&archive, "libfoo.a".to_string(), 3).unwrap();

        assert_eq!(state.file_name, "libfoo.a");
        assert_eq!(state.archive_index, 3);
        assert_eq!(state.members.len(), 1);
        assert_eq!(state.members[0].name, "foo.o");
        assert_eq!(
            state.entries,
            vec![ArchiveEntry {
                symbol: "foo",
                member_index: 0
            }]
        );
        assert_eq!(state.extracted, vec![false]);
    }

    #[test]
    fn indexes_member_that_defines_multiple_symbols() {
        let object = build_rel_object(
            &[
                TestSymbol {
                    name: "foo",
                    binding: Elf64SymbolBinding::STB_GLOBAL,
                    ty: Elf64SymbolType::STT_FUNC,
                    section_idx: 2,
                    value: 0,
                    size: 5,
                },
                TestSymbol {
                    name: "bar",
                    binding: Elf64SymbolBinding::STB_WEAK,
                    ty: Elf64SymbolType::STT_FUNC,
                    section_idx: 2,
                    value: 1,
                    size: 4,
                },
            ],
            &[],
        );
        let archive = build_archive(&[("multi.o/", &object)]);

        let state = index_archive(&archive, "libmulti.a".to_string(), 1).unwrap();

        assert_eq!(
            state.entries,
            vec![
                ArchiveEntry {
                    symbol: "foo",
                    member_index: 0
                },
                ArchiveEntry {
                    symbol: "bar",
                    member_index: 0
                },
            ]
        );
    }

    #[test]
    fn duplicate_defined_symbols_keep_both_entries_in_member_order() {
        let first = build_rel_object(
            &[TestSymbol {
                name: "dup",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let second = build_rel_object(
            &[TestSymbol {
                name: "dup",
                binding: Elf64SymbolBinding::STB_WEAK,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let archive = build_archive(&[("one.o/", &first), ("two.o/", &second)]);

        let state = index_archive(&archive, "libdup.a".to_string(), 0).unwrap();

        assert_eq!(state.members.len(), 2);
        assert_eq!(
            state.entries,
            vec![
                ArchiveEntry {
                    symbol: "dup",
                    member_index: 0
                },
                ArchiveEntry {
                    symbol: "dup",
                    member_index: 1
                },
            ]
        );
    }

    #[test]
    fn index_excludes_undefined_local_file_and_section_symbols() {
        let object = build_rel_object(
            &[
                TestSymbol {
                    name: "",
                    binding: Elf64SymbolBinding::STB_LOCAL,
                    ty: Elf64SymbolType::STT_SECTION,
                    section_idx: 2,
                    value: 0,
                    size: 0,
                },
                TestSymbol {
                    name: "member.c",
                    binding: Elf64SymbolBinding::STB_LOCAL,
                    ty: Elf64SymbolType::STT_FILE,
                    section_idx: 0xFFF1,
                    value: 0,
                    size: 0,
                },
                TestSymbol {
                    name: "local_only",
                    binding: Elf64SymbolBinding::STB_LOCAL,
                    ty: Elf64SymbolType::STT_FUNC,
                    section_idx: 2,
                    value: 1,
                    size: 1,
                },
                TestSymbol {
                    name: "foo",
                    binding: Elf64SymbolBinding::STB_GLOBAL,
                    ty: Elf64SymbolType::STT_FUNC,
                    section_idx: 2,
                    value: 0,
                    size: 5,
                },
                TestSymbol {
                    name: "bar",
                    binding: Elf64SymbolBinding::STB_WEAK,
                    ty: Elf64SymbolType::STT_FUNC,
                    section_idx: 2,
                    value: 1,
                    size: 4,
                },
                TestSymbol {
                    name: "baz",
                    binding: Elf64SymbolBinding::STB_GLOBAL,
                    ty: Elf64SymbolType::STT_NOTYPE,
                    section_idx: 0,
                    value: 0,
                    size: 0,
                },
            ],
            &[],
        );
        let archive = build_archive(&[("multi.o/", &object)]);

        let state = index_archive(&archive, "libmulti.a".to_string(), 2).unwrap();

        assert_eq!(
            state
                .entries
                .iter()
                .map(|entry| (entry.symbol, entry.member_index))
                .collect::<Vec<_>>(),
            vec![("foo", 0), ("bar", 0)]
        );
    }

    #[test]
    fn entries_map_each_symbol_to_the_correct_member() {
        let first = build_rel_object(
            &[TestSymbol {
                name: "foo",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let second = build_rel_object(
            &[TestSymbol {
                name: "bar",
                binding: Elf64SymbolBinding::STB_GLOBAL,
                ty: Elf64SymbolType::STT_FUNC,
                section_idx: 2,
                value: 0,
                size: 5,
            }],
            &[],
        );
        let archive = build_archive(&[("one.o/", &first), ("two.o/", &second)]);

        let state = index_archive(&archive, "libpair.a".to_string(), 4).unwrap();

        assert_eq!(
            state.entries,
            vec![
                ArchiveEntry {
                    symbol: "foo",
                    member_index: 0
                },
                ArchiveEntry {
                    symbol: "bar",
                    member_index: 1
                },
            ]
        );
    }

    #[test]
    fn archive_member_indexing_uses_archive_member_file_id() {
        let object = build_rel_object(
            &[
                TestSymbol {
                    name: "",
                    binding: Elf64SymbolBinding::STB_LOCAL,
                    ty: Elf64SymbolType::STT_SECTION,
                    section_idx: 2,
                    value: 0,
                    size: 0,
                },
                TestSymbol {
                    name: "foo",
                    binding: Elf64SymbolBinding::STB_GLOBAL,
                    ty: Elf64SymbolType::STT_FUNC,
                    section_idx: 2,
                    value: 0,
                    size: 5,
                },
            ],
            &[TestRelocation {
                offset: 0,
                sym: 2,
                ty: 2,
                addend: -4,
            }],
        );
        let archive = build_archive(&[("foo.o/", &object)]);
        let state = index_archive(&archive, "libfoo.a".to_string(), 9).unwrap();
        let file_id = FileId::ArchiveMember {
            archive_index: 9,
            member_index: 0,
        };

        let parsed =
            parse_member_object(state.members[0].bytes, &state.members[0].name, 9, 0).unwrap();

        assert_eq!(parsed.file_id, file_id);
        assert!(
            parsed
                .sections
                .iter()
                .all(|section| section.file_id == file_id)
        );
        assert!(
            parsed
                .symbols
                .iter()
                .all(|symbol| symbol.file_id == file_id)
        );
        assert!(
            parsed
                .relocations
                .iter()
                .all(|relocation| relocation.file_id == file_id)
        );
    }
}
