use std::collections::HashMap;

use anyhow::{Context, Result};
use elf::{Elf64SymbolBinding, Elf64SymbolInfo, Elf64SymbolSectionIdx, Elf64SymbolType};

use crate::{archive::ArchiveReader, input_id::FileId, parse};

pub struct MemberInfo<'a> {
    pub name: String,
    pub bytes: &'a [u8],
    pub defined: Vec<&'a str>,
    pub undefined: Vec<&'a str>,
}

pub struct ArchiveState<'a> {
    pub file_name: String,
    pub archive_idx: usize,
    pub members: Vec<MemberInfo<'a>>,
    pub by_symbol: HashMap<&'a str, usize>,
    pub extracted: Vec<bool>,
}

pub fn index_archive<'a>(
    bytes: &'a [u8],
    file_name: String,
    archive_idx: usize,
) -> Result<ArchiveState<'a>> {
    let reader = ArchiveReader::new(bytes)
        .with_context(|| format!("failed to parse archive: {file_name}"))?;
    let long_names = reader.long_name_table()?;
    let mut members: Vec<MemberInfo<'a>> = Vec::new();
    let mut by_symbol: HashMap<&'a str, usize> = HashMap::new();

    for (member_idx, member) in reader.object_members().enumerate() {
        let member =
            member.with_context(|| format!("failed to read archive member in {file_name}"))?;
        let name = member
            .resolved_name(long_names)
            .with_context(|| format!("failed to resolve archive member name in {file_name}"))?;
        let member_bytes = member
            .object_bytes()
            .with_context(|| format!("failed to read object bytes for {file_name}({name})"))?;
        let object = parse_member_object(member_bytes, &name, archive_idx, member_idx)
            .with_context(|| format!("failed to parse archive member {name}"))?;
        let (defined, undefined) = collect_symbols(&object);

        for &symbol in &defined {
            by_symbol.entry(symbol).or_insert(member_idx);
        }

        members.push(MemberInfo {
            name,
            bytes: member_bytes,
            defined,
            undefined,
        });
    }

    let extracted = vec![false; members.len()];

    Ok(ArchiveState {
        file_name,
        archive_idx,
        members,
        by_symbol,
        extracted,
    })
}

fn parse_member_object<'a>(
    bytes: &'a [u8],
    member_name: &str,
    archive_idx: usize,
    member_idx: usize,
) -> Result<parse::ObjectFile<'a>> {
    parse::parse(
        bytes,
        member_name.to_string(),
        FileId::ArchiveMember {
            archive_idx,
            member_idx,
        },
    )
}

fn collect_symbols<'a>(object: &parse::ObjectFile<'a>) -> (Vec<&'a str>, Vec<&'a str>) {
    let mut defined = Vec::new();
    let mut undefined = Vec::new();

    for symbol in &object.symbols {
        if symbol.name.is_empty() {
            continue;
        }

        if matches!(
            symbol.info.get_enum(Elf64SymbolInfo::st_type),
            Some(Elf64SymbolType::STT_FILE | Elf64SymbolType::STT_SECTION)
        ) {
            continue;
        }

        match symbol.section_idx {
            Elf64SymbolSectionIdx::Undefined => undefined.push(symbol.name),
            _ => {
                if matches!(
                    symbol.info.get_enum(Elf64SymbolInfo::st_bind),
                    Some(Elf64SymbolBinding::STB_GLOBAL | Elf64SymbolBinding::STB_WEAK)
                ) {
                    defined.push(symbol.name);
                }
            }
        }
    }

    (defined, undefined)
}

#[cfg(test)]
mod tests {
    use super::{index_archive, parse_member_object};
    use crate::{
        input_id::FileId,
        test_utils::{TestRelocation, TestSymbol, build_archive, build_rel_object},
    };
    use elf::{Elf64SymbolBinding, Elf64SymbolType};

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
        assert_eq!(state.archive_idx, 3);
        assert_eq!(state.members.len(), 1);
        assert_eq!(state.members[0].name, "foo.o");
        assert_eq!(state.members[0].defined, vec!["foo"]);
        assert!(state.members[0].undefined.is_empty());
        assert_eq!(state.by_symbol["foo"], 0);
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

        assert_eq!(state.members[0].defined, vec!["foo", "bar"]);
        assert_eq!(state.by_symbol["foo"], 0);
        assert_eq!(state.by_symbol["bar"], 0);
    }

    #[test]
    fn duplicate_defined_symbol_across_members_keeps_first_member() {
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
        assert_eq!(state.by_symbol["dup"], 0);
    }

    #[test]
    fn defined_and_undefined_lists_ignore_file_and_section_symbols() {
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

        assert_eq!(state.members[0].defined, vec!["foo", "bar"]);
        assert_eq!(state.members[0].undefined, vec!["baz"]);
    }

    #[test]
    fn by_symbol_maps_each_symbol_to_the_correct_member() {
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

        assert_eq!(state.by_symbol["foo"], 0);
        assert_eq!(state.by_symbol["bar"], 1);
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
            archive_idx: 9,
            member_idx: 0,
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
