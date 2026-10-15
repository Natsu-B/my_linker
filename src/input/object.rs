//! Read one ELF object into the records the linker needs.
//!
//! [`parse`] takes bytes and returns an [`ObjectFile`] with [`InputSection`],
//! [`ObjectSymbol`], and [`ObjectRelocation`] records. It checks for little-endian
//! x86-64 `ET_REL` here so later steps can use that target's rules.
//!
//! A symbol's value in an object is often a section offset, not an address.
//! A RELA relocation holds a patch offset, a symbol index, a kind, and a signed
//! addend. We keep those input indices until layout joins them to output sections.
//! `SHT_NOBITS`, such as .bss, takes memory but has no bytes in the file.
//!
//! References: ELF gABI "ELF Header", "Sections", "Symbol Table", and "Relocation";
//! AMD64 psABI §§4.1–4.4. GNU ld uses these same ELF records for static inputs.

use std::borrow::Cow;

use anyhow::{Context, Result, bail, ensure};
use elf::{
    self, Elf64RelaInfo, Elf64SectionFlags, Elf64SectionType, Elf64SymbolInfo,
    Elf64SymbolSectionIdx, ElfEndian, ElfFileType, ElfMachineType,
};

use crate::input::FileId;
/// Keep original ELF indices so later steps can join symbols and relocations.
#[derive(Debug)]
pub(crate) struct ObjectFile<'a> {
    pub(crate) file_name: String,

    pub(crate) file_id: FileId,

    pub(crate) sections: Vec<InputSection<'a>>,

    pub(crate) symbols: Vec<ObjectSymbol<'a>>,

    pub(crate) relocations: Vec<ObjectRelocation>,
}

/// An input's bytes and memory needs, kept separate from its output address.
#[derive(Clone, Debug)]
pub(crate) struct InputSection<'a> {
    pub(crate) file_id: FileId,

    /// Index in this input's section table, not the output table.
    pub(crate) idx: u16,

    pub(crate) name: &'a str,

    pub(crate) flags: Elf64SectionFlags,

    pub(crate) section_type: Elf64SectionType,

    /// Bytes per fixed-size record, or zero for unstructured data.
    pub(crate) entry_size: u64,

    pub(crate) align: u64,

    /// Borrow object bytes; own linker-made bytes. NOBITS has no file bytes.
    pub(crate) data: Option<Cow<'a, [u8]>>,

    /// Memory size, even when NOBITS has no data.
    pub(crate) size: u64,
}

/// Keep the input symbol value and index until the linker picks a definition.
#[derive(Debug)]
pub(crate) struct ObjectSymbol<'a> {
    pub(crate) file_id: FileId,

    /// Index in this object's symbol table; relocations refer to it.
    pub(crate) idx: u16,

    /// Defining input section, or SHN_UNDEF, SHN_ABS, or SHN_COMMON.
    pub(crate) section_idx: Elf64SymbolSectionIdx,

    pub(crate) name: &'a str,

    pub(crate) info: Elf64SymbolInfo,

    pub(crate) size: u64,

    /// Raw `st_other` bits, including ELF visibility.
    pub(crate) other: u8,

    /// Usually a section offset in ET_REL, not a virtual address.
    pub(crate) value: u64,
}

/// A RELA patch: find its input section and symbol, then add the signed addend.
#[derive(Debug)]
pub(crate) struct ObjectRelocation {
    pub(crate) file_id: FileId,

    /// The relocation section's `sh_info`: the input section to patch.
    pub(crate) target_idx: u32,

    /// Byte offset from the target input section's start.
    pub(crate) offset: u64,

    /// Symbol index and relocation kind, packed together in the file.
    pub(crate) info: Elf64RelaInfo,

    /// Signed value from r_addend; the target bytes do not supply it.
    pub(crate) addend: i64,
}

/// Check the target and read one object's sections, symbols, and RELA records.
///
/// Names and file bytes borrow `mmap`. Reject SHT_REL here: later steps need an
/// explicit addend, which SHT_REL does not store.
pub(crate) fn parse<'a>(
    mmap: &'a [u8],
    file_name: String,
    file_id: FileId,
) -> Result<ObjectFile<'a>> {
    let elf = elf::Elf64::new(mmap)
        .with_context(|| format!("failed to parse ELF file: {}", file_name))?;

    // Check the target here for objects and archive members alike. Later
    // steps can then write x86-64 little-endian fields without another check.
    ensure!(
        elf.endian() == ElfEndian::Little,
        "unsupported endianness: {:?} in file: {} (expected little-endian)",
        elf.endian(),
        file_name
    );
    ensure!(
        elf.arch() == ElfMachineType::EM_X86_64,
        "unsupported architecture: {:?} in file: {}",
        elf.arch(),
        file_name
    );
    ensure!(
        elf.elf_type() == ElfFileType::ET_REL,
        "unsupported file type: {:?} in file: {}",
        elf.elf_type(),
        file_name
    );

    let mut object_file: ObjectFile<'a> = ObjectFile {
        file_name,
        file_id,
        sections: Vec::new(),
        symbols: Vec::new(),
        relocations: Vec::new(),
    };

    for section in elf.sections() {
        pr_debug!("Section: {}", section.name()?);
        match section.section_type() {
            Elf64SectionType::SHT_NULL => pr_debug!("  Type: NULL"),
            Elf64SectionType::SHT_PROGBITS
            | Elf64SectionType::SHT_NOBITS
            | Elf64SectionType::SHT_INIT_ARRAY
            | Elf64SectionType::SHT_FINI_ARRAY
            | Elf64SectionType::SHT_PREINIT_ARRAY
            | Elf64SectionType::SHT_NOTE => {
                pr_debug!("  Type: {:?}", section.section_type());
                let section = InputSection::<'a> {
                    file_id,
                    idx: section.idx(),
                    name: section.name()?,
                    flags: section.flags(),
                    section_type: section.section_type(),
                    entry_size: section.entry_size(),
                    align: section.align(),
                    data: section.data().map(Cow::Borrowed),
                    size: section.size(),
                };
                object_file.sections.push(section);
            }
            Elf64SectionType::SHT_SYMTAB => {
                pr_debug!("  Type: SYMTAB");
                for (i, symbol) in section.symbols()?.enumerate() {
                    pr_debug!("    Symbol: {}", symbol.name()?);
                    let symbol = ObjectSymbol {
                        file_id,
                        idx: i as u16,
                        section_idx: symbol.section_idx(),
                        name: symbol.name()?,
                        info: symbol.info(),
                        size: symbol.size(),
                        other: symbol.other(),
                        value: symbol.value(),
                    };
                    object_file.symbols.push(symbol);
                }
            }
            Elf64SectionType::SHT_STRTAB => pr_debug!("  Type: STRTAB"),
            Elf64SectionType::SHT_RELA => {
                pr_debug!("  Type: RELA");
                for relocation in section.rela()? {
                    pr_debug!(
                        "    Relocation: offset={:#x}, info={:?}, addend={}",
                        relocation.offset(),
                        relocation.info(),
                        relocation.addend()
                    );
                    let relocation = ObjectRelocation {
                        file_id,
                        target_idx: relocation.target_idx(),
                        offset: relocation.offset(),
                        info: relocation.info(),
                        addend: relocation.addend(),
                    };
                    object_file.relocations.push(relocation);
                }
            }
            Elf64SectionType::SHT_REL => {
                pr_debug!("  Type: REL");
                bail!(
                    "unsupported relocation format SHT_REL in section {} in file: {} (expected SHT_RELA)",
                    section.name()?,
                    object_file.file_name
                )
            }
            _ => pr_debug!("  Type: Other({:?})", section.section_type()),
        }
    }

    Ok(object_file)
}

#[cfg(test)]
mod tests {
    //! Check the target rules and keep input indices even for unaligned members.

    use super::parse;
    use crate::{
        input::FileId,
        input::archive::reader::ArchiveReader,
        test_utils::{TestRelocation, TestSymbol, build_archive, build_rel_object},
    };
    use elf::{Elf64SymbolBinding, Elf64SymbolType};

    #[test]
    fn rejects_big_endian_objects_at_the_input_boundary() {
        // Keep a valid big-endian header and null section so only the
        // linker's target check, not the generic ELF reader, rejects it.
        let mut object = vec![0; 128];
        object[..7].copy_from_slice(b"\x7fELF\x02\x02\x01");
        object[16..18].copy_from_slice(&elf::ElfFileType::ET_REL.raw().to_be_bytes());
        object[18..20].copy_from_slice(&elf::ElfMachineType::EM_X86_64.raw().to_be_bytes());
        object[20..24].copy_from_slice(&1u32.to_be_bytes());
        object[40..48].copy_from_slice(&64u64.to_be_bytes());
        object[52..54].copy_from_slice(&64u16.to_be_bytes());
        object[58..60].copy_from_slice(&64u16.to_be_bytes());
        object[60..62].copy_from_slice(&1u16.to_be_bytes());
        assert!(elf::Elf64::new(&object).is_ok());

        let error = parse(
            &object,
            "big-endian.o".to_string(),
            FileId::InputObject { input_index: 0 },
        )
        .unwrap_err();

        assert!(error.to_string().contains("unsupported endianness"));
        assert!(error.to_string().contains("big-endian.o"));
    }

    #[test]
    fn rejects_other_machines_accepted_by_the_generic_reader() {
        let mut object = build_rel_object(&[], &[]);
        object[18..20].copy_from_slice(&elf::ElfMachineType::EM_AARCH64.raw().to_le_bytes());
        assert!(elf::Elf64::new(&object).is_ok());

        let error = parse(
            &object,
            "aarch64.o".to_string(),
            FileId::InputObject { input_index: 0 },
        )
        .unwrap_err();

        assert!(error.to_string().contains("unsupported architecture"));
        assert!(error.to_string().contains("aarch64.o"));
    }

    #[test]
    fn parse_propagates_object_file_id_to_sections_symbols_and_relocations() {
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
        let file_id = FileId::InputObject { input_index: 7 };

        let parsed = parse(&object, "plain.o".to_string(), file_id).unwrap();

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

    #[test]
    fn rejects_rel_relocations_with_an_unsupported_format_error() {
        let mut object = build_rel_object(
            &[],
            &[TestRelocation {
                offset: 0,
                sym: 0,
                ty: 0,
                addend: 0,
            }],
        );
        let shoff = u64::from_le_bytes(object[40..48].try_into().unwrap()) as usize;
        let section_type = shoff + 3 * 64 + 4;
        object[section_type..section_type + 4]
            .copy_from_slice(&elf::Elf64SectionType::SHT_REL.raw().to_le_bytes());
        let error = parse(
            &object,
            "rel.o".to_string(),
            FileId::InputObject { input_index: 0 },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported relocation format SHT_REL")
        );
        assert!(error.to_string().contains("rel.o"));
    }

    #[test]
    fn collects_all_three_array_section_types_with_their_data() {
        for ty in [
            elf::Elf64SectionType::SHT_PREINIT_ARRAY,
            elf::Elf64SectionType::SHT_INIT_ARRAY,
            elf::Elf64SectionType::SHT_FINI_ARRAY,
        ] {
            let mut object = build_rel_object(&[], &[]);
            let shoff = u64::from_le_bytes(object[40..48].try_into().unwrap()) as usize;
            let section_type = shoff + 2 * 64 + 4;
            object[section_type..section_type + 4].copy_from_slice(&ty.raw().to_le_bytes());
            let parsed = parse(
                &object,
                "array.o".to_string(),
                FileId::InputObject { input_index: 0 },
            )
            .unwrap();
            assert_eq!(parsed.sections.len(), 1);
            assert_eq!(
                parsed.sections[0].data.as_deref().unwrap(),
                &[0x90, 0x90, 0x90, 0x90, 0xc3]
            );
        }
    }

    #[test]
    fn parse_accepts_archive_member_that_is_not_eight_byte_aligned() {
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
        let reader = ArchiveReader::new(&archive).unwrap();
        let member = reader.object_members().next().unwrap().unwrap();
        let file_id = FileId::ArchiveMember {
            archive_index: 0,
            member_index: 0,
        };

        assert_ne!(member.payload_offset() % std::mem::align_of::<u64>(), 0);

        let parsed = parse(member.object_bytes().unwrap(), "foo.o".to_string(), file_id).unwrap();

        assert_eq!(parsed.file_id, file_id);
        assert!(parsed.symbols.iter().any(|symbol| symbol.name == "foo"));
    }
}
