use std::cell::OnceCell;

use crate::{
    parse::{ObjectFile, ObjectRelocation, ObjectSection, ObjectSymbol},
    script,
};
use anyhow::{Result, ensure};
use elf::{Elf64ProgramHeaderFlags, Elf64SectionFlags, Elf64SectionType, ElfEndian};
use num::integer::lcm;

pub struct SectionPlacement<'a> {
    pub out_idx: u16,
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
}

pub fn link(
    object_files: Vec<ObjectFile>,
) -> Result<(
    Vec<SectionPlacement>,
    Vec<ObjectSymbol>,
    Vec<ObjectRelocation>,
    ElfData,
)> {
    pr_debug!("Linking {} object files", object_files.len());

    // TODO:
    // if !ALLOC:
    //     return
    // else if ty == SHT_NOBITS:
    //    .bss
    // else if SHF_EXECINSTR:
    //    .text
    // else if SHF_WRITE:
    //   .data
    // else:
    //   .rodata

    const TEXT_IDX: u16 = 0;
    const DATA_IDX: u16 = 1;
    const RODATA_IDX: u16 = 2;
    const BSS_IDX: u16 = 3;

    let mut sections: Vec<SectionPlacement<'_>> = Vec::with_capacity(object_files.len());
    let mut symbols: Vec<ObjectSymbol> = Vec::new();
    let mut relocations: Vec<ObjectRelocation> = Vec::new();
    let mut endianness = None;

    for object_file in object_files {
        pr_debug!("Object file: {}", object_file.file_name);
        ensure!(
            endianness.is_none_or(|x| x == object_file.endian),
            "Inconsistent endianness in file: {}",
            object_file.file_name
        );
        endianness.get_or_insert(object_file.endian);
        for section in object_file.sections {
            pr_debug!("  Section: {}", section.name);
            if section.flags.get(Elf64SectionFlags::SHF_ALLOC) == 0 {
                continue;
            } else if section.ty == Elf64SectionType::SHT_NOBITS {
                pr_debug!("    Type: .bss");
                ensure!(
                    section.flags.get(Elf64SectionFlags::SHF_EXECINSTR) == 0,
                    "invalid section: .bss section cannot have SHF_EXECINSTR flag in file: {}",
                    object_file.file_name
                );
                let size = section.size;
                let bss_section = sections.iter_mut().find(|x| x.out_idx == BSS_IDX);
                if let Some(bss_section) = bss_section {
                    let bss_offset = bss_section.size.next_multiple_of(section.align);
                    bss_section.size = bss_offset + size;
                    bss_section.align = lcm(bss_section.align, section.align);
                    bss_section.sections_data.push((section, bss_offset));
                } else {
                    sections.push(SectionPlacement {
                        out_idx: BSS_IDX,
                        name: ".bss".to_string(),
                        flags: Elf64ProgramHeaderFlags::new()
                            .set(Elf64ProgramHeaderFlags::readable, 1)
                            .set(Elf64ProgramHeaderFlags::writable, 1),
                        size: size,
                        align: section.align,
                        sections_data: vec![(section, 0)],
                        va: OnceCell::new(),
                        data: None,
                    });
                }
            } else if section.flags.get(Elf64SectionFlags::SHF_EXECINSTR) != 0 {
                pr_debug!("    Type: .text");
                ensure!(
                    section.flags.get(Elf64SectionFlags::SHF_WRITE) == 0,
                    "invalid section: .text section cannot have SHF_WRITE flag in file: {}",
                    object_file.file_name
                );
                let size = section.size;
                let text_section = sections.iter_mut().find(|x| x.out_idx == TEXT_IDX);
                if let Some(text_section) = text_section {
                    let text_offset = text_section.size.next_multiple_of(section.align);
                    text_section.size = text_offset + size;
                    text_section.align = lcm(text_section.align, section.align);
                    let data = text_section.data.as_mut().unwrap();
                    if data.len() < text_offset as usize {
                        data.resize(text_offset as usize, 0);
                    }
                    data.extend(section.data.unwrap());
                    text_section.sections_data.push((section, text_offset));
                } else {
                    sections.push(SectionPlacement {
                        out_idx: TEXT_IDX,
                        name: ".text".to_string(),
                        size: size,
                        align: section.align,
                        data: Some(section.data.unwrap().to_vec()),
                        sections_data: vec![(section, 0)],
                        va: OnceCell::new(),
                        flags: Elf64ProgramHeaderFlags::new()
                            .set(Elf64ProgramHeaderFlags::readable, 1)
                            .set(Elf64ProgramHeaderFlags::executable, 1),
                    });
                }
            } else if section.flags.get(Elf64SectionFlags::SHF_WRITE) != 0 {
                pr_debug!("    Type: .data");
                ensure!(
                    section.flags.get(Elf64SectionFlags::SHF_EXECINSTR) == 0,
                    "invalid section: .data section cannot have SHF_EXECINSTR flag in file: {}",
                    object_file.file_name
                );
                let size = section.size;
                let data_section = sections.iter_mut().find(|x| x.out_idx == DATA_IDX);
                if let Some(data_section) = data_section {
                    let data_offset = data_section.size.next_multiple_of(section.align);
                    data_section.size = data_offset + size;
                    data_section.align = lcm(data_section.align, section.align);
                    let data = data_section.data.as_mut().unwrap();
                    if data.len() < data_offset as usize {
                        data.resize(data_offset as usize, 0);
                    }
                    data.extend(section.data.unwrap());
                    data_section.sections_data.push((section, data_offset));
                } else {
                    sections.push(SectionPlacement {
                        out_idx: DATA_IDX,
                        name: ".data".to_string(),
                        size: size,
                        align: section.align,
                        data: Some(section.data.unwrap().to_vec()),
                        sections_data: vec![(section, 0)],
                        va: OnceCell::new(),
                        flags: Elf64ProgramHeaderFlags::new()
                            .set(Elf64ProgramHeaderFlags::readable, 1)
                            .set(Elf64ProgramHeaderFlags::writable, 1),
                    });
                }
            } else {
                pr_debug!("    Type: .rodata");
                ensure!(
                    section.flags.get(Elf64SectionFlags::SHF_EXECINSTR) == 0,
                    "invalid section: .rodata section cannot have SHF_EXECINSTR flag in file: {}",
                    object_file.file_name
                );
                let size = section.size;
                let rodata_section = sections.iter_mut().find(|x| x.out_idx == RODATA_IDX);
                if let Some(rodata_section) = rodata_section {
                    let rodata_offset = rodata_section.size.next_multiple_of(section.align);
                    rodata_section.size = rodata_offset + size;
                    rodata_section.align = lcm(rodata_section.align, section.align);
                    let data = rodata_section.data.as_mut().unwrap();
                    if data.len() < rodata_offset as usize {
                        data.resize(rodata_offset as usize, 0);
                    }
                    data.extend(section.data.unwrap());
                    rodata_section.sections_data.push((section, rodata_offset));
                } else {
                    sections.push(SectionPlacement {
                        out_idx: RODATA_IDX,
                        name: ".rodata".to_string(),
                        size: size,
                        align: section.align,
                        data: Some(section.data.unwrap().to_vec()),
                        sections_data: vec![(section, 0)],
                        va: OnceCell::new(),
                        flags: Elf64ProgramHeaderFlags::new()
                            .set(Elf64ProgramHeaderFlags::readable, 1),
                    });
                }
            }
        }

        for symbol in object_file.symbols {
            pr_debug!("  Symbol: {}", symbol.name);
            symbols.push(symbol);
        }

        for relocation in object_file.relocations {
            pr_debug!(
                "  Relocation: offset={:#x}, info={:?}, addend={}",
                relocation.offset,
                relocation.target_idx,
                relocation.addend
            );
            relocations.push(relocation);
        }
    }

    sections.sort_unstable_by_key(|x| x.out_idx);

    pr_debug!("Section virtual addresses:");
    let va_guard = script::LINKER_DATA.read().unwrap();
    let mut current_va = va_guard.vart_addr;

    // already sorted by out_idx
    for section in sections.iter_mut() {
        current_va = current_va.next_multiple_of(section.align);
        section.va.set(current_va).unwrap();
        pr_debug!("  out_idx: {}, va: {:#x}", section.out_idx, current_va);
        current_va += section.size;
    }

    Ok((
        sections,
        symbols,
        relocations,
        ElfData {
            endianness: endianness.unwrap(),
        },
    ))
}
