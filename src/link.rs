use std::cell::OnceCell;

use crate::{
    parse::{ObjectFile, ObjectSection},
    script,
};
use anyhow::{Result, ensure};
use elf::{Elf64SectionFlags, Elf64SectionType};
use num::integer::lcm;

pub struct SectionPlacement<'a> {
    out_idx: u16,
    size: u64,
    align: u64,
    va: OnceCell<u64>,
    output_data: Vec<(ObjectSection<'a>, u64 /* offset */)>,
}

pub fn link(object_files: Vec<ObjectFile>) -> Result<Vec<SectionPlacement>> {
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
    const BSS_IDX: u16 = 1;
    const DATA_IDX: u16 = 2;
    const RODATA_IDX: u16 = 3;

    let mut sections: Vec<SectionPlacement<'_>> = Vec::with_capacity(object_files.len());
    for object_file in object_files {
        pr_debug!("Object file: {}", object_file.file_name);
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
                    bss_section.output_data.push((section, bss_offset));
                } else {
                    sections.push(SectionPlacement {
                        out_idx: BSS_IDX,
                        size: size,
                        align: section.align,
                        output_data: vec![(section, 0)],
                        va: OnceCell::new(),
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
                    text_section.output_data.push((section, text_offset));
                } else {
                    sections.push(SectionPlacement {
                        out_idx: TEXT_IDX,
                        size: size,
                        align: section.align,
                        output_data: vec![(section, 0)],
                        va: OnceCell::new(),
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
                    data_section.output_data.push((section, data_offset));
                } else {
                    sections.push(SectionPlacement {
                        out_idx: DATA_IDX,
                        size: size,
                        align: section.align,
                        output_data: vec![(section, 0)],
                        va: OnceCell::new(),
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
                    rodata_section.output_data.push((section, rodata_offset));
                } else {
                    sections.push(SectionPlacement {
                        out_idx: RODATA_IDX,
                        size: size,
                        align: section.align,
                        output_data: vec![(section, 0)],
                        va: OnceCell::new(),
                    });
                }
            }
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

    Ok(sections)
}
