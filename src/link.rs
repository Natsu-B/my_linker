use std::ops::Deref;

use crate::{
    parse::{ObjectFile, ObjectSection},
    script,
};
use anyhow::{Context, Result, ensure};
use elf::{Elf64SectionFlags, Elf64SectionType};

pub struct LinkedResult {}

struct SectionPlacement<'a> {
    out_idx: u16,
    addr: u64,
    output_data: ObjectSection<'a>,
}

pub fn link(object_files: Vec<ObjectFile>) -> Result<LinkedResult> {
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

    let va_guard = script::LINKER_DATA.read().unwrap();
    let mut va = va_guard.vart_addr;

    const TEXT_IDX: u16 = 0;
    const BSS_IDX: u16 = 1;
    const DATA_IDX: u16 = 2;
    const RODATA_IDX: u16 = 3;

    let mut sections = Vec::with_capacity(object_files.len());
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
                sections.push(SectionPlacement {
                    out_idx: BSS_IDX,
                    addr: va,
                    output_data: section,
                });
                va += size;
            } else if section.flags.get(Elf64SectionFlags::SHF_EXECINSTR) != 0 {
                pr_debug!("    Type: .text");
                ensure!(
                    section.flags.get(Elf64SectionFlags::SHF_WRITE) == 0,
                    "invalid section: .text section cannot have SHF_WRITE flag in file: {}",
                    object_file.file_name
                );
                let size = section.size;
                sections.push(SectionPlacement {
                    out_idx: TEXT_IDX,
                    addr: va,
                    output_data: section,
                });
                va += size;
            } else if section.flags.get(Elf64SectionFlags::SHF_WRITE) != 0 {
                pr_debug!("    Type: .data");
                ensure!(
                    section.flags.get(Elf64SectionFlags::SHF_EXECINSTR) == 0,
                    "invalid section: .data section cannot have SHF_EXECINSTR flag in file: {}",
                    object_file.file_name
                );
                let size = section.size;
                sections.push(SectionPlacement {
                    out_idx: DATA_IDX,
                    addr: va,
                    output_data: section,
                });
                va += size;
            } else {
                pr_debug!("    Type: .rodata");
                ensure!(
                    section.flags.get(Elf64SectionFlags::SHF_EXECINSTR) == 0,
                    "invalid section: .rodata section cannot have SHF_EXECINSTR flag in file: {}",
                    object_file.file_name
                );
                let size = section.size;
                sections.push(SectionPlacement {
                    out_idx: RODATA_IDX,
                    addr: va,
                    output_data: section,
                });
                va += size;
            }
        }
    }

    Ok(LinkedResult {})
}
