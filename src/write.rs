use std::fs::OpenOptions;

use anyhow::{Ok, Result};
use elf::{ExecElf64Writer, LoadSegment};
use memmap2::MmapMut;

use crate::link::{ElfData, SectionPlacement};

pub fn output(
    section_placements: Vec<SectionPlacement>,
    elf_data: ElfData,
    output_file: String,
    entry: u64,
) -> Result<()> {
    pr_debug!("Write output file: {}", output_file);
    let mut writer = ExecElf64Writer::new_x86_64_executable(entry);
    for section_placement in section_placements {
        let va = *section_placement.va.get().unwrap();
        let segment = LoadSegment {
            flags: section_placement.flags,
            vaddr: va,
            paddr: va,
            align: section_placement.align,
            data: section_placement.data.unwrap_or_else(|| Vec::new()),
            mem_size: section_placement.size,
        };
        writer.add_load_segment(segment);
    }

    let file_size = writer.file_size()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output_file)?;

    file.set_len(file_size)?;
    let mut mmap = unsafe { MmapMut::map_mut(&file) }?;
    writer.write_into(&mut mmap)?;
    mmap.flush()?;

    Ok(())
}
