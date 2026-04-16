use anyhow::{Ok, Result};
use elf::ExecElf64Writer;

use crate::link::{ElfData, SectionPlacement};

pub fn output(
    section_placements: Vec<SectionPlacement>,
    elf_data: ElfData,
    output_file: String,
    entry: u64,
) -> Result<()> {
    pr_debug!("Write output file: {}", output_file);
    let writer = ExecElf64Writer::new_x86_64_executable(entry);
    for section_placement in section_placements {
        
    }

    Ok(())
}
