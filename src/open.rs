use std::fs::File;

use anyhow::{Context, Ok};
use memmap2::Mmap;

pub fn open_file_and_mmap(file_name: &String) -> anyhow::Result<Mmap> {
    pr_info!("Processing file: {}", file_name);
    pr_debug!("Opening file: {}", file_name);
    let file =
        File::open(file_name).with_context(|| format!("failed to open file: {}", file_name))?;
    pr_debug!("Successfully opened file: {}", file_name);
    // # Safety
    // This is safe because we are not modifying the file
    let mmap =
        unsafe { Mmap::map(&file).with_context(|| format!("failed to mmap file: {}", file_name))? };
    pr_debug!("Successfully created memory map for file: {}", file_name);

    Ok(mmap)
}
