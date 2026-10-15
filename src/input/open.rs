//! Map an input file so later steps can borrow its bytes.
//!
//! [`open_file_and_mmap`] takes a path and returns a read-only [`memmap2::Mmap`].
//! [`super::MappedFiles`] keeps the map alive through the link. This avoids a
//! copy of each large static library and lets rayon read files in parallel.
//! The backing file must stay unchanged while the map exists.
//!
//! Reference: ELF gABI "File Format" explains the file ranges that later readers
//! use for headers, sections, and tables.

use std::fs::File;

use anyhow::{Context, Ok};
use memmap2::Mmap;

/// Map a file read-only. The caller must keep its backing file unchanged.
pub(crate) fn open_file_and_mmap(file_name: &String) -> anyhow::Result<Mmap> {
    pr_info!("Processing file: {}", file_name);
    pr_debug!("Opening file: {}", file_name);
    let file =
        File::open(file_name).with_context(|| format!("failed to open file: {}", file_name))?;
    pr_debug!("Successfully opened file: {}", file_name);
    // SAFETY: We only read the map. The caller must keep its backing file
    // unchanged until MappedFiles drops the map.
    let mmap =
        unsafe { Mmap::map(&file).with_context(|| format!("failed to mmap file: {}", file_name))? };
    pr_debug!("Successfully created memory map for file: {}", file_name);

    Ok(mmap)
}
