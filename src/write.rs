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
        if section_placement.size == 0
            && section_placement
                .data
                .as_ref()
                .is_none_or(|data| data.is_empty())
        {
            continue;
        }
        let va = *section_placement.va.get().unwrap();
        let segment = LoadSegment {
            flags: section_placement.flags,
            vaddr: va,
            paddr: va,
            align: section_placement.segment_align,
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

#[cfg(test)]
mod tests {
    use std::{
        cell::OnceCell,
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use elf::{Elf64, Elf64ProgramHeaderFlags, ElfEndian, PF_R, PF_W, PF_X};

    use super::output;
    use crate::link::{ElfData, SectionPlacement};

    struct TempOutputPath(PathBuf);

    impl TempOutputPath {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            Self(std::env::temp_dir().join(format!(
                "my_linker-write-test-{}-{}.elf",
                std::process::id(),
                unique
            )))
        }

        fn as_path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempOutputPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn placed_section(
        out_idx: u16,
        name: &str,
        flags: u32,
        size: u64,
        align: u64,
        segment_align: u64,
        va: u64,
        data: Option<Vec<u8>>,
    ) -> SectionPlacement<'static> {
        let placement_va = {
            let cell = OnceCell::new();
            cell.set(va).unwrap();
            cell
        };

        SectionPlacement {
            out_idx,
            name: name.to_string(),
            flags: Elf64ProgramHeaderFlags::from_bits(flags),
            size,
            align,
            segment_align,
            va: placement_va,
            data,
            sections_data: Vec::new(),
        }
    }

    #[test]
    fn output_skips_empty_sections_and_uses_segment_alignment() {
        let path = TempOutputPath::new();
        let sections = vec![
            placed_section(
                0,
                ".text",
                PF_R | PF_X,
                2,
                16,
                0x1000,
                0x400000,
                Some(vec![0x90, 0xC3]),
            ),
            placed_section(
                1,
                ".rodata",
                PF_R,
                5,
                8,
                0x1000,
                0x401000,
                Some(b"hello".to_vec()),
            ),
            placed_section(
                2,
                ".data",
                PF_R | PF_W,
                0,
                8,
                0x1000,
                0x402000,
                Some(Vec::new()),
            ),
            placed_section(3, ".bss", PF_R | PF_W, 0, 8, 0x1000, 0x403000, None),
        ];

        output(
            sections,
            ElfData {
                endianness: ElfEndian::Little,
            },
            path.as_path().display().to_string(),
            0x400000,
        )
        .unwrap();

        let bytes = fs::read(path.as_path()).unwrap();
        let elf = Elf64::new(&bytes).unwrap();
        let headers = elf.program_headers().collect::<Vec<_>>();

        assert_eq!(headers.len(), 2);
        assert!(headers.iter().all(|header| header.align() == 0x1000));
        assert!(
            headers
                .iter()
                .all(|header| header.file_size() != 0 || header.mem_size() != 0)
        );
    }
}
