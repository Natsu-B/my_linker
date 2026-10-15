use std::{
    fs::{OpenOptions, Permissions},
    os::unix::fs::PermissionsExt,
};

use anyhow::{Ok, Result};
use elf::{
    Elf64ProgramHeaderFlags, ElfProgramHeaderType, ExecElf64Writer, LoadSegment, ProgramHeader,
};
use memmap2::MmapMut;

use crate::link::{ElfData, PAGE_SIZE, SectionPlacement};

pub fn output(
    section_placements: Vec<SectionPlacement>,
    elf_data: ElfData,
    output_file: String,
    entry: u64,
) -> Result<()> {
    pr_debug!("Write output file: {}", output_file);
    let mut writer = ExecElf64Writer::new_x86_64_executable(entry);
    writer.endian = elf_data.endianness;
    writer.map_headers(elf_data.header_vaddr, PAGE_SIZE);
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
    writer.add_program_header(ProgramHeader {
        segment_type: ElfProgramHeaderType::PT_GNU_STACK,
        flags: Elf64ProgramHeaderFlags::new()
            .set(Elf64ProgramHeaderFlags::readable, 1)
            .set(Elf64ProgramHeaderFlags::writable, 1),
        offset: 0,
        vaddr: 0,
        paddr: 0,
        file_size: 0,
        mem_size: 0,
        align: 16,
    });

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
    file.set_permissions(Permissions::from_mode(0o755))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        cell::OnceCell,
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use elf::{Elf64, Elf64ProgramHeaderFlags, ElfEndian, ElfProgramHeaderType, PF_R, PF_W, PF_X};

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
                0x401000,
                Some(vec![0x90, 0xC3]),
            ),
            placed_section(
                1,
                ".rodata",
                PF_R,
                5,
                8,
                0x1000,
                0x402000,
                Some(b"hello".to_vec()),
            ),
            placed_section(
                2,
                ".data",
                PF_R | PF_W,
                0,
                8,
                0x1000,
                0x403000,
                Some(Vec::new()),
            ),
            placed_section(3, ".bss", PF_R | PF_W, 0, 8, 0x1000, 0x404000, None),
        ];

        fs::write(path.as_path(), b"old output").unwrap();
        fs::set_permissions(path.as_path(), fs::Permissions::from_mode(0o600)).unwrap();
        output(
            sections,
            ElfData {
                endianness: ElfEndian::Little,
                header_vaddr: 0x400000,
            },
            path.as_path().display().to_string(),
            0x401000,
        )
        .unwrap();

        let bytes = fs::read(path.as_path()).unwrap();
        let elf = Elf64::new(&bytes).unwrap();
        let headers = elf
            .program_headers()
            .filter(|header| header.segment_type() == ElfProgramHeaderType::PT_LOAD)
            .collect::<Vec<_>>();

        assert_eq!(elf.program_header_count(), 4);
        assert_eq!(headers.len(), 3);
        assert!(headers.iter().all(|header| header.align() == 0x1000));
        assert!(
            headers
                .iter()
                .all(|header| header.file_size() != 0 || header.mem_size() != 0)
        );
        assert_eq!(
            fs::metadata(path.as_path()).unwrap().permissions().mode() & 0o7777,
            0o755
        );
    }
}
