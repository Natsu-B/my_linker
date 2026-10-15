use std::{
    fs::{OpenOptions, Permissions},
    os::unix::fs::PermissionsExt,
};

use anyhow::{Context, Result, ensure};
use elf::{
    Elf64ProgramHeaderFlags, ElfProgramHeaderType, ExecElf64Writer, LoadSegment, PF_R, PF_W,
    ProgramHeader,
    write::{ELF_HEADER_SIZE, PROGRAM_HEADER_SIZE},
};
use memmap2::MmapMut;

use crate::link::{ElfData, PAGE_SIZE, SectionPlacement};

// Output-section data remains separate until relocations have been applied.
// Consecutive output sections with the same permissions share one PT_LOAD.
fn load_segments(sections: Vec<SectionPlacement>, elf_data: &ElfData) -> Result<Vec<LoadSegment>> {
    let mut segments = vec![LoadSegment {
        flags: Elf64ProgramHeaderFlags::from_bits(PF_R),
        vaddr: elf_data.header_vaddr,
        paddr: elf_data.header_vaddr,
        align: PAGE_SIZE,
        data: vec![0; usize::try_from(elf_data.sizeof_headers).context("headers too large")?],
        mem_size: elf_data.sizeof_headers,
    }];
    for section in sections.into_iter().filter(|section| section.size != 0) {
        let va = *section.va.get().context("output section has no address")?;
        let previous = segments.last().unwrap();
        let previous_end = previous
            .vaddr
            .checked_add(previous.mem_size)
            .context("segment address exceeds u64")?;
        ensure!(va >= previous_end, "output sections overlap");
        if section.flags != previous.flags {
            ensure!(
                va / PAGE_SIZE >= previous_end.div_ceil(PAGE_SIZE),
                "load segments with different permissions share a virtual page"
            );
            segments.push(LoadSegment {
                flags: section.flags,
                vaddr: va,
                paddr: va,
                align: PAGE_SIZE.max(section.align),
                data: Vec::new(),
                mem_size: 0,
            });
        }
        let segment = segments.last_mut().unwrap();
        // For the header load p_offset is fixed at zero; PAGE_SIZE is its
        // alignment even if an input section happens to be more aligned.
        if segment.vaddr != elf_data.header_vaddr {
            segment.align = segment.align.max(section.align);
        }
        let offset = va - segment.vaddr;
        if let Some(data) = section.data {
            ensure!(
                data.len() as u64 <= section.size,
                "output section file size exceeds memory size"
            );
            if !data.is_empty() {
                segment
                    .data
                    .resize(usize::try_from(offset).context("segment too large")?, 0);
                segment.data.extend(data);
            }
        }
        segment.mem_size = offset
            .checked_add(section.size)
            .context("segment size exceeds u64")?;
    }
    Ok(segments)
}

pub fn output(
    section_placements: Vec<SectionPlacement>,
    elf_data: ElfData,
    output_file: String,
    entry: u64,
) -> Result<()> {
    pr_debug!("Write output file: {}", output_file);
    let mut writer = ExecElf64Writer::new_x86_64_executable(entry);
    writer.endian = elf_data.endianness;
    let mut segments = load_segments(section_placements, &elf_data)?.into_iter();
    writer.header_segment = segments.next();
    for segment in segments {
        writer.add_load_segment(segment);
    }
    writer.add_program_header(ProgramHeader {
        segment_type: ElfProgramHeaderType::PT_GNU_STACK,
        flags: Elf64ProgramHeaderFlags::from_bits(PF_R | PF_W),
        offset: 0,
        vaddr: 0,
        paddr: 0,
        file_size: 0,
        mem_size: 0,
        align: 16,
    });
    // Layout reserved SIZEOF_HEADERS bytes before the first section; the
    // headers written here must fit exactly in that space.
    let phnum = 1 + writer.segments.len() + writer.program_headers.len();
    ensure!(
        ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE * phnum as u64 == elf_data.sizeof_headers,
        "program header count {phnum} does not match SIZEOF_HEADERS {:#x}",
        elf_data.sizeof_headers
    );

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
    use std::{cell::OnceCell, collections::HashMap};

    use super::*;

    fn section(name: &str, va: u64, size: u64, data: Option<Vec<u8>>) -> SectionPlacement<'static> {
        SectionPlacement {
            name: name.to_string(),
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R | PF_W),
            size,
            align: 16,
            va: OnceCell::from(va),
            data,
            sections_data: Vec::new(),
        }
    }

    #[test]
    fn grouping_keeps_bss_tails_and_materializes_internal_zero_fill() {
        let elf_data = ElfData {
            endianness: elf::ElfEndian::Little,
            header_vaddr: 0x400000,
            sizeof_headers: 232,
            script_symbols: HashMap::new(),
        };
        let segments = load_segments(
            vec![
                section(".data", 0x401000, 2, Some(vec![1, 2])),
                section(".zero", 0x401002, 14, None),
                section(".more", 0x401010, 1, Some(vec![3])),
                section(".bss", 0x401020, 32, None),
                section(".empty", 0x402000, 0, Some(Vec::new())),
            ],
            &elf_data,
        )
        .unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[1].vaddr, 0x401000);
        assert_eq!(segments[1].mem_size, 64);
        assert_eq!(segments[1].data.len(), 17);
        assert_eq!(&segments[1].data[..2], &[1, 2]);
        assert_eq!(&segments[1].data[2..16], &[0; 14]);
        assert_eq!(segments[1].data[16], 3);
    }
}
