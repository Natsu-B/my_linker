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
    if let Some(tls) = elf_data.tls.filter(|tls| tls.file_size != 0) {
        let segment = segments
            .iter_mut()
            .find(|segment| {
                tls.vaddr.checked_sub(segment.vaddr).is_some_and(|offset| {
                    offset
                        .checked_add(tls.mem_size)
                        .is_some_and(|end| end <= segment.mem_size)
                })
            })
            .context("TLS template must be contained in one PT_LOAD segment")?;
        let end = tls.vaddr - segment.vaddr + tls.file_size;
        // A script may reserve trailing padding in .tdata with assignments.
        let file_size = segment
            .data
            .len()
            .max(usize::try_from(end).context("TLS template too large")?);
        segment.data.resize(file_size, 0);
    }
    Ok(segments)
}

fn executable_writer(
    section_placements: Vec<SectionPlacement>,
    elf_data: &ElfData,
    entry: u64,
) -> Result<ExecElf64Writer> {
    let mut writer = ExecElf64Writer::new_x86_64_executable(entry);
    let mut segments = load_segments(section_placements, elf_data)?.into_iter();
    writer.header_segment = segments.next();
    for segment in segments {
        writer.add_load_segment(segment);
    }
    if let Some(tls) = elf_data.tls {
        writer.add_program_header(ProgramHeader {
            segment_type: ElfProgramHeaderType::PT_TLS,
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R),
            offset: 0,
            vaddr: tls.vaddr,
            paddr: tls.vaddr,
            file_size: tls.file_size,
            mem_size: tls.mem_size,
            align: tls.align,
        });
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
    if let Some(tls) = elf_data.tls {
        // All headers are reserved before translating the TLS template VMA.
        let offset = writer.file_offset(tls.vaddr)?;
        let header = writer
            .program_headers
            .iter_mut()
            .find(|header| header.segment_type == ElfProgramHeaderType::PT_TLS)
            .context("PT_TLS header was not added")?;
        header.offset = offset;
    }
    Ok(writer)
}

pub fn output(
    section_placements: Vec<SectionPlacement>,
    elf_data: ElfData,
    output_file: String,
    entry: u64,
) -> Result<()> {
    pr_debug!("Write output file: {}", output_file);
    let writer = executable_writer(section_placements, &elf_data, entry)?;
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
    use std::{borrow::Cow, cell::OnceCell, collections::HashMap};

    use super::*;
    use crate::{input_id::FileId, parse::ObjectSection, tls::TlsSegment};
    use elf::{Elf64, Elf64SectionFlags};

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
            header_vaddr: 0x400000,
            sizeof_headers: 232,
            script_symbols: HashMap::new(),
            tls: None,
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

    fn tls_section(
        name: &'static str,
        va: u64,
        size: u64,
        align: u64,
        data: Option<Vec<u8>>,
    ) -> SectionPlacement<'static> {
        let input = ObjectSection {
            file_id: FileId::Object(0),
            idx: 1,
            name,
            flags: Elf64SectionFlags::from_bits(0x403),
            align,
            size,
            data: data.clone().map(Cow::Owned),
        };
        let mut section = section(name, va, size, data);
        section.align = align;
        section.sections_data.push((input, 0));
        section
    }

    #[test]
    fn tls_headers_describe_initialized_zero_fill_and_alignment_ranges() {
        // Exercise both a TLS tail and initialized RW data after .tbss.
        for following_data in [false, true] {
            for (mut sections, expected) in [
                (
                    vec![
                        tls_section(".tdata", 0x401020, 24, 8, Some(vec![7; 24])),
                        tls_section(".tbss", 0x401040, 17, 32, None),
                    ],
                    TlsSegment {
                        vaddr: 0x401020,
                        file_size: 24,
                        mem_size: 49,
                        align: 32,
                    },
                ),
                (
                    vec![tls_section(".tdata", 0x401028, 24, 8, Some(vec![7; 24]))],
                    TlsSegment {
                        vaddr: 0x401028,
                        file_size: 24,
                        mem_size: 24,
                        align: 8,
                    },
                ),
                (
                    vec![tls_section(".tbss", 0x401020, 17, 32, None)],
                    TlsSegment {
                        vaddr: 0x401020,
                        file_size: 0,
                        mem_size: 17,
                        align: 32,
                    },
                ),
            ] {
                let tls = TlsSegment::from_sections(&sections).unwrap();
                assert_eq!(tls, Some(expected));
                if following_data {
                    sections.insert(0, section(".prefix", 0x401000, 1, Some(vec![9])));
                    sections.push(section(".data", 0x401080, 1, Some(vec![0x42])));
                }
                let elf_data = ElfData {
                    header_vaddr: 0x400000,
                    sizeof_headers: ELF_HEADER_SIZE + 4 * PROGRAM_HEADER_SIZE,
                    script_symbols: HashMap::new(),
                    tls,
                };
                let writer = executable_writer(sections, &elf_data, 0x400000).unwrap();
                let mut bytes = vec![0; writer.file_size().unwrap() as usize];
                writer.write_into(&mut bytes).unwrap();
                let elf = Elf64::new(&bytes).unwrap();
                assert_eq!(elf.program_header_count(), 4);
                let tls = elf
                    .program_headers()
                    .find(|header| header.segment_type() == ElfProgramHeaderType::PT_TLS)
                    .unwrap();
                assert_eq!(tls.flags(), PF_R);
                assert_eq!(tls.vaddr(), expected.vaddr);
                assert_eq!(tls.paddr(), expected.vaddr);
                assert_eq!(tls.file_size(), expected.file_size);
                assert_eq!(tls.mem_size(), expected.mem_size);
                assert_eq!(tls.align(), expected.align);
                assert_eq!(tls.data().unwrap(), vec![7; expected.file_size as usize]);
                let load = elf
                    .program_headers()
                    .find(|header| header.flags() == PF_R | PF_W)
                    .unwrap();
                assert_eq!(tls.offset(), load.offset() + tls.vaddr() - load.vaddr());
                if following_data {
                    let data = load.data().unwrap();
                    assert_eq!(*data.last().unwrap(), 0x42);
                    assert_eq!(
                        &data[(tls.vaddr() - load.vaddr() + expected.file_size) as usize
                            ..data.len() - 1],
                        vec![
                            0;
                            data.len()
                                - 1
                                - (tls.vaddr() - load.vaddr() + expected.file_size) as usize
                        ]
                    );
                    assert_eq!(load.vaddr() + data.len() as u64 - 1, 0x401080);
                }
            }
        }
    }

    #[test]
    fn trailing_script_padding_is_present_in_the_tls_file_image() {
        let mut tdata = tls_section(".tdata", 0x401000, 24, 8, Some(vec![7; 24]));
        tdata.size = 32;
        let sections = vec![tdata];
        let tls = TlsSegment::from_sections(&sections).unwrap().unwrap();
        assert_eq!(tls.file_size, 32);
        assert_eq!(tls.mem_size, 32);
        let elf_data = ElfData {
            header_vaddr: 0x400000,
            sizeof_headers: ELF_HEADER_SIZE + 4 * PROGRAM_HEADER_SIZE,
            script_symbols: HashMap::new(),
            tls: Some(tls),
        };
        let writer = executable_writer(sections, &elf_data, 0x400000).unwrap();
        let mut bytes = vec![0; writer.file_size().unwrap() as usize];
        writer.write_into(&mut bytes).unwrap();
        let elf = Elf64::new(&bytes).unwrap();
        let tls = elf
            .program_headers()
            .find(|header| header.segment_type() == ElfProgramHeaderType::PT_TLS)
            .unwrap();
        assert_eq!(&tls.data().unwrap()[..24], &[7; 24]);
        assert_eq!(&tls.data().unwrap()[24..], &[0; 8]);
    }
}
