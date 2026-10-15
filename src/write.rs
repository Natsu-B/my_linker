use std::{
    fs::{OpenOptions, Permissions},
    os::unix::fs::PermissionsExt,
};

use anyhow::{Context, Result, ensure};
use elf::{
    Elf64ProgramHeaderFlags, Elf64SectionFlags, Elf64SectionType, Elf64SymbolSectionIdx,
    Elf64SymbolType, ElfProgramHeaderType, ExecElf64Writer, LoadSegment, PF_R, PF_W, ProgramHeader,
    SHN_ABS, SHN_LORESERVE, SHN_UNDEF,
    write::{ELF_HEADER_SIZE, Elf64SymbolEntry, PROGRAM_HEADER_SIZE, Section, SymbolTableBuilder},
};
use memmap2::MmapMut;

use crate::{
    link::{ElfData, Linked, PAGE_SIZE, SectionPlacement},
    resolve::{Definition, ResolvedSymbol},
    synthetic::SyntheticSection,
};

/// Translate layout indices to ELF section indices without emitting empty sections.
struct SectionHeaderIndices {
    by_output: Vec<Option<u16>>,
    kept_count: usize,
}

impl SectionHeaderIndices {
    fn new(sections: &[SectionPlacement]) -> Result<Self> {
        let mut by_output = Vec::with_capacity(sections.len());
        let mut kept_count = 0;
        for section in sections {
            let index = if section.size == 0 {
                None
            } else {
                kept_count += 1;
                let index = u16::try_from(kept_count).context("too many output sections")?;
                ensure!(
                    index < SHN_LORESERVE,
                    "output section requires an extended index"
                );
                Some(index)
            };
            by_output.push(index);
        }
        Ok(Self {
            by_output,
            kept_count,
        })
    }

    fn get(&self, output_index: usize) -> Result<u16> {
        self.by_output
            .get(output_index)
            .copied()
            .flatten()
            .context("output section has no section header")
    }

    fn for_symbol(&self, output_index: usize) -> Result<u16> {
        let following = self
            .by_output
            .get(output_index..)
            .context("symbol output section index is out of range")?;
        // An empty section's markers retain their values. Associate them with
        // the following kept section, or the preceding one at the end of the
        // image. This also makes empty preinit-array markers name .init_array.
        Ok(following
            .iter()
            .find_map(|index| *index)
            .or_else(|| {
                self.by_output[..output_index]
                    .iter()
                    .rev()
                    .find_map(|index| *index)
            })
            .unwrap_or(SHN_ABS))
    }
}

fn contains_synthetic(section: &SectionPlacement, synthetic: SyntheticSection) -> bool {
    section
        .sections_data
        .iter()
        .any(|(input, _)| synthetic.is_input(input))
}

fn output_sections(
    sections: &[SectionPlacement],
    indices: &SectionHeaderIndices,
) -> Result<Vec<Section>> {
    sections
        .iter()
        .filter(|section| section.size != 0)
        .map(|section| {
            let first = section.sections_data.first().map(|(input, _)| input);
            let section_type = if section.data.is_none() {
                Elf64SectionType::SHT_NOBITS
            } else {
                first.map_or(Elf64SectionType::SHT_PROGBITS, |input| input.section_type)
            };
            let mut entry_size = first.map_or(0, |input| input.entry_size);
            if section
                .sections_data
                .iter()
                .any(|(input, _)| input.entry_size != entry_size)
            {
                entry_size = 0;
            }
            let has_tls = section
                .sections_data
                .iter()
                .any(|(input, _)| input.flags.get(Elf64SectionFlags::SHF_TLS) != 0);
            // MERGE/STRINGS describe the whole output only when every input has
            // that attribute and their fixed-size entries agree.
            let merge = entry_size != 0
                && section
                    .sections_data
                    .iter()
                    .all(|(input, _)| input.flags.get(Elf64SectionFlags::SHF_MERGE) != 0);
            let strings = entry_size != 0
                && section
                    .sections_data
                    .iter()
                    .all(|(input, _)| input.flags.get(Elf64SectionFlags::SHF_STRINGS) != 0);
            let mut flags = Elf64SectionFlags::new()
                .set(Elf64SectionFlags::SHF_ALLOC, 1)
                .set(
                    Elf64SectionFlags::SHF_WRITE,
                    u64::from(section.flags.get(Elf64ProgramHeaderFlags::writable)),
                )
                .set(
                    Elf64SectionFlags::SHF_EXECINSTR,
                    u64::from(section.flags.get(Elf64ProgramHeaderFlags::executable)),
                )
                .set(Elf64SectionFlags::SHF_TLS, u64::from(has_tls))
                .set(Elf64SectionFlags::SHF_MERGE, u64::from(merge))
                .set(Elf64SectionFlags::SHF_STRINGS, u64::from(strings));
            let info = if contains_synthetic(section, SyntheticSection::RelaIplt) {
                // IRELATIVE records write the synthetic GOT slots. SHF_INFO_LINK
                // makes sh_info identify that output section, even under a custom name.
                let target = sections
                    .iter()
                    .position(|candidate| contains_synthetic(candidate, SyntheticSection::Got))
                    .context("IRELATIVE records have no GOT output section")?;
                flags = flags.set(Elf64SectionFlags::SHF_INFO_LINK, 1);
                u32::from(indices.get(target)?)
            } else {
                0
            };
            Ok(Section {
                name: section.name.clone(),
                section_type,
                flags,
                address: *section.va.get().context("output section has no address")?,
                size: section.size,
                link: u32::from(SHN_UNDEF),
                info,
                align: section.align,
                entry_size,
                data: None,
            })
        })
        .collect()
}

fn output_symbol<'a>(
    symbol: &'a ResolvedSymbol,
    linked: &Linked,
    indices: &SectionHeaderIndices,
) -> Result<Elf64SymbolEntry<'a>> {
    let output_index = match symbol.definition {
        Definition::Input {
            file_id,
            section_idx: Elf64SymbolSectionIdx::Index(index),
            ..
        } => Some(
            linked
                .section_index
                .get(&(file_id, index))
                .context("symbol section was not placed")?
                .output_idx,
        ),
        Definition::Script { .. } => linked
            .elf_data
            .script_symbol_sections
            .get(&symbol.name)
            .copied(),
        _ => None,
    };
    let section_index = if let Some(index) = output_index {
        indices.for_symbol(index)?
    } else if matches!(symbol.definition, Definition::UndefinedWeak) {
        SHN_UNDEF
    } else {
        SHN_ABS
    };
    let mut value = *symbol.va.get().context("output symbol has no value")?;
    if symbol.ty == Some(Elf64SymbolType::STT_TLS) && output_index.is_some() {
        // Executable TLS st_value is an offset in the TLS template, whereas
        // relocation evaluation keeps using the symbol's virtual address.
        value = value
            .checked_sub(
                linked
                    .elf_data
                    .tls
                    .context("TLS symbol without PT_TLS")?
                    .vaddr,
            )
            .context("TLS symbol precedes the TLS template")?;
    }
    Ok(Elf64SymbolEntry {
        name: &symbol.name,
        binding: symbol.binding,
        ty: symbol.ty.unwrap_or(Elf64SymbolType::STT_NOTYPE),
        other: symbol.other,
        section_index,
        value,
        size: symbol.size,
    })
}

fn symbol_table_sections(linked: &Linked, indices: &SectionHeaderIndices) -> Result<[Section; 2]> {
    let mut builder = SymbolTableBuilder::new();
    for symbol in linked.symbols.all_symbols().filter(|symbol| {
        !symbol.name.is_empty()
            && symbol.va.get().is_some()
            && !matches!(
                symbol.ty,
                Some(Elf64SymbolType::STT_SECTION | Elf64SymbolType::STT_FILE)
            )
    }) {
        builder.add(output_symbol(symbol, linked, indices)?);
    }
    // The allocated headers follow section zero, then .symtab and .strtab.
    let strtab_index = u32::try_from(indices.kept_count + 2).context("too many sections")?;
    builder.build(strtab_index)
}

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
            segment.data.resize(
                usize::try_from(offset + section.size).context("segment too large")?,
                0,
            );
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
    let indices = SectionHeaderIndices::new(&section_placements)?;
    let sections = output_sections(&section_placements, &indices)?;
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
    writer.sections = sections;
    Ok(writer)
}

pub fn output(linked: Linked, output_file: String, entry: u64) -> Result<()> {
    pr_debug!("Write output file: {}", output_file);
    let indices = SectionHeaderIndices::new(&linked.sections)?;
    let tables = symbol_table_sections(&linked, &indices)?;
    let mut writer = executable_writer(linked.sections, &linked.elf_data, entry)?;
    writer.sections.extend(tables);
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
            script_symbol_sections: HashMap::new(),
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
            flags: Elf64SectionFlags::new()
                .set(Elf64SectionFlags::SHF_ALLOC, 1)
                .set(Elf64SectionFlags::SHF_WRITE, 1)
                .set(Elf64SectionFlags::SHF_TLS, 1),
            section_type: if data.is_some() {
                elf::Elf64SectionType::SHT_PROGBITS
            } else {
                elf::Elf64SectionType::SHT_NOBITS
            },
            entry_size: 0,
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
                    script_symbol_sections: HashMap::new(),
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
            script_symbol_sections: HashMap::new(),
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
