use anyhow::{Context, Result, ensure};
use elf::{Elf64ProgramHeaderFlags, LoadSegment, PF_R};

use super::{HeaderInfo, OutputSection, PAGE_SIZE, tls::TlsSegment};

pub(crate) fn load_segment_count(sections: &[OutputSection]) -> u64 {
    let mut count = 1; // Mapped headers are the first read-only load.
    let mut flags = Elf64ProgramHeaderFlags::from_bits(PF_R);
    for section in sections.iter().filter(|section| section.size != 0) {
        if section.flags != flags {
            count += 1;
            flags = section.flags;
        }
    }
    count
}

/// The PT_LOAD fields that can be known before assembling file bytes.
pub(crate) struct LoadSegmentLayout {
    pub(crate) flags: Elf64ProgramHeaderFlags,
    pub(crate) address: u64,
    pub(crate) file_size: u64,
    pub(crate) mem_size: u64,
    pub(crate) align: u64,
}

// Consecutive output sections with the same permissions share one PT_LOAD.
// Reporting and output use the same description, including internal zero fill.
pub(crate) fn load_segment_layouts(
    sections: &[OutputSection],
    headers: &HeaderInfo,
    tls: Option<TlsSegment>,
) -> Result<Vec<LoadSegmentLayout>> {
    let mut segments = vec![LoadSegmentLayout {
        flags: Elf64ProgramHeaderFlags::from_bits(PF_R),
        address: headers.address,
        align: PAGE_SIZE,
        file_size: headers.size,
        mem_size: headers.size,
    }];
    for section in sections.iter().filter(|section| section.size != 0) {
        let address = *section
            .address
            .get()
            .context("output section has no address")?;
        let previous = segments.last().unwrap();
        let previous_end = previous
            .address
            .checked_add(previous.mem_size)
            .context("segment address exceeds u64")?;
        ensure!(address >= previous_end, "output sections overlap");
        if section.flags != previous.flags {
            ensure!(
                address / PAGE_SIZE >= previous_end.div_ceil(PAGE_SIZE),
                "load segments with different permissions share a virtual page"
            );
            segments.push(LoadSegmentLayout {
                flags: section.flags,
                address,
                align: PAGE_SIZE.max(section.align),
                file_size: 0,
                mem_size: 0,
            });
        }
        let segment = segments.last_mut().unwrap();
        // The header load has p_offset zero and PAGE_SIZE alignment.
        if segment.address != headers.address {
            segment.align = segment.align.max(section.align);
        }
        segment.mem_size = (address - segment.address)
            .checked_add(section.size)
            .context("segment size exceeds u64")?;
        if let Some(data) = &section.data {
            ensure!(
                data.len() as u64 <= section.size,
                "output section file size exceeds memory size"
            );
            segment.file_size = segment.mem_size;
        }
    }
    if let Some(tls) = tls.filter(|tls| tls.file_size != 0) {
        let segment = segments
            .iter_mut()
            .find(|segment| {
                tls.vaddr
                    .checked_sub(segment.address)
                    .is_some_and(|offset| {
                        offset
                            .checked_add(tls.mem_size)
                            .is_some_and(|end| end <= segment.mem_size)
                    })
            })
            .context("TLS template must be contained in one PT_LOAD segment")?;
        // A script may reserve trailing padding in .tdata with assignments.
        segment.file_size = segment
            .file_size
            .max(tls.vaddr - segment.address + tls.file_size);
    }
    Ok(segments)
}

// Output-section data remains separate until relocations have been applied.
pub(crate) fn load_segments(
    sections: Vec<OutputSection>,
    headers: &HeaderInfo,
    tls: Option<TlsSegment>,
) -> Result<Vec<LoadSegment>> {
    let mut segments = load_segment_layouts(&sections, headers, tls)?
        .into_iter()
        .map(|segment| {
            Ok(LoadSegment {
                flags: segment.flags,
                vaddr: segment.address,
                paddr: segment.address,
                align: segment.align,
                data: vec![0; usize::try_from(segment.file_size).context("segment too large")?],
                mem_size: segment.mem_size,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut index = 0;
    for section in sections.into_iter().filter(|section| section.size != 0) {
        if section.flags != segments[index].flags {
            index += 1;
        }
        if let Some(data) = section.data {
            let segment = &mut segments[index];
            let offset = usize::try_from(section.address.get().unwrap() - segment.vaddr)
                .context("section offset exceeds usize")?;
            segment.data[offset..offset + data.len()].copy_from_slice(&data);
        }
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use std::cell::OnceCell;

    use super::*;
    use elf::PF_W;

    fn section(
        name: &str,
        address: u64,
        size: u64,
        data: Option<Vec<u8>>,
    ) -> OutputSection<'static> {
        OutputSection {
            name: name.to_string(),
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R | PF_W),
            size,
            align: 16,
            address: OnceCell::from(address),
            data,
            inputs: Vec::new(),
        }
    }

    #[test]
    fn grouping_keeps_bss_tails_and_materializes_internal_zero_fill() {
        let headers = HeaderInfo {
            address: 0x400000,
            size: 232,
        };
        let segments = load_segments(
            vec![
                section(".data", 0x401000, 2, Some(vec![1, 2])),
                section(".zero", 0x401002, 14, None),
                section(".more", 0x401010, 1, Some(vec![3])),
                section(".bss", 0x401020, 32, None),
                section(".empty", 0x402000, 0, Some(Vec::new())),
            ],
            &headers,
            None,
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
