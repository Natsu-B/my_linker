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

// Output-section data remains separate until relocations have been applied.
// Consecutive output sections with the same permissions share one PT_LOAD.
pub(crate) fn load_segments(
    sections: Vec<OutputSection>,
    headers: &HeaderInfo,
    tls: Option<TlsSegment>,
) -> Result<Vec<LoadSegment>> {
    let mut segments = vec![LoadSegment {
        flags: Elf64ProgramHeaderFlags::from_bits(PF_R),
        vaddr: headers.address,
        paddr: headers.address,
        align: PAGE_SIZE,
        data: vec![0; usize::try_from(headers.size).context("headers too large")?],
        mem_size: headers.size,
    }];
    for section in sections.into_iter().filter(|section| section.size != 0) {
        let address = *section
            .address
            .get()
            .context("output section has no address")?;
        let previous = segments.last().unwrap();
        let previous_end = previous
            .vaddr
            .checked_add(previous.mem_size)
            .context("segment address exceeds u64")?;
        ensure!(address >= previous_end, "output sections overlap");
        if section.flags != previous.flags {
            ensure!(
                address / PAGE_SIZE >= previous_end.div_ceil(PAGE_SIZE),
                "load segments with different permissions share a virtual page"
            );
            segments.push(LoadSegment {
                flags: section.flags,
                vaddr: address,
                paddr: address,
                align: PAGE_SIZE.max(section.align),
                data: Vec::new(),
                mem_size: 0,
            });
        }
        let segment = segments.last_mut().unwrap();
        // For the header load p_offset is fixed at zero; PAGE_SIZE is its
        // alignment even if an input section happens to be more aligned.
        if segment.vaddr != headers.address {
            segment.align = segment.align.max(section.align);
        }
        let offset = address - segment.vaddr;
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
    if let Some(tls) = tls.filter(|tls| tls.file_size != 0) {
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
