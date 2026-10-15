//! Group placed sections into the memory ranges the kernel will load.
//!
//! [`load_segment_layouts`] takes section addresses and returns
//! [`LoadSegmentLayout`] records. [`load_segments`] adds the patched bytes to
//! make ELF [`LoadSegment`] values. [`load_segment_count`] supplies the count
//! needed to set SIZEOF_HEADERS.
//!
//! A PT_LOAD segment gives one range a set of read, write, and execute flags.
//! As in GNU ld's usual static layout, a permission change starts a new page.
//! A .bss tail needs memory only; if more data follows .bss in the same segment,
//! we must put zeros in the file for that gap. The first load maps the headers.
//!
//! References: ELF gABI "Program Header", "Segment Permissions", and "Segment Contents";
//! AMD64 psABI §5.1.

use anyhow::{Context, Result, ensure};
use elf::{Elf64ProgramHeaderFlags, LoadSegment, PF_R};

use super::{HeaderInfo, OutputSection, PAGE_SIZE, tls::TlsSegment};

/// A PT_LOAD's memory and file sizes, before collecting its bytes.
pub(crate) struct LoadSegmentLayout {
    pub(crate) flags: Elf64ProgramHeaderFlags,
    pub(crate) address: u64,
    /// File bytes, including any internal gaps filled with zeros.
    pub(crate) file_size: u64,
    /// Memory bytes, including any trailing NOBITS range.
    pub(crate) mem_size: u64,
    /// File offset and virtual address must match modulo this alignment.
    pub(crate) align: u64,
}

/// Give reports and output the same load ranges, file sizes, and zero-fill tails.
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
        // File offset zero already fixes the header load's page alignment.
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
        // Startup also copies padding a script leaves at the end of .tdata.
        segment.file_size = segment
            .file_size
            .max(tls.vaddr - segment.address + tls.file_size);
    }
    Ok(segments)
}

/// Join patched bytes into zero-filled load buffers.
///
/// A NOBITS gap before later data needs zeros in the file. A NOBITS tail
/// only needs a larger memory size.
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

/// Count loads for SIZEOF_HEADERS, including the load that maps the headers.
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

#[cfg(test)]
mod tests {
    //! Check file bytes for internal zero-fill gaps and memory-only tails.

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
