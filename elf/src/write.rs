use anyhow::{Context, Result, ensure};

use crate::{
    PF_R, PF_W, PF_X,
    abi::{ElfEndian, ElfFileType, ElfMachineType, ElfProgramHeaderType},
};

const ELF_HEADER_SIZE: u64 = 64;
const PROGRAM_HEADER_SIZE: u64 = 56;
const ELF_VERSION_CURRENT: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecElf64Writer {
    pub endian: ElfEndian,
    pub machine: ElfMachineType,
    pub entry: u64,
    pub segments: Vec<LoadSegment>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadSegment {
    pub flags: u32,
    pub vaddr: u64,
    pub paddr: u64,
    pub align: u64,
    pub data: Vec<u8>,
    pub mem_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElfLayout {
    pub file_size: u64,
    pub phoff: u64,
    pub phnum: u16,
    pub segments: Vec<SegmentLayout>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentLayout {
    pub offset: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub align: u64,
    pub flags: u32,
}

impl ExecElf64Writer {
    pub fn new_x86_64_executable(entry: u64) -> Self {
        Self {
            endian: ElfEndian::Little,
            machine: ElfMachineType::EM_X86_64,
            entry,
            segments: Vec::new(),
        }
    }

    pub fn add_load_segment(&mut self, seg: LoadSegment) {
        self.segments.push(seg);
    }

    pub fn layout(&self) -> Result<ElfLayout> {
        self.validate_writer()?;
        ensure!(
            !self.segments.is_empty(),
            "executable output requires at least one PT_LOAD segment"
        );

        let phnum: u16 = self
            .segments
            .len()
            .try_into()
            .context("too many program headers")?;
        let phoff = ELF_HEADER_SIZE;
        let mut cursor = phoff
            .checked_add(u64::from(phnum) * PROGRAM_HEADER_SIZE)
            .context("program header table exceeds u64")?;
        let mut layouts = Vec::with_capacity(self.segments.len());

        for segment in &self.segments {
            self.validate_segment(segment)?;

            let file_size: u64 = segment
                .data
                .len()
                .try_into()
                .context("segment data length does not fit in u64")?;
            let offset = if segment.align == 0 {
                cursor
            } else {
                next_congruent_offset(cursor, segment.align, segment.vaddr % segment.align)?
            };

            let end = offset
                .checked_add(file_size)
                .context("segment file range exceeds u64")?;
            cursor = cursor.max(end);

            layouts.push(SegmentLayout {
                offset,
                file_size,
                mem_size: segment.mem_size,
                vaddr: segment.vaddr,
                paddr: segment.paddr,
                align: segment.align,
                flags: segment.flags,
            });
        }

        Ok(ElfLayout {
            file_size: cursor,
            phoff,
            phnum,
            segments: layouts,
        })
    }

    pub fn file_size(&self) -> Result<u64> {
        Ok(self.layout()?.file_size)
    }

    pub fn write_into(&self, out: &mut [u8], layout: &ElfLayout) -> Result<()> {
        self.validate_writer()?;
        ensure!(
            usize::try_from(layout.file_size)
                .ok()
                .is_some_and(|size| out.len() >= size),
            "output buffer is too small"
        );
        ensure!(
            layout.phnum as usize == self.segments.len(),
            "layout/program header count does not match segment count"
        );
        ensure!(
            layout.segments.len() == self.segments.len(),
            "layout segment count does not match writer segment count"
        );

        let file_size = usize::try_from(layout.file_size).context("layout file size too large")?;
        out[..file_size].fill(0);

        out[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        out[4] = 2;
        out[5] = match self.endian {
            ElfEndian::Little => 1,
            ElfEndian::Big => 2,
        };
        out[6] = 1;

        write_u16(out, 16, ElfFileType::ET_EXEC.raw(), self.endian)?;
        write_u16(out, 18, self.machine.raw(), self.endian)?;
        write_u32(out, 20, ELF_VERSION_CURRENT, self.endian)?;
        write_u64(out, 24, self.entry, self.endian)?;
        write_u64(out, 32, layout.phoff, self.endian)?;
        write_u64(out, 40, 0, self.endian)?;
        write_u32(out, 48, 0, self.endian)?;
        write_u16(out, 52, ELF_HEADER_SIZE as u16, self.endian)?;
        write_u16(out, 54, PROGRAM_HEADER_SIZE as u16, self.endian)?;
        write_u16(out, 56, layout.phnum, self.endian)?;
        write_u16(out, 58, 0, self.endian)?;
        write_u16(out, 60, 0, self.endian)?;
        write_u16(out, 62, 0, self.endian)?;

        for (idx, (segment, seg_layout)) in self.segments.iter().zip(&layout.segments).enumerate() {
            self.validate_segment(segment)?;
            ensure!(
                seg_layout.file_size
                    == u64::try_from(segment.data.len()).context("segment data too large")?,
                "layout file size does not match segment data"
            );
            ensure!(
                seg_layout.mem_size >= seg_layout.file_size,
                "layout mem size is smaller than file size"
            );
            if seg_layout.align != 0 {
                ensure!(
                    seg_layout.offset % seg_layout.align == seg_layout.vaddr % seg_layout.align,
                    "segment alignment relation is invalid"
                );
            }

            let phoff = layout
                .phoff
                .checked_add(u64::try_from(idx).unwrap() * PROGRAM_HEADER_SIZE)
                .context("program header offset exceeds u64")?;
            let phoff = usize::try_from(phoff).context("program header offset too large")?;

            write_u32(out, phoff, ElfProgramHeaderType::PT_LOAD.raw(), self.endian)?;
            write_u32(out, phoff + 4, seg_layout.flags, self.endian)?;
            write_u64(out, phoff + 8, seg_layout.offset, self.endian)?;
            write_u64(out, phoff + 16, seg_layout.vaddr, self.endian)?;
            write_u64(out, phoff + 24, seg_layout.paddr, self.endian)?;
            write_u64(out, phoff + 32, seg_layout.file_size, self.endian)?;
            write_u64(out, phoff + 40, seg_layout.mem_size, self.endian)?;
            write_u64(out, phoff + 48, seg_layout.align, self.endian)?;

            let data_offset =
                usize::try_from(seg_layout.offset).context("segment offset too large")?;
            let data_end = data_offset
                .checked_add(segment.data.len())
                .context("segment data range exceeds usize")?;
            ensure!(data_end <= out.len(), "segment data exceeds output buffer");
            out[data_offset..data_end].copy_from_slice(&segment.data);
        }

        Ok(())
    }

    fn validate_writer(&self) -> Result<()> {
        ensure!(
            self.endian == ElfEndian::Little,
            "writer only supports little-endian ELF64 output"
        );
        ensure!(
            self.machine == ElfMachineType::EM_X86_64,
            "writer only supports x86_64 output"
        );
        Ok(())
    }

    fn validate_segment(&self, segment: &LoadSegment) -> Result<()> {
        let file_size: u64 = segment
            .data
            .len()
            .try_into()
            .context("segment data length does not fit in u64")?;
        ensure!(
            file_size <= segment.mem_size,
            "segment file size exceeds memory size"
        );
        ensure!(
            segment.align == 0 || segment.align == 1 || segment.align.is_power_of_two(),
            "segment alignment must be 0, 1, or a power of two"
        );
        ensure!(
            segment.flags & !(PF_R | PF_W | PF_X) == 0,
            "segment flags contain unsupported bits"
        );
        Ok(())
    }
}

fn next_congruent_offset(cursor: u64, align: u64, remainder: u64) -> Result<u64> {
    let cursor_mod = cursor % align;
    if cursor_mod == remainder {
        return Ok(cursor);
    }

    let delta = if cursor_mod < remainder {
        remainder - cursor_mod
    } else {
        align - (cursor_mod - remainder)
    };

    cursor
        .checked_add(delta)
        .context("segment offset exceeds u64")
}

fn write_u16(out: &mut [u8], offset: usize, value: u16, endian: ElfEndian) -> Result<()> {
    write_bytes(
        out,
        offset,
        &match endian {
            ElfEndian::Big => value.to_be_bytes(),
            ElfEndian::Little => value.to_le_bytes(),
        },
    )
}

fn write_u32(out: &mut [u8], offset: usize, value: u32, endian: ElfEndian) -> Result<()> {
    write_bytes(
        out,
        offset,
        &match endian {
            ElfEndian::Big => value.to_be_bytes(),
            ElfEndian::Little => value.to_le_bytes(),
        },
    )
}

fn write_u64(out: &mut [u8], offset: usize, value: u64, endian: ElfEndian) -> Result<()> {
    write_bytes(
        out,
        offset,
        &match endian {
            ElfEndian::Big => value.to_be_bytes(),
            ElfEndian::Little => value.to_le_bytes(),
        },
    )
}

fn write_bytes(out: &mut [u8], offset: usize, bytes: &[u8]) -> Result<()> {
    let end = offset
        .checked_add(bytes.len())
        .context("write range exceeds usize")?;
    ensure!(end <= out.len(), "write out of bounds");
    out[offset..end].copy_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        Elf64, ElfFileType, PF_R, PF_W, PF_X,
        write::{ExecElf64Writer, LoadSegment},
    };

    #[test]
    fn layout_preserves_offset_alignment_relation() {
        let mut writer = ExecElf64Writer::new_x86_64_executable(0x401123);
        writer.add_load_segment(LoadSegment {
            flags: PF_R | PF_X,
            vaddr: 0x401123,
            paddr: 0x401123,
            align: 0x1000,
            data: vec![0x90, 0xC3],
            mem_size: 2,
        });

        let layout = writer.layout().unwrap();
        let segment = &layout.segments[0];

        assert_eq!(
            segment.offset % segment.align,
            segment.vaddr % segment.align
        );
        assert_eq!(writer.file_size().unwrap(), layout.file_size);
    }

    #[test]
    fn layout_supports_bss_tail_segments() {
        let mut writer = ExecElf64Writer::new_x86_64_executable(0x401000);
        writer.add_load_segment(LoadSegment {
            flags: PF_R | PF_W,
            vaddr: 0x402000,
            paddr: 0x402000,
            align: 0x1000,
            data: vec![1, 2, 3, 4],
            mem_size: 0x200,
        });

        let layout = writer.layout().unwrap();
        let segment = &layout.segments[0];

        assert_eq!(segment.file_size, 4);
        assert_eq!(segment.mem_size, 0x200);
        assert_eq!(layout.file_size, segment.offset + segment.file_size);
    }

    #[test]
    fn write_into_round_trips_through_reader() {
        let mut writer = ExecElf64Writer::new_x86_64_executable(0x401000);
        writer.add_load_segment(LoadSegment {
            flags: PF_R | PF_X,
            vaddr: 0x401000,
            paddr: 0x401000,
            align: 0x1000,
            data: vec![0xC3],
            mem_size: 1,
        });
        writer.add_load_segment(LoadSegment {
            flags: PF_R | PF_W,
            vaddr: 0x402000,
            paddr: 0x402000,
            align: 0x1000,
            data: vec![0x11, 0x22, 0x33],
            mem_size: 0x100,
        });

        let layout = writer.layout().unwrap();
        let mut storage = vec![0u8; layout.file_size as usize + 1];
        writer.write_into(&mut storage[1..], &layout).unwrap();

        let elf = Elf64::new(&storage[1..]).unwrap();
        assert_eq!(elf.elf_type(), ElfFileType::ET_EXEC);
        assert_eq!(elf.entry(), 0x401000);
        assert_eq!(elf.program_header_count(), 2);

        let phdrs = elf.program_headers().collect::<Vec<_>>();
        assert_eq!(phdrs.len(), 2);
        assert_eq!(phdrs[0].flags(), PF_R | PF_X);
        assert_eq!(phdrs[0].data().unwrap(), &[0xC3]);
        assert_eq!(phdrs[1].flags(), PF_R | PF_W);
        assert_eq!(phdrs[1].file_size(), 3);
        assert_eq!(phdrs[1].mem_size(), 0x100);
        assert_eq!(phdrs[1].data().unwrap(), &[0x11, 0x22, 0x33]);
    }
}
