use anyhow::{Context, Result, ensure};
use typestate::{RawReg, bitregs};

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
    pub program_headers: Vec<ProgramHeader>,
    header_segment: Option<ProgramHeader>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadSegment {
    pub flags: Elf64ProgramHeaderFlags,
    pub vaddr: u64,
    pub paddr: u64,
    pub align: u64,
    pub data: Vec<u8>,
    pub mem_size: u64,
}

bitregs! {
    pub struct Elf64ProgramHeaderFlags: u32 {
        pub executable@[0:0],
        pub writable@[1:1],
        pub readable@[2:2],
        _reserved@[31:3],
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ElfLayout {
    file_size: u64,
    phoff: u64,
    phnum: u16,
    header_segment: Option<ProgramHeader>,
    segments: Vec<ProgramHeader>,
}

/// A program header describing an existing file range, without adding payload bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramHeader {
    pub segment_type: ElfProgramHeaderType,
    pub flags: Elf64ProgramHeaderFlags,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub align: u64,
}

impl ExecElf64Writer {
    pub fn new_x86_64_executable(entry: u64) -> Self {
        Self {
            endian: ElfEndian::Little,
            machine: ElfMachineType::EM_X86_64,
            entry,
            segments: Vec::new(),
            program_headers: vec![ProgramHeader {
                segment_type: ElfProgramHeaderType::PT_GNU_STACK,
                flags: Elf64ProgramHeaderFlags::from_bits(PF_R | PF_W),
                offset: 0,
                vaddr: 0,
                paddr: 0,
                file_size: 0,
                mem_size: 0,
                align: 16,
            }],
            header_segment: None,
        }
    }

    pub fn add_load_segment(&mut self, seg: LoadSegment) {
        self.segments.push(seg);
    }

    pub fn add_program_header(&mut self, header: ProgramHeader) {
        self.program_headers.push(header);
    }

    /// Map the ELF header and complete program header table in a read-only PT_LOAD.
    /// The caller must reserve this virtual address range before other load segments.
    pub fn map_headers(&mut self, vaddr: u64, align: u64) {
        self.header_segment = Some(ProgramHeader {
            segment_type: ElfProgramHeaderType::PT_LOAD,
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R),
            offset: 0,
            vaddr,
            paddr: vaddr,
            file_size: 0,
            mem_size: 0,
            align,
        });
    }

    fn layout(&self) -> Result<ElfLayout> {
        self.validate_writer()?;
        ensure!(
            !self.segments.is_empty(),
            "executable output requires at least one PT_LOAD segment"
        );

        let phnum: u16 = self
            .segments
            .len()
            .checked_add(self.program_headers.len())
            .and_then(|count| count.checked_add(usize::from(self.header_segment.is_some())))
            .context("too many program headers")?
            .try_into()
            .context("too many program headers")?;
        let phoff = ELF_HEADER_SIZE;
        let mut cursor = phoff
            .checked_add(u64::from(phnum) * PROGRAM_HEADER_SIZE)
            .context("program header table exceeds u64")?;
        let header_segment = self.header_segment.clone().map(|mut header| {
            header.file_size = cursor;
            header.mem_size = cursor;
            header
        });
        if let Some(header) = &header_segment {
            validate_program_header(header)?;
        }
        let mut layouts = Vec::with_capacity(self.segments.len());

        for segment in &self.segments {
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

            let header = ProgramHeader {
                segment_type: ElfProgramHeaderType::PT_LOAD,
                offset,
                file_size,
                mem_size: segment.mem_size,
                vaddr: segment.vaddr,
                paddr: segment.paddr,
                align: segment.align,
                flags: segment.flags,
            };
            validate_program_header(&header)?;
            layouts.push(header);
        }

        for header in &self.program_headers {
            validate_program_header(header)?;
            ensure!(
                header.file_size == 0
                    || header
                        .offset
                        .checked_add(header.file_size)
                        .is_some_and(|end| end <= cursor),
                "program header file range exceeds output file"
            );
        }

        Ok(ElfLayout {
            file_size: cursor,
            phoff,
            phnum,
            header_segment,
            segments: layouts,
        })
    }

    pub fn file_size(&self) -> Result<u64> {
        Ok(self.layout()?.file_size)
    }

    pub fn write_into(&self, out: &mut [u8]) -> Result<()> {
        self.validate_writer()?;
        let layout = self.layout()?;
        ensure!(
            usize::try_from(layout.file_size)
                .ok()
                .is_some_and(|size| out.len() >= size),
            "output buffer is too small"
        );
        ensure!(
            layout.phnum as usize
                == self.segments.len()
                    + self.program_headers.len()
                    + usize::from(layout.header_segment.is_some()),
            "layout/program header count does not match writer"
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

        for (idx, header) in layout
            .header_segment
            .iter()
            .chain(&layout.segments)
            .chain(&self.program_headers)
            .enumerate()
        {
            let phoff = layout
                .phoff
                .checked_add(u64::try_from(idx).unwrap() * PROGRAM_HEADER_SIZE)
                .context("program header offset exceeds u64")?;
            let phoff = usize::try_from(phoff).context("program header offset too large")?;

            write_u32(out, phoff, header.segment_type.raw(), self.endian)?;
            write_u32(out, phoff + 4, header.flags.to_raw(), self.endian)?;
            write_u64(out, phoff + 8, header.offset, self.endian)?;
            write_u64(out, phoff + 16, header.vaddr, self.endian)?;
            write_u64(out, phoff + 24, header.paddr, self.endian)?;
            write_u64(out, phoff + 32, header.file_size, self.endian)?;
            write_u64(out, phoff + 40, header.mem_size, self.endian)?;
            write_u64(out, phoff + 48, header.align, self.endian)?;
        }

        for (segment, seg_layout) in self.segments.iter().zip(&layout.segments) {
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
}

fn validate_program_header(header: &ProgramHeader) -> Result<()> {
    ensure!(
        header.file_size <= header.mem_size,
        "segment file size exceeds memory size"
    );
    ensure!(
        header.align == 0 || header.align.is_power_of_two(),
        "segment alignment must be 0, 1, or a power of two"
    );
    ensure!(
        header.flags.to_raw() & !(PF_R | PF_W | PF_X) == 0,
        "segment flags contain unsupported bits"
    );
    if header.segment_type == ElfProgramHeaderType::PT_LOAD && header.align != 0 {
        ensure!(
            header.offset % header.align == header.vaddr % header.align,
            "segment alignment relation is invalid"
        );
    }
    Ok(())
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
        Elf64, Elf64ProgramHeaderFlags, ElfFileType, ElfProgramHeaderType, PF_R, PF_W, PF_X,
        write::{ExecElf64Writer, LoadSegment, ProgramHeader},
    };

    #[test]
    fn write_into_preserves_offset_alignment_relation() {
        let mut writer = ExecElf64Writer::new_x86_64_executable(0x401123);
        writer.add_load_segment(LoadSegment {
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R | PF_X),
            vaddr: 0x401123,
            paddr: 0x401123,
            align: 0x1000,
            data: vec![0x90, 0xC3],
            mem_size: 2,
        });

        let file_size = writer.file_size().unwrap();
        let mut storage = vec![0u8; file_size as usize + 1];
        writer.write_into(&mut storage[1..]).unwrap();
        let elf = Elf64::new(&storage[1..]).unwrap();
        let segment = elf.program_headers().next().unwrap();

        assert_eq!(
            segment.offset() % segment.align(),
            segment.vaddr() % segment.align()
        );
        assert_eq!(file_size, storage.len() as u64 - 1);
    }

    #[test]
    fn write_into_supports_bss_tail_segments() {
        let mut writer = ExecElf64Writer::new_x86_64_executable(0x401000);
        writer.add_load_segment(LoadSegment {
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R | PF_W),
            vaddr: 0x402000,
            paddr: 0x402000,
            align: 0x1000,
            data: vec![1, 2, 3, 4],
            mem_size: 0x200,
        });

        let file_size = writer.file_size().unwrap();
        let mut storage = vec![0u8; file_size as usize];
        writer.write_into(&mut storage).unwrap();
        let elf = Elf64::new(&storage).unwrap();
        let segment = elf.program_headers().next().unwrap();

        assert_eq!(segment.file_size(), 4);
        assert_eq!(segment.mem_size(), 0x200);
        assert_eq!(file_size, segment.offset() + segment.file_size());
    }

    #[test]
    fn write_into_preserves_offset_alignment_relation_for_multiple_page_aligned_segments() {
        let mut writer = ExecElf64Writer::new_x86_64_executable(0x401000);
        writer.add_load_segment(LoadSegment {
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R | PF_X),
            vaddr: 0x401000,
            paddr: 0x401000,
            align: 0x1000,
            data: vec![0x90; 0x120],
            mem_size: 0x120,
        });
        writer.add_load_segment(LoadSegment {
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R),
            vaddr: 0x402000,
            paddr: 0x402000,
            align: 0x1000,
            data: b"page-aligned-rodata".to_vec(),
            mem_size: 0x100,
        });

        let file_size = writer.file_size().unwrap();
        let mut storage = vec![0u8; file_size as usize];
        writer.write_into(&mut storage).unwrap();
        let elf = Elf64::new(&storage).unwrap();
        let segments = elf
            .program_headers()
            .filter(|header| header.segment_type() == ElfProgramHeaderType::PT_LOAD)
            .collect::<Vec<_>>();

        assert_eq!(segments.len(), 2);
        for segment in &segments {
            assert_eq!(segment.align(), 0x1000);
            assert_eq!(
                segment.offset() % segment.align(),
                segment.vaddr() % segment.align()
            );
        }
        assert!(segments[1].offset() >= segments[0].offset() + segments[0].file_size());
    }

    #[test]
    fn write_into_round_trips_through_reader() {
        let mut writer = ExecElf64Writer::new_x86_64_executable(0x401000);
        writer.add_load_segment(LoadSegment {
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R | PF_X),
            vaddr: 0x401000,
            paddr: 0x401000,
            align: 0x1000,
            data: vec![0xC3],
            mem_size: 1,
        });
        writer.add_load_segment(LoadSegment {
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R | PF_W),
            vaddr: 0x402000,
            paddr: 0x402000,
            align: 0x1000,
            data: vec![0x11, 0x22, 0x33],
            mem_size: 0x100,
        });

        let file_size = writer.file_size().unwrap();
        let mut storage = vec![0u8; file_size as usize + 1];
        writer.write_into(&mut storage[1..]).unwrap();

        let elf = Elf64::new(&storage[1..]).unwrap();
        assert_eq!(elf.elf_type(), ElfFileType::ET_EXEC);
        assert_eq!(elf.entry(), 0x401000);
        assert_eq!(elf.program_header_count(), 3);

        let phdrs = elf.program_headers().collect::<Vec<_>>();
        assert_eq!(phdrs.len(), 3);
        assert_eq!(phdrs[0].flags(), PF_R | PF_X);
        assert_eq!(phdrs[0].data().unwrap(), &[0xC3]);
        assert_eq!(phdrs[1].flags(), PF_R | PF_W);
        assert_eq!(phdrs[1].file_size(), 3);
        assert_eq!(phdrs[1].mem_size(), 0x100);
        assert_eq!(phdrs[1].data().unwrap(), &[0x11, 0x22, 0x33]);
        assert_eq!(phdrs[2].segment_type(), ElfProgramHeaderType::PT_GNU_STACK);
        assert_eq!(phdrs[2].flags(), PF_R | PF_W);
        assert_eq!(phdrs[2].file_size(), 0);
        assert_eq!(phdrs[2].mem_size(), 0);
    }

    #[test]
    fn write_into_maps_headers_and_emits_additional_program_headers() {
        let mut writer = ExecElf64Writer::new_x86_64_executable(0x401000);
        writer.map_headers(0x400000, 0x1000);
        writer.add_load_segment(LoadSegment {
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R | PF_X),
            vaddr: 0x401000,
            paddr: 0x401000,
            align: 0x1000,
            data: vec![0x90, 0x90, 0x90, 0xC3],
            mem_size: 4,
        });
        writer.add_program_header(ProgramHeader {
            segment_type: ElfProgramHeaderType::PT_NOTE,
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R),
            offset: 0x1000,
            vaddr: 0x401000,
            paddr: 0x501000,
            file_size: 4,
            mem_size: 4,
            align: 4,
        });

        let mut storage = vec![0u8; writer.file_size().unwrap() as usize];
        writer.write_into(&mut storage).unwrap();
        let elf = Elf64::new(&storage).unwrap();
        let headers = elf.program_headers().collect::<Vec<_>>();
        let header_segment = &headers[0];

        assert_eq!(elf.program_header_count(), 4);
        assert_eq!(header_segment.segment_type(), ElfProgramHeaderType::PT_LOAD);
        assert_eq!(header_segment.flags(), PF_R);
        assert_eq!(header_segment.offset(), 0);
        assert_eq!(header_segment.vaddr(), 0x400000);
        assert_eq!(header_segment.paddr(), 0x400000);
        assert_eq!(header_segment.align(), 0x1000);
        assert_eq!(header_segment.file_size(), 64 + 56 * 4);
        assert_eq!(header_segment.mem_size(), header_segment.file_size());
        assert_eq!(header_segment.data().unwrap(), &storage[..64 + 56 * 4]);
        assert_eq!(headers[1].data().unwrap(), &[0x90, 0x90, 0x90, 0xC3]);

        let note = &headers[3];
        assert_eq!(note.segment_type(), ElfProgramHeaderType::PT_NOTE);
        assert_eq!(note.flags(), PF_R);
        assert_eq!(note.offset(), 0x1000);
        assert_eq!(note.vaddr(), 0x401000);
        assert_eq!(note.paddr(), 0x501000);
        assert_eq!(note.file_size(), 4);
        assert_eq!(note.mem_size(), 4);
        assert_eq!(note.align(), 4);
        assert_eq!(note.data().unwrap(), headers[1].data().unwrap());
    }

    #[test]
    fn map_headers_rejects_misaligned_virtual_address() {
        let mut writer = ExecElf64Writer::new_x86_64_executable(0x401000);
        writer.map_headers(0x400001, 0x1000);
        writer.add_load_segment(LoadSegment {
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R | PF_X),
            vaddr: 0x401000,
            paddr: 0x401000,
            align: 0x1000,
            data: vec![0xC3],
            mem_size: 1,
        });

        let error = writer.file_size().unwrap_err();
        assert!(error.to_string().contains("alignment relation is invalid"));
    }
}
