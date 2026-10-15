//! Compute file offsets and write a little-endian x86-64 ELF executable.
//!
//! [`ExecElf64Writer`] takes [`LoadSegment`], [`ProgramHeader`], and [`Section`]
//! records. It checks them and computes file offsets before
//! [`ExecElf64Writer::write_into`] fills a buffer. [`SymbolTableBuilder`] adds
//! the null symbol and puts local symbols before globals, as ELF requires.
//!
//! Section headers for loaded data point into load segments; other tables go
//! after those bytes. Like GNU ld, each PT_LOAD file offset must match its
//! virtual address modulo alignment. The kernel uses that rule to map pages.
//!
//! References: ELF gABI "ELF Header", "Sections", "String Table", "Symbol Table",
//! and "Program Header"; AMD64 psABI §5.1.

use anyhow::{Context, Result, ensure};
use typestate::{RawReg, bitregs};

use crate::{
    PF_R, PF_W, PF_X,
    abi::{
        Elf64SectionFlags, Elf64SectionType, Elf64SymbolBinding, Elf64SymbolInfo, Elf64SymbolType,
        ElfEndian, ElfFileType, ElfMachineType, ElfProgramHeaderType, SHN_LORESERVE, SHN_UNDEF,
    },
};

pub const ELF_HEADER_SIZE: u64 = 64;
pub const PROGRAM_HEADER_SIZE: u64 = 56;
pub const SECTION_HEADER_SIZE: u64 = 64;
pub const SYMBOL_ENTRY_SIZE: u64 = 24;
const ELF_VERSION_CURRENT: u32 = 1;

/// Set the image's sections and segments, then compute offsets before writing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecElf64Writer {
    /// Only little-endian output passes validation.
    pub endian: ElfEndian,
    /// Only x86-64 output passes validation.
    pub machine: ElfMachineType,
    pub entry: u64,
    /// Ordinary loads after the optional header load.
    pub segments: Vec<LoadSegment>,
    /// Headers such as TLS and GNU_STACK; add them before asking for file offsets.
    pub program_headers: Vec<ProgramHeader>,
    /// The first load's byte prefix holds the ELF and program headers.
    pub header_segment: Option<LoadSegment>,
    /// Keep ELF index order, without section zero or the final .shstrtab;
    /// the writer adds both. An empty list omits the section table.
    pub sections: Vec<Section>,
}

/// Allocated data already lives in a load. Other data follows the load bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub section_type: Elf64SectionType,
    pub flags: Elf64SectionFlags,
    pub address: u64,
    pub size: u64,
    /// sh_link: a related table index, such as .strtab for .symtab.
    pub link: u32,
    /// sh_info: type-specific data, such as the first non-local symbol index.
    pub info: u32,
    pub align: u64,
    /// Bytes per fixed-size record, or zero for unstructured bytes.
    pub entry_size: u64,
    /// Supply bytes only for non-allocated sections; allocated bytes come from loads.
    pub data: Option<Vec<u8>>,
}

/// Set the final st_value and ELF section index before adding a symbol.
pub struct Elf64SymbolEntry<'a> {
    pub name: &'a str,
    pub binding: Elf64SymbolBinding,
    pub ty: Elf64SymbolType,
    pub other: u8,
    /// Final output index, or a special value such as SHN_ABS.
    pub section_index: u16,
    /// Use a virtual address, absolute value, or TLS template offset as the type requires.
    pub value: u64,
    pub size: u64,
}

impl Elf64SymbolEntry<'_> {
    fn encode_into(&self, bytes: &mut Vec<u8>, name_offset: u32) {
        let info = Elf64SymbolInfo::new()
            .set(Elf64SymbolInfo::st_bind, self.binding as u8)
            .set(Elf64SymbolInfo::st_type, self.ty as u8);
        bytes.extend_from_slice(&name_offset.to_le_bytes());
        bytes.push(info.to_raw());
        bytes.push(self.other);
        bytes.extend_from_slice(&self.section_index.to_le_bytes());
        bytes.extend_from_slice(&self.value.to_le_bytes());
        bytes.extend_from_slice(&self.size.to_le_bytes());
    }
}

/// Build little-endian .symtab and .strtab, adding null entries and sorting locals first.
#[derive(Default)]
pub struct SymbolTableBuilder<'a> {
    symbols: Vec<Elf64SymbolEntry<'a>>,
}

impl<'a> SymbolTableBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, symbol: Elf64SymbolEntry<'a>) {
        self.symbols.push(symbol);
    }

    /// Supply the final .strtab section index so .symtab can link to it.
    ///
    /// ELF requires the null symbol first and all locals before globals. Stable
    /// sorting keeps the caller's order within those two groups.
    pub fn build(mut self, strtab_index: u32) -> Result<[Section; 2]> {
        ensure!(
            strtab_index != u32::from(SHN_UNDEF),
            "symbol string table requires a section index"
        );
        // ELF puts the null symbol first and uses sh_info to mark the first
        // non-local symbol. Keep the caller's order within each group.
        self.symbols
            .sort_by_key(|symbol| symbol.binding != Elf64SymbolBinding::STB_LOCAL);
        let first_global = 1 + self
            .symbols
            .iter()
            .take_while(|symbol| symbol.binding == Elf64SymbolBinding::STB_LOCAL)
            .count();
        let mut symtab = vec![0; SYMBOL_ENTRY_SIZE as usize];
        let mut strtab = vec![0];
        for symbol in self.symbols {
            ensure!(!symbol.name.contains('\0'), "symbol name contains NUL");
            let name_offset =
                u32::try_from(strtab.len()).context("symbol string table too large")?;
            strtab.extend_from_slice(symbol.name.as_bytes());
            strtab.push(0);
            symbol.encode_into(&mut symtab, name_offset);
        }
        Ok([
            Section {
                name: ".symtab".to_string(),
                section_type: Elf64SectionType::SHT_SYMTAB,
                flags: Elf64SectionFlags::new(),
                address: 0,
                size: symtab.len() as u64,
                link: strtab_index,
                info: u32::try_from(first_global).context("too many local symbols")?,
                align: 8,
                entry_size: SYMBOL_ENTRY_SIZE,
                data: Some(symtab),
            },
            Section {
                name: ".strtab".to_string(),
                section_type: Elf64SectionType::SHT_STRTAB,
                flags: Elf64SectionFlags::new(),
                address: 0,
                size: strtab.len() as u64,
                link: u32::from(SHN_UNDEF),
                info: 0,
                align: 1,
                entry_size: 0,
                data: Some(strtab),
            },
        ])
    }
}

/// Describe an extra header such as PT_TLS that refers to an existing load's bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramHeader {
    pub segment_type: ElfProgramHeaderType,
    pub flags: Elf64ProgramHeaderFlags,
    /// Set the file offset after all headers that affect load offsets are present.
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    /// Zero for headers without file bytes, such as GNU_STACK.
    pub file_size: u64,
    /// Can exceed file_size for a TLS zero-fill tail.
    pub mem_size: u64,
    pub align: u64,
}

/// Map data.len() file bytes and zero the rest up to mem_size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadSegment {
    pub flags: Elf64ProgramHeaderFlags,
    pub vaddr: u64,
    pub paddr: u64,
    /// File offset and virtual address must match modulo this alignment.
    pub align: u64,
    /// Include explicit zeros for gaps before later initialized bytes.
    pub data: Vec<u8>,
    /// Memory size, at least as large as data.len().
    pub mem_size: u64,
}

bitregs! {
    /// The load's execute, write, and read permissions apply to whole pages.
    pub struct Elf64ProgramHeaderFlags: u32 {
        pub executable@[0:0],
        pub writable@[1:1],
        pub readable@[2:2],
        reserved@[31:3] [ignore],
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ElfLayout {
    file_size: u64,
    phoff: u64,
    phnum: u16,
    header_segment: Option<SegmentLayout>,
    segments: Vec<SegmentLayout>,
    sections: Vec<SectionLayout>,
    shoff: u64,
    shstrtab: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SectionLayout {
    name: u32,
    offset: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SegmentLayout {
    offset: u64,
    file_size: u64,
    mem_size: u64,
    vaddr: u64,
    paddr: u64,
    align: u64,
    flags: Elf64ProgramHeaderFlags,
}

impl ExecElf64Writer {
    /// Start an empty little-endian x86-64 ET_EXEC image at the given entry address.
    pub fn new_x86_64_executable(entry: u64) -> Self {
        Self {
            endian: ElfEndian::Little,
            machine: ElfMachineType::EM_X86_64,
            entry,
            segments: Vec::new(),
            program_headers: Vec::new(),
            header_segment: None,
            sections: Vec::new(),
        }
    }

    /// Add a load whose file offset the writer will choose from its address and alignment.
    pub fn add_load_segment(&mut self, seg: LoadSegment) {
        self.segments.push(seg);
    }

    /// Add before asking for offsets: each extra header can move load bytes in the file.
    pub fn add_program_header(&mut self, header: ProgramHeader) {
        self.program_headers.push(header);
    }

    /// Map the ELF headers in a read-only load at file offset zero.
    ///
    /// Set header_segment directly if this load also needs bytes after the headers.
    pub fn map_headers(&mut self, vaddr: u64, align: u64) {
        self.header_segment = Some(LoadSegment {
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R),
            vaddr,
            paddr: vaddr,
            align,
            data: Vec::new(),
            mem_size: 0,
        });
    }

    fn layout(&self) -> Result<ElfLayout> {
        self.validate_writer()?;
        ensure!(
            self.header_segment.is_some() || !self.segments.is_empty(),
            "executable output requires at least one PT_LOAD segment"
        );

        let phnum: u16 = (usize::from(self.header_segment.is_some())
            + self.segments.len()
            + self.program_headers.len())
        .try_into()
        .context("too many program headers")?;
        let phoff = ELF_HEADER_SIZE;
        let mut cursor = phoff
            .checked_add(u64::from(phnum) * PROGRAM_HEADER_SIZE)
            .context("program header table exceeds u64")?;
        let header_segment = if let Some(header) = &self.header_segment {
            self.validate_segment(header)?;
            let file_size = cursor.max(header.data.len() as u64);
            let layout = SegmentLayout {
                offset: 0,
                file_size,
                mem_size: file_size.max(header.mem_size),
                vaddr: header.vaddr,
                paddr: header.paddr,
                align: header.align,
                flags: header.flags,
            };
            validate_layout(&layout)?;
            cursor = file_size;
            Some(layout)
        } else {
            None
        };
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

        for header in &self.program_headers {
            self.validate_program_header(header, cursor)?;
        }

        let mut layout = ElfLayout {
            file_size: cursor,
            phoff,
            phnum,
            header_segment,
            segments: layouts,
            sections: Vec::new(),
            shoff: 0,
            shstrtab: Vec::new(),
        };
        self.layout_sections(&mut layout)?;
        Ok(layout)
    }

    fn layout_sections(&self, layout: &mut ElfLayout) -> Result<()> {
        if self.sections.is_empty() {
            return Ok(());
        }
        // This writer does not write extended indices (SHN_XINDEX), so keep
        // section counts below the reserved range.
        ensure!(
            self.sections.len() + 2 < usize::from(SHN_LORESERVE),
            "too many section headers"
        );
        layout.shstrtab.push(0);
        let mut cursor = layout.file_size;
        for section in &self.sections {
            self.validate_section(section)?;
            let name = u32::try_from(layout.shstrtab.len()).context("section names too large")?;
            layout.shstrtab.extend_from_slice(section.name.as_bytes());
            layout.shstrtab.push(0);
            let offset = if section.flags.get(Elf64SectionFlags::SHF_ALLOC) != 0 {
                let segment = layout
                    .header_segment
                    .iter()
                    .chain(&layout.segments)
                    .find(|segment| {
                        section
                            .address
                            .checked_sub(segment.vaddr)
                            .is_some_and(|offset| {
                                offset.checked_add(section.size).is_some_and(|end| {
                                    end <= segment.mem_size
                                        && (section.section_type == Elf64SectionType::SHT_NOBITS
                                            || end <= segment.file_size)
                                })
                            })
                    })
                    .with_context(|| {
                        format!("allocated section {} is outside its PT_LOAD", section.name)
                    })?;
                segment
                    .offset
                    .checked_add(section.address - segment.vaddr)
                    .context("section offset exceeds u64")?
            } else {
                cursor = cursor
                    .checked_next_multiple_of(section.align.max(1))
                    .context("section alignment exceeds u64")?;
                let offset = cursor;
                if section.section_type != Elf64SectionType::SHT_NOBITS {
                    cursor = cursor
                        .checked_add(section.size)
                        .context("section data exceeds u64")?;
                }
                offset
            };
            layout.sections.push(SectionLayout { name, offset });
        }
        let name = u32::try_from(layout.shstrtab.len()).context("section names too large")?;
        layout.shstrtab.extend_from_slice(b".shstrtab\0");
        layout.sections.push(SectionLayout {
            name,
            offset: cursor,
        });
        cursor = cursor
            .checked_add(layout.shstrtab.len() as u64)
            .context("section names exceed u64")?;
        layout.shoff = cursor
            .checked_next_multiple_of(8)
            .context("section table alignment exceeds u64")?;
        layout.file_size = layout
            .shoff
            .checked_add((layout.sections.len() as u64 + 1) * SECTION_HEADER_SIZE)
            .context("section table exceeds u64")?;
        Ok(())
    }

    /// Check the image and compute the size needed for loads, tables, and headers.
    pub fn file_size(&self) -> Result<u64> {
        Ok(self.layout()?.file_size)
    }

    /// Find the file offset for an address in a load, after adding all headers.
    ///
    /// A zero-fill tail can map to a conceptual offset past EOF; no file bytes
    /// exist there.
    pub fn file_offset(&self, vaddr: u64) -> Result<u64> {
        let layout = self.layout()?;
        let segment = layout
            .header_segment
            .iter()
            .chain(&layout.segments)
            .find(|segment| {
                vaddr
                    .checked_sub(segment.vaddr)
                    .is_some_and(|offset| offset < segment.mem_size)
            })
            .context("virtual address is outside the PT_LOAD segments")?;
        segment
            .offset
            .checked_add(vaddr - segment.vaddr)
            .context("file offset exceeds u64")
    }

    /// Check the image and write it into a buffer large enough for file_size().
    ///
    /// Zero the used prefix before filling it so alignment gaps and reserved fields
    /// do not keep bytes from the caller's buffer.
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
                == usize::from(layout.header_segment.is_some())
                    + self.segments.len()
                    + self.program_headers.len(),
            "layout/program header count does not match writer"
        );
        ensure!(
            layout.segments.len() == self.segments.len(),
            "layout segment count does not match writer segment count"
        );

        let file_size = usize::try_from(layout.file_size).context("layout file size too large")?;
        out[..file_size].fill(0);
        // The first load leaves room for headers. Copy its bytes before
        // writing headers into that prefix, or the copy would erase them.
        if let Some(header) = &self.header_segment {
            out[..header.data.len()].copy_from_slice(&header.data);
        }

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
        write_u64(out, 40, layout.shoff, self.endian)?;
        write_u32(out, 48, 0, self.endian)?;
        write_u16(out, 52, ELF_HEADER_SIZE as u16, self.endian)?;
        write_u16(out, 54, PROGRAM_HEADER_SIZE as u16, self.endian)?;
        write_u16(out, 56, layout.phnum, self.endian)?;
        let shnum = if layout.sections.is_empty() {
            0
        } else {
            layout.sections.len() as u16 + 1
        };
        write_u16(
            out,
            58,
            if shnum == 0 {
                0
            } else {
                SECTION_HEADER_SIZE as u16
            },
            self.endian,
        )?;
        write_u16(out, 60, shnum, self.endian)?;
        write_u16(out, 62, shnum.saturating_sub(1), self.endian)?;

        let mut phdr_idx = 0;
        if let Some(header_segment) = &layout.header_segment {
            self.write_program_header(
                out,
                &layout,
                phdr_idx,
                ElfProgramHeaderType::PT_LOAD,
                header_segment,
            )?;
            phdr_idx += 1;
        }

        for (segment, seg_layout) in self.segments.iter().zip(&layout.segments) {
            self.validate_segment(segment)?;
            ensure!(
                seg_layout.file_size
                    == u64::try_from(segment.data.len()).context("segment data too large")?,
                "layout file size does not match segment data"
            );
            validate_layout(seg_layout)?;

            self.write_program_header(
                out,
                &layout,
                phdr_idx,
                ElfProgramHeaderType::PT_LOAD,
                seg_layout,
            )?;
            phdr_idx += 1;

            let data_offset =
                usize::try_from(seg_layout.offset).context("segment offset too large")?;
            let data_end = data_offset
                .checked_add(segment.data.len())
                .context("segment data range exceeds usize")?;
            ensure!(data_end <= out.len(), "segment data exceeds output buffer");
            out[data_offset..data_end].copy_from_slice(&segment.data);
        }

        for header in &self.program_headers {
            self.validate_program_header(header, layout.file_size)?;
            let seg_layout = SegmentLayout {
                offset: header.offset,
                file_size: header.file_size,
                mem_size: header.mem_size,
                vaddr: header.vaddr,
                paddr: header.paddr,
                align: header.align,
                flags: header.flags,
            };
            self.write_program_header(out, &layout, phdr_idx, header.segment_type, &seg_layout)?;
            phdr_idx += 1;
        }

        self.write_sections(out, &layout)?;
        Ok(())
    }

    fn write_sections(&self, out: &mut [u8], layout: &ElfLayout) -> Result<()> {
        if self.sections.is_empty() {
            return Ok(());
        }
        let names = Section {
            name: ".shstrtab".to_string(),
            section_type: Elf64SectionType::SHT_STRTAB,
            flags: Elf64SectionFlags::new(),
            address: 0,
            size: layout.shstrtab.len() as u64,
            link: u32::from(SHN_UNDEF),
            info: 0,
            align: 1,
            entry_size: 0,
            data: None,
        };
        for (index, (section, placed)) in self
            .sections
            .iter()
            .chain([&names])
            .zip(&layout.sections)
            .enumerate()
        {
            let header = usize::try_from(layout.shoff + (index as u64 + 1) * SECTION_HEADER_SIZE)
                .context("section header offset too large")?;
            write_u32(out, header, placed.name, self.endian)?;
            write_u32(out, header + 4, section.section_type.raw(), self.endian)?;
            write_u64(out, header + 8, section.flags.to_raw(), self.endian)?;
            write_u64(out, header + 16, section.address, self.endian)?;
            write_u64(out, header + 24, placed.offset, self.endian)?;
            write_u64(out, header + 32, section.size, self.endian)?;
            write_u32(out, header + 40, section.link, self.endian)?;
            write_u32(out, header + 44, section.info, self.endian)?;
            write_u64(out, header + 48, section.align, self.endian)?;
            write_u64(out, header + 56, section.entry_size, self.endian)?;
            let data = if index == self.sections.len() {
                Some(layout.shstrtab.as_slice())
            } else {
                section.data.as_deref()
            };
            if let Some(data) = data {
                write_bytes(
                    out,
                    usize::try_from(placed.offset).context("section offset too large")?,
                    data,
                )?;
            }
        }
        Ok(())
    }

    fn validate_section(&self, section: &Section) -> Result<()> {
        ensure!(!section.name.contains('\0'), "section name contains NUL");
        ensure!(
            section.align == 0 || section.align.is_power_of_two(),
            "section alignment must be 0 or a power of two"
        );
        ensure!(
            section.link < self.sections.len() as u32 + 2,
            "section link index is out of range"
        );
        if section.flags.get(Elf64SectionFlags::SHF_ALLOC) != 0 {
            ensure!(
                section.data.is_none(),
                "allocated section data must come from PT_LOAD"
            );
            ensure!(
                section.address.is_multiple_of(section.align.max(1)),
                "allocated section address is misaligned"
            );
        } else if section.section_type == Elf64SectionType::SHT_NOBITS {
            ensure!(
                section.data.is_none(),
                "NOBITS section cannot have file data"
            );
        } else {
            ensure!(
                section
                    .data
                    .as_ref()
                    .is_some_and(|data| data.len() as u64 == section.size),
                "non-allocated section size does not match data"
            );
        }
        Ok(())
    }

    fn write_program_header(
        &self,
        out: &mut [u8],
        layout: &ElfLayout,
        idx: u16,
        segment_type: ElfProgramHeaderType,
        seg_layout: &SegmentLayout,
    ) -> Result<()> {
        let phoff = layout
            .phoff
            .checked_add(u64::from(idx) * PROGRAM_HEADER_SIZE)
            .context("program header offset exceeds u64")?;
        let phoff = usize::try_from(phoff).context("program header offset too large")?;

        write_u32(out, phoff, segment_type.raw(), self.endian)?;
        write_u32(out, phoff + 4, seg_layout.flags.to_raw(), self.endian)?;
        write_u64(out, phoff + 8, seg_layout.offset, self.endian)?;
        write_u64(out, phoff + 16, seg_layout.vaddr, self.endian)?;
        write_u64(out, phoff + 24, seg_layout.paddr, self.endian)?;
        write_u64(out, phoff + 32, seg_layout.file_size, self.endian)?;
        write_u64(out, phoff + 40, seg_layout.mem_size, self.endian)?;
        write_u64(out, phoff + 48, seg_layout.align, self.endian)?;
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
            segment.flags.to_raw() & !(PF_R | PF_W | PF_X) == 0,
            "segment flags contain unsupported bits"
        );
        Ok(())
    }

    fn validate_program_header(&self, header: &ProgramHeader, file_size: u64) -> Result<()> {
        ensure!(
            header.segment_type != ElfProgramHeaderType::PT_LOAD,
            "PT_LOAD must be added with add_load_segment"
        );
        ensure!(
            header.file_size <= header.mem_size,
            "program header file size exceeds memory size"
        );
        ensure!(
            header.align == 0 || header.align == 1 || header.align.is_power_of_two(),
            "program header alignment must be 0, 1, or a power of two"
        );
        ensure!(
            header.flags.to_raw() & !(PF_R | PF_W | PF_X) == 0,
            "program header flags contain unsupported bits"
        );
        ensure!(
            header.file_size == 0
                || header
                    .offset
                    .checked_add(header.file_size)
                    .is_some_and(|end| end <= file_size),
            "program header file range exceeds output file"
        );
        Ok(())
    }
}

fn validate_layout(seg_layout: &SegmentLayout) -> Result<()> {
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
    //! Check ELF tables, zero-fill tails, and file-offset/address alignment.

    use crate::{
        Elf64, Elf64ProgramHeaderFlags, Elf64SectionFlags, Elf64SectionType, ElfFileType,
        ElfProgramHeaderType, PF_R, PF_W, PF_X, SHN_UNDEF,
        write::{ExecElf64Writer, LoadSegment, ProgramHeader, Section},
    };

    #[test]
    fn symbol_table_builder_orders_locals_and_round_trips_metadata() {
        use super::{Elf64SymbolEntry, SYMBOL_ENTRY_SIZE, SymbolTableBuilder};
        use crate::{
            Elf64SymbolBinding, Elf64SymbolInfo, Elf64SymbolSectionIdx, Elf64SymbolType, SHN_ABS,
            SHN_UNDEF,
        };

        let mut builder = SymbolTableBuilder::new();
        for (name, binding, value, size) in [
            ("global", Elf64SymbolBinding::STB_GLOBAL, 0x1234, 16),
            ("local_first", Elf64SymbolBinding::STB_LOCAL, 0x2345, 8),
            ("weak", Elf64SymbolBinding::STB_WEAK, 0, 0),
            ("local_second", Elf64SymbolBinding::STB_LOCAL, 0x3456, 4),
        ] {
            builder.add(Elf64SymbolEntry {
                name,
                binding,
                ty: Elf64SymbolType::STT_OBJECT,
                other: 0,
                section_index: if binding == Elf64SymbolBinding::STB_WEAK {
                    SHN_UNDEF
                } else {
                    SHN_ABS
                },
                value,
                size,
            });
        }
        let mut writer = ExecElf64Writer::new_x86_64_executable(0x401000);
        writer.add_load_segment(LoadSegment {
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R),
            vaddr: 0x401000,
            paddr: 0x401000,
            align: 0x1000,
            data: vec![0],
            mem_size: 1,
        });
        // This image has no allocated sections, so .strtab follows null and .symtab.
        writer.sections.extend(builder.build(2).unwrap());
        let mut bytes = vec![0; writer.file_size().unwrap() as usize];
        writer.write_into(&mut bytes).unwrap();
        let elf = Elf64::new(&bytes).unwrap();
        let table = elf
            .sections()
            .find(|section| section.name().unwrap() == ".symtab")
            .unwrap();
        let symbols = table.symbols().unwrap().collect::<Vec<_>>();
        assert_eq!(table.info(), 3);
        assert_eq!(table.entry_size(), SYMBOL_ENTRY_SIZE);
        assert_eq!(
            symbols
                .iter()
                .map(|symbol| symbol.name().unwrap())
                .collect::<Vec<_>>(),
            ["", "local_first", "local_second", "global", "weak"]
        );
        assert_eq!(symbols[0].section_idx(), Elf64SymbolSectionIdx::Undefined);
        assert_eq!(symbols[3].value(), 0x1234);
        assert_eq!(symbols[3].size(), 16);
        assert_eq!(
            symbols[3].section_idx(),
            Elf64SymbolSectionIdx::AbsoluteSymbols
        );
        assert_eq!(
            symbols[4].info().get_enum(Elf64SymbolInfo::st_bind),
            Some(Elf64SymbolBinding::STB_WEAK)
        );
        assert_eq!(symbols[4].section_idx(), Elf64SymbolSectionIdx::Undefined);
    }

    #[test]
    fn section_table_reuses_load_data_and_appends_non_allocated_bytes() {
        let mut writer = ExecElf64Writer::new_x86_64_executable(0x401000);
        writer.add_load_segment(LoadSegment {
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R | PF_W),
            vaddr: 0x401000,
            paddr: 0x401000,
            align: 0x1000,
            data: vec![1, 2, 3],
            mem_size: 0x100,
        });
        let data_end = writer.file_size().unwrap();
        writer.sections = vec![
            Section {
                name: ".data".to_string(),
                section_type: Elf64SectionType::SHT_PROGBITS,
                flags: Elf64SectionFlags::new()
                    .set(Elf64SectionFlags::SHF_ALLOC, 1)
                    .set(Elf64SectionFlags::SHF_WRITE, 1),
                address: 0x401000,
                size: 3,
                link: u32::from(SHN_UNDEF),
                info: 0,
                align: 1,
                entry_size: 0,
                data: None,
            },
            Section {
                name: ".bss".to_string(),
                section_type: Elf64SectionType::SHT_NOBITS,
                flags: Elf64SectionFlags::new()
                    .set(Elf64SectionFlags::SHF_ALLOC, 1)
                    .set(Elf64SectionFlags::SHF_WRITE, 1),
                address: 0x401010,
                size: 0xf0,
                link: u32::from(SHN_UNDEF),
                info: 0,
                align: 16,
                entry_size: 0,
                data: None,
            },
            Section {
                name: ".strtab".to_string(),
                section_type: Elf64SectionType::SHT_STRTAB,
                flags: Elf64SectionFlags::new(),
                address: 0,
                size: 5,
                link: u32::from(SHN_UNDEF),
                info: 0,
                align: 8,
                entry_size: 0,
                data: Some(b"\0foo\0".to_vec()),
            },
        ];
        let mut bytes = vec![0; writer.file_size().unwrap() as usize + 1];
        writer.write_into(&mut bytes[1..]).unwrap();
        let elf = Elf64::new(&bytes[1..]).unwrap();
        let load = elf.program_headers().next().unwrap();
        let sections = elf.sections().collect::<Vec<_>>();
        assert_eq!(sections.len(), 5);
        assert_eq!(sections[0].section_type(), Elf64SectionType::SHT_NULL);
        assert_eq!(sections[1].data().unwrap(), &[1, 2, 3]);
        assert_eq!(sections[1].offset(), load.offset());
        assert_eq!(sections[2].offset(), load.offset() + 16);
        assert_eq!(sections[2].data(), None);
        assert_eq!(sections[3].offset(), data_end.next_multiple_of(8));
        assert_eq!(sections[3].data().unwrap(), b"\0foo\0");
        assert_eq!(sections[4].name().unwrap(), ".shstrtab");
        assert_eq!(load.file_size(), 3);
        assert_eq!(load.mem_size(), 0x100);
        // A file-backed section cannot live in a zero-fill tail; bad sizes
        // must also fail before the writer touches the buffer.
        writer.sections[1].section_type = Elf64SectionType::SHT_PROGBITS;
        assert!(
            writer
                .file_size()
                .unwrap_err()
                .to_string()
                .contains("outside its PT_LOAD")
        );
        writer.sections[1].section_type = Elf64SectionType::SHT_NOBITS;
        writer.sections[2].size = 6;
        assert!(
            writer
                .file_size()
                .unwrap_err()
                .to_string()
                .contains("size does not match data")
        );
    }

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
        let segments = elf.program_headers().collect::<Vec<_>>();

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

        assert_eq!(elf.program_header_count(), 3);
        assert_eq!(header_segment.segment_type(), ElfProgramHeaderType::PT_LOAD);
        assert_eq!(header_segment.flags(), PF_R);
        assert_eq!(header_segment.offset(), 0);
        assert_eq!(header_segment.vaddr(), 0x400000);
        assert_eq!(header_segment.paddr(), 0x400000);
        assert_eq!(header_segment.align(), 0x1000);
        assert_eq!(header_segment.file_size(), 64 + 56 * 3);
        assert_eq!(header_segment.mem_size(), header_segment.file_size());
        assert_eq!(header_segment.data().unwrap(), &storage[..64 + 56 * 3]);
        assert_eq!(headers[1].data().unwrap(), &[0x90, 0x90, 0x90, 0xC3]);

        let note = &headers[2];
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
    fn header_load_can_contain_data_following_the_program_headers() {
        let mut writer = ExecElf64Writer::new_x86_64_executable(0x400100);
        let header_size = 64 + 56;
        let mut data = vec![0; header_size];
        data.extend_from_slice(&[0x90, 0xc3]);
        writer.header_segment = Some(LoadSegment {
            flags: Elf64ProgramHeaderFlags::from_bits(PF_R | PF_X),
            vaddr: 0x400000,
            paddr: 0x400000,
            align: 0x1000,
            mem_size: data.len() as u64 + 16,
            data,
        });
        let mut storage = vec![0; writer.file_size().unwrap() as usize];
        writer.write_into(&mut storage).unwrap();
        let elf = Elf64::new(&storage).unwrap();
        let header = elf.program_headers().next().unwrap();
        assert_eq!(elf.program_header_count(), 1);
        assert_eq!(header.offset(), 0);
        assert_eq!(header.file_size(), 122);
        assert_eq!(header.mem_size(), 138);
        assert_eq!(&header.data().unwrap()[120..], &[0x90, 0xc3]);
        assert_eq!(&storage[..4], b"\x7fELF");
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
