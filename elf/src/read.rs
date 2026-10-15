//! Read ELF64 headers and tables while borrowing names and data.
//!
//! [`Elf64::new`] takes file bytes and checks the header and table ranges.
//! [`Elf64Section`] opens symbol and RELA tables when asked; names and data
//! borrow the input slice. The file's byte-order tag tells each getter how
//! to read its multi-byte fields.
//!
//! An archive can place ELF records on a two-byte boundary, short of Rust's
//! alignment needs. We copy raw records with unaligned reads rather than borrow
//! them as structs. This reader accepts x86-64 and AArch64 headers; the linker
//! checks its stricter target rules when it reads an input object.
//!
//! References: ELF gABI "ELF Header", "Sections", "String Table", "Symbol Table",
//! "Relocation", and "Program Header"; AMD64 psABI §§4.1–4.4 and 5.1.

use anyhow::{Context, Result, bail, ensure};
use core::{mem::size_of, ptr};

use crate::abi::{
    Elf64Header, Elf64ProgramHeader as RawElf64ProgramHeader, Elf64RelaInfo, Elf64RelaTable,
    Elf64SectionFlags, Elf64SectionHeaderData, Elf64SectionType, Elf64SymbolInfo,
    Elf64SymbolSectionIdx, Elf64SymbolTable, ElfEndian, ElfFileType, ElfMachineType,
    ElfProgramHeaderType, SHN_ABS, SHN_COMMON, SHN_UNDEF,
};

/// Borrow the file bytes and decode fields using the byte order in its header.
pub struct Elf64<'a> {
    data: &'a [u8],
    endian: ElfEndian,
    header: Elf64Header,
}

impl<'a> Elf64<'a> {
    pub fn check_elf_magic(elf: &[u8]) -> bool {
        elf.get(0..4) == Some(&[0x7F, b'E', b'L', b'F'][..])
    }

    /// Check the ELF64 header and top-level table ranges, borrowing the bytes.
    ///
    /// Read names and section contents only when asked. This checks the outer
    /// format, not every symbol or relocation. The linker checks its target rules
    /// separately; the reader accepts x86-64 and AArch64 and both byte orders.
    pub fn new(elf: &'a [u8]) -> Result<Self> {
        ensure!(elf.len() >= size_of::<Elf64Header>(), "File too short");
        ensure!(
            Self::check_elf_magic(elf),
            "Invalid ELF magic: {:?}",
            elf.get(0..4)
        );

        let header = read_struct::<Elf64Header>(elf, 0).context("File too short")?;
        ensure!(
            header.e_ident.class == 2,
            "Unsupported ELF class: {}",
            header.e_ident.class
        );

        let endian = match header.e_ident.data {
            1 => ElfEndian::Little,
            2 => ElfEndian::Big,
            _ => bail!("Unsupported ELF data encoding: {}", header.e_ident.data),
        };

        ensure!(
            header.e_ident.version == 1,
            "Unsupported ELF version: {}",
            header.e_ident.version
        );
        ensure!(
            header.e_ehsize.read(endian) == size_of::<Elf64Header>() as u16,
            "Invalid ELF header size: {}",
            header.e_ehsize.read(endian)
        );
        ensure!(
            matches!(
                header.e_machine.read(endian),
                ElfMachineType::EM_X86_64 | ElfMachineType::EM_AARCH64
            ),
            "Unsupported ELF machine type: {}",
            header.e_machine.read(endian).raw()
        );
        ensure!(
            header.e_version.read(endian) == 1,
            "Unsupported ELF version: {}",
            header.e_version.read(endian)
        );

        let phnum = header.e_phnum.read(endian);
        let phentsize = header.e_phentsize.read(endian);
        if phnum > 0 {
            ensure!(
                phentsize == size_of::<RawElf64ProgramHeader>() as u16,
                "Invalid ELF program header size: {}",
                phentsize
            );
            ensure!(
                range_in_bounds(
                    elf.len(),
                    header.e_phoff.read(endian),
                    u64::from(phnum) * u64::from(phentsize)
                ),
                "Program headers exceed file bounds"
            );
        }

        let shnum = header.e_shnum.read(endian);
        let shentsize = header.e_shentsize.read(endian);
        if shnum > 0 {
            ensure!(
                shentsize == size_of::<Elf64SectionHeaderData>() as u16,
                "Invalid ELF section header size: {}",
                shentsize
            );
            ensure!(
                range_in_bounds(
                    elf.len(),
                    header.e_shoff.read(endian),
                    u64::from(shnum) * u64::from(shentsize)
                ),
                "Section headers exceed file bounds"
            );
        }

        match header.e_type.read(endian) {
            ElfFileType::ET_REL => {
                ensure!(
                    phnum == 0,
                    "Relocatable files should not have program headers"
                );
                ensure!(
                    shnum > 0,
                    "Relocatable files must have at least one section header"
                );
            }
            ElfFileType::ET_EXEC | ElfFileType::ET_DYN => {
                ensure!(
                    phnum > 0,
                    "Executable and shared object files must have at least one program header"
                );
            }
            ElfFileType::ET_CORE => {}
            other => bail!("Unsupported ELF file type: {}", other.raw()),
        }

        Ok(Self {
            data: elf,
            endian,
            header,
        })
    }

    pub fn arch(&self) -> ElfMachineType {
        self.header.e_machine.read(self.endian)
    }

    pub fn elf_type(&self) -> ElfFileType {
        self.header.e_type.read(self.endian)
    }

    pub fn endian(&self) -> ElfEndian {
        self.endian
    }

    pub fn entry(&self) -> u64 {
        self.header.e_entry.read(self.endian)
    }

    pub fn program_header_count(&self) -> u16 {
        self.header.e_phnum.read(self.endian)
    }

    pub fn program_headers(&self) -> Elf64ProgramHeaderIter<'_, 'a> {
        Elf64ProgramHeaderIter {
            elf: self,
            ph_idx: 0,
        }
    }

    /// Visit original section indices, including ELF's required null section.
    pub fn sections(&self) -> Elf64SectionIter<'_, 'a> {
        Elf64SectionIter {
            elf: self,
            sh_idx: 0,
        }
    }

    fn sections_size(&self) -> u16 {
        self.header.e_shnum.read(self.endian)
    }

    fn bytes_at(&self, offset: u64, size: u64) -> Option<&'a [u8]> {
        let start = usize::try_from(offset).ok()?;
        let len = usize::try_from(size).ok()?;
        let end = start.checked_add(len)?;
        self.data.get(start..end)
    }

    fn read_program_header(&self, idx: u16) -> Option<RawElf64ProgramHeader> {
        if idx >= self.program_header_count() {
            return None;
        }

        let offset =
            self.header.e_phoff.read(self.endian).checked_add(
                u64::from(idx) * u64::from(self.header.e_phentsize.read(self.endian)),
            )?;

        read_struct::<RawElf64ProgramHeader>(self.data, offset)
    }

    fn get_section(&self, idx: u16) -> Option<Elf64Section<'_, 'a>> {
        if idx >= self.sections_size() {
            return None;
        }

        let offset =
            self.header.e_shoff.read(self.endian).checked_add(
                u64::from(idx) * u64::from(self.header.e_shentsize.read(self.endian)),
            )?;
        let header = read_struct::<Elf64SectionHeaderData>(self.data, offset)?;

        Some(Elf64Section {
            elf: self,
            header,
            sh_idx: idx,
        })
    }

    fn read_string_from_section(
        &self,
        section: &Elf64Section<'_, 'a>,
        offset: u64,
        label: &'static str,
    ) -> Result<&'a str> {
        let data = section
            .data()
            .with_context(|| format!("{label} string table has no data"))?;
        read_c_string(data, offset)
            .with_context(|| format!("{label} string offset {offset} is invalid"))
    }
}

/// Walk program headers in file order.
pub struct Elf64ProgramHeaderIter<'elf, 'data> {
    elf: &'elf Elf64<'data>,
    ph_idx: u16,
}

impl<'elf, 'data> Iterator for Elf64ProgramHeaderIter<'elf, 'data> {
    type Item = Elf64ProgramHeader<'elf, 'data>;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.ph_idx;
        let header = self.elf.read_program_header(idx)?;
        self.ph_idx = idx.saturating_add(1);
        Some(Elf64ProgramHeader {
            elf: self.elf,
            header,
        })
    }
}

/// Use the file's byte order to read one segment's range and flags.
pub struct Elf64ProgramHeader<'elf, 'data> {
    elf: &'elf Elf64<'data>,
    header: RawElf64ProgramHeader,
}

impl<'elf, 'data> Elf64ProgramHeader<'elf, 'data> {
    pub fn segment_type(&self) -> ElfProgramHeaderType {
        self.header.p_type.read(self.elf.endian)
    }

    pub fn flags(&self) -> u32 {
        self.header.p_flags.read(self.elf.endian)
    }

    pub fn offset(&self) -> u64 {
        self.header.p_offset.read(self.elf.endian)
    }

    pub fn vaddr(&self) -> u64 {
        self.header.p_vaddr.read(self.elf.endian)
    }

    pub fn paddr(&self) -> u64 {
        self.header.p_paddr.read(self.elf.endian)
    }

    /// Bytes stored in the file; a load can need more memory than this.
    pub fn file_size(&self) -> u64 {
        self.header.p_filesz.read(self.elf.endian)
    }

    /// Total memory size, including any zero-filled tail.
    pub fn mem_size(&self) -> u64 {
        self.header.p_memsz.read(self.elf.endian)
    }

    /// File offset and virtual address must match modulo this value.
    pub fn align(&self) -> u64 {
        self.header.p_align.read(self.elf.endian)
    }

    /// Borrow the file prefix, or return `None` if its range lies outside the input.
    pub fn data(&self) -> Option<&'data [u8]> {
        self.elf.bytes_at(self.offset(), self.file_size())
    }
}

/// Walk section headers in index order, including section zero.
pub struct Elf64SectionIter<'elf, 'data> {
    elf: &'elf Elf64<'data>,
    sh_idx: u16,
}

impl<'elf, 'data> Iterator for Elf64SectionIter<'elf, 'data> {
    type Item = Elf64Section<'elf, 'data>;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.sh_idx;
        let section = self.elf.get_section(idx)?;
        self.sh_idx = idx.saturating_add(1);
        Some(section)
    }
}

/// Keep a section's original index and borrow its name and bytes from the file.
pub struct Elf64Section<'elf, 'data> {
    elf: &'elf Elf64<'data>,
    header: Elf64SectionHeaderData,
    sh_idx: u16,
}

impl<'elf, 'data> Elf64Section<'elf, 'data> {
    /// Follow the section-name table and check the name's offset and NUL terminator.
    pub fn name(&self) -> Result<&'data str> {
        let shstr_section = self
            .elf
            .get_section(self.elf.header.e_shstrndx.read(self.elf.endian))
            .context("Failed to get section header string table")?;
        self.elf.read_string_from_section(
            &shstr_section,
            u64::from(self.header.sh_name.read(self.elf.endian)),
            "section header",
        )
    }

    pub fn idx(&self) -> u16 {
        self.sh_idx
    }

    pub fn section_type(&self) -> Elf64SectionType {
        self.header.sh_type.read(self.elf.endian)
    }

    pub fn flags(&self) -> Elf64SectionFlags {
        self.header.sh_flags.read(self.elf.endian)
    }

    /// Required alignment; zero and one impose no constraint.
    pub fn align(&self) -> u64 {
        self.header.sh_addralign.read(self.elf.endian)
    }

    /// NOBITS has no file data. Return `None` for it or an invalid file range.
    pub fn data(&self) -> Option<&'data [u8]> {
        if self.section_type() == Elf64SectionType::SHT_NOBITS {
            None
        } else {
            self.elf.bytes_at(
                self.header.sh_offset.read(self.elf.endian),
                self.header.sh_size.read(self.elf.endian),
            )
        }
    }

    /// sh_addr is usually zero in ET_REL; output files can give a virtual address.
    pub fn address(&self) -> u64 {
        self.header.sh_addr.read(self.elf.endian)
    }

    pub fn offset(&self) -> u64 {
        self.header.sh_offset.read(self.elf.endian)
    }

    /// Table index with a type-specific meaning, such as a symbol table's string table.
    pub fn link(&self) -> u32 {
        self.header.sh_link.read(self.elf.endian)
    }

    /// Type-specific data, such as a RELA target or the first non-local symbol index.
    pub fn info(&self) -> u32 {
        self.header.sh_info.read(self.elf.endian)
    }

    /// Bytes per fixed-size record, or zero for unstructured data.
    pub fn entry_size(&self) -> u64 {
        self.header.sh_entsize.read(self.elf.endian)
    }

    /// Memory size for NOBITS, even though no bytes occupy the file.
    pub fn size(&self) -> u64 {
        self.header.sh_size.read(self.elf.endian)
    }

    /// Require SYMTAB or DYNSYM with a size that fits whole ELF64 symbol records.
    pub fn symbols(&'elf self) -> Result<Elf64SymbolIter<'elf, 'data>> {
        ensure!(
            matches!(
                self.section_type(),
                Elf64SectionType::SHT_SYMTAB | Elf64SectionType::SHT_DYNSYM
            ),
            "Section is not a symbol table"
        );
        ensure!(
            self.size()
                .is_multiple_of(size_of::<Elf64SymbolTable>() as u64),
            "Section size is not a multiple of symbol entry size"
        );
        Ok(Elf64SymbolIter {
            section: self,
            sym_idx: 0,
        })
    }

    /// Require RELA with a size that fits whole explicit-addend records.
    pub fn rela(&'elf self) -> Result<Elf64RelaIter<'elf, 'data>> {
        ensure!(
            self.section_type() == Elf64SectionType::SHT_RELA,
            "Section is not a RELA table"
        );
        ensure!(
            self.size()
                .is_multiple_of(size_of::<Elf64RelaTable>() as u64),
            "Section size is not a multiple of RELA entry size"
        );
        Ok(Elf64RelaIter {
            section: self,
            rela_idx: 0,
        })
    }
}

/// Walk explicit-addend records in section order.
pub struct Elf64RelaIter<'elf, 'data> {
    section: &'elf Elf64Section<'elf, 'data>,
    rela_idx: u16,
}

impl<'elf, 'data> Iterator for Elf64RelaIter<'elf, 'data> {
    type Item = Elf64Rela<'elf, 'data>;

    fn next(&mut self) -> Option<Self::Item> {
        let rela_size = size_of::<Elf64RelaTable>() as u64;
        let idx = u64::from(self.rela_idx);
        let offset_in_section = idx.checked_mul(rela_size)?;
        let end_in_section = offset_in_section.checked_add(rela_size)?;
        if end_in_section > self.section.size() {
            return None;
        }
        let offset = self
            .section
            .header
            .sh_offset
            .read(self.section.elf.endian)
            .checked_add(offset_in_section)?;
        let header = read_struct::<Elf64RelaTable>(self.section.elf.data, offset)?;

        self.rela_idx = self.rela_idx.saturating_add(1);
        Some(Elf64Rela {
            section: self.section,
            header,
        })
    }
}

/// Keep the containing relocation section so sh_info can name the patch target.
pub struct Elf64Rela<'elf, 'data> {
    section: &'elf Elf64Section<'elf, 'data>,
    header: Elf64RelaTable,
}

impl<'elf, 'data> Elf64Rela<'elf, 'data> {
    /// ET_REL uses a target-section offset; ET_EXEC uses a virtual address.
    pub fn offset(&self) -> u64 {
        self.header.r_offset.read(self.section.elf.endian)
    }

    pub fn info(&self) -> Elf64RelaInfo {
        let info = self.header.r_info.read(self.section.elf.endian);
        Elf64RelaInfo {
            sym: (info >> 32) as u32,
            ty: (info & 0xFFFF_FFFF) as u32,
        }
    }

    pub fn addend(&self) -> i64 {
        self.header.r_addend.read(self.section.elf.endian)
    }

    /// Read the target section index from the containing RELA section's sh_info.
    pub fn target_idx(&self) -> u32 {
        self.section.header.sh_info.read(self.section.elf.endian)
    }
}

/// Walk symbol indices in file order, including the null symbol.
pub struct Elf64SymbolIter<'elf, 'data> {
    section: &'elf Elf64Section<'elf, 'data>,
    sym_idx: u16,
}

impl<'elf, 'data> Iterator for Elf64SymbolIter<'elf, 'data> {
    type Item = Elf64Symbol<'elf, 'data>;

    fn next(&mut self) -> Option<Self::Item> {
        let sym_size = size_of::<Elf64SymbolTable>() as u64;
        let idx = u64::from(self.sym_idx);
        let offset_in_section = idx.checked_mul(sym_size)?;
        let end_in_section = offset_in_section.checked_add(sym_size)?;
        if end_in_section > self.section.size() {
            return None;
        }
        let offset = self
            .section
            .header
            .sh_offset
            .read(self.section.elf.endian)
            .checked_add(offset_in_section)?;
        let header = read_struct::<Elf64SymbolTable>(self.section.elf.data, offset)?;

        self.sym_idx = self.sym_idx.saturating_add(1);
        Some(Elf64Symbol {
            section: self.section,
            header,
        })
    }
}

/// Find a symbol's name through its table's sh_link string table.
pub struct Elf64Symbol<'elf, 'data> {
    section: &'elf Elf64Section<'elf, 'data>,
    header: Elf64SymbolTable,
}

impl<'elf, 'data> Elf64Symbol<'elf, 'data> {
    /// Follow the symbol table's linked string table and check the name's bounds.
    pub fn name(&self) -> Result<&'data str> {
        let strtab_section = self
            .section
            .elf
            .get_section(self.section.header.sh_link.read(self.section.elf.endian) as u16)
            .context("Failed to get symbol string table")?;
        self.section.elf.read_string_from_section(
            &strtab_section,
            u64::from(self.header.st_name.read(self.section.elf.endian)),
            "symbol",
        )
    }

    /// Tell real defining sections from undefined, absolute, and COMMON values.
    pub fn section_idx(&self) -> Elf64SymbolSectionIdx {
        match self.header.st_shndx.read(self.section.elf.endian) {
            SHN_UNDEF => Elf64SymbolSectionIdx::Undefined,
            SHN_ABS => Elf64SymbolSectionIdx::AbsoluteSymbols,
            SHN_COMMON => Elf64SymbolSectionIdx::Common,
            idx => Elf64SymbolSectionIdx::Index(idx),
        }
    }

    /// ET_REL usually stores a section offset. ET_EXEC stores an address,
    /// except TLS symbols, which store offsets within the TLS template.
    pub fn value(&self) -> u64 {
        self.header.st_value.read(self.section.elf.endian)
    }

    pub fn size(&self) -> u64 {
        self.header.st_size.read(self.section.elf.endian)
    }

    /// Keep raw st_other bits, including the low visibility bits.
    pub fn other(&self) -> u8 {
        self.header.st_other
    }

    pub fn info(&self) -> Elf64SymbolInfo {
        self.header.st_info
    }
}

fn read_struct<T: Copy>(data: &[u8], offset: u64) -> Option<T> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(size_of::<T>())?;
    let bytes = data.get(start..end)?;
    let ptr = bytes.as_ptr().cast::<T>();
    // SAFETY: Every T used here holds integer fields that accept any bits.
    // The slice covers all of T. Copy without alignment because ar members
    // need only start at a two-byte boundary.
    Some(unsafe { ptr::read_unaligned(ptr) })
}

fn range_in_bounds(total_len: usize, offset: u64, len: u64) -> bool {
    let Some(start) = usize::try_from(offset).ok() else {
        return false;
    };
    let Some(size) = usize::try_from(len).ok() else {
        return false;
    };
    let Some(end) = start.checked_add(size) else {
        return false;
    };
    end <= total_len
}

fn read_c_string(data: &[u8], offset: u64) -> Result<&str> {
    let start = usize::try_from(offset).context("string offset does not fit in usize")?;
    let tail = data.get(start..).context("string offset out of bounds")?;
    let nul = tail
        .iter()
        .position(|&b| b == 0)
        .context("missing NUL terminator")?;
    std::str::from_utf8(&tail[..nul]).context("string is not valid UTF-8")
}

#[cfg(test)]
mod tests {
    //! Check bad table ranges and valid headers at unaligned byte offsets.

    use crate::{
        Elf64, Elf64SectionType, Elf64SymbolBinding, Elf64SymbolInfo, Elf64SymbolSectionIdx,
        Elf64SymbolType, ElfEndian, ElfFileType, ElfMachineType, x86_64::X86_64RelocationType,
    };

    fn write_u16(out: &mut [u8], offset: usize, value: u16) {
        out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(out: &mut [u8], offset: usize, value: u32) {
        out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(out: &mut [u8], offset: usize, value: u64) {
        out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn write_i64(out: &mut [u8], offset: usize, value: i64) {
        out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn build_minimal_rel_object() -> Vec<u8> {
        const ELF_HEADER_SIZE: usize = 64;
        const SECTION_HEADER_SIZE: usize = 64;
        const SYMBOL_SIZE: usize = 24;
        const RELA_SIZE: usize = 24;

        let shstrtab = b"\0.shstrtab\0.text\0.symtab\0.strtab\0.rela.text\0";
        let strtab = b"\0_start\0";
        let text = [0x90, 0x90, 0x90, 0xC3];

        let shstrtab_offset = ELF_HEADER_SIZE;
        let text_offset = shstrtab_offset + shstrtab.len();
        let symtab_offset = text_offset + text.len();
        let strtab_offset = symtab_offset + SYMBOL_SIZE * 2;
        let rela_offset = strtab_offset + strtab.len();
        let shoff = rela_offset + RELA_SIZE;
        let file_size = shoff + SECTION_HEADER_SIZE * 6;

        let mut out = vec![0u8; file_size];

        out[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        out[4] = 2;
        out[5] = 1;
        out[6] = 1;

        write_u16(&mut out, 16, ElfFileType::ET_REL.raw());
        write_u16(&mut out, 18, ElfMachineType::EM_X86_64.raw());
        write_u32(&mut out, 20, 1);
        write_u64(&mut out, 24, 0);
        write_u64(&mut out, 32, 0);
        write_u64(&mut out, 40, shoff as u64);
        write_u32(&mut out, 48, 0);
        write_u16(&mut out, 52, ELF_HEADER_SIZE as u16);
        write_u16(&mut out, 54, 0);
        write_u16(&mut out, 56, 0);
        write_u16(&mut out, 58, SECTION_HEADER_SIZE as u16);
        write_u16(&mut out, 60, 6);
        write_u16(&mut out, 62, 1);

        out[shstrtab_offset..shstrtab_offset + shstrtab.len()].copy_from_slice(shstrtab);
        out[text_offset..text_offset + text.len()].copy_from_slice(&text);
        out[strtab_offset..strtab_offset + strtab.len()].copy_from_slice(strtab);

        let symtab_entry_1 = symtab_offset + SYMBOL_SIZE;
        write_u32(&mut out, symtab_entry_1, 1);
        out[symtab_entry_1 + 4] =
            ((Elf64SymbolBinding::STB_GLOBAL as u8) << 4) | (Elf64SymbolType::STT_FUNC as u8);
        out[symtab_entry_1 + 5] = 0;
        write_u16(&mut out, symtab_entry_1 + 6, 2);
        write_u64(&mut out, symtab_entry_1 + 8, 0);
        write_u64(&mut out, symtab_entry_1 + 16, text.len() as u64);

        write_u64(&mut out, rela_offset, 0);
        write_u64(
            &mut out,
            rela_offset + 8,
            ((1u64) << 32) | X86_64RelocationType::Pc32 as u64,
        );
        write_i64(&mut out, rela_offset + 16, -4);

        let mut sh = shoff;

        sh += SECTION_HEADER_SIZE;

        write_u32(&mut out, sh, 1);
        write_u32(&mut out, sh + 4, Elf64SectionType::SHT_STRTAB.raw());
        write_u64(&mut out, sh + 16, 0);
        write_u64(&mut out, sh + 24, shstrtab_offset as u64);
        write_u64(&mut out, sh + 32, shstrtab.len() as u64);
        write_u64(&mut out, sh + 48, 1);
        sh += SECTION_HEADER_SIZE;

        write_u32(&mut out, sh, 11);
        write_u32(&mut out, sh + 4, Elf64SectionType::SHT_PROGBITS.raw());
        write_u64(&mut out, sh + 8, 0x6);
        write_u64(&mut out, sh + 16, 0);
        write_u64(&mut out, sh + 24, text_offset as u64);
        write_u64(&mut out, sh + 32, text.len() as u64);
        write_u64(&mut out, sh + 48, 16);
        sh += SECTION_HEADER_SIZE;

        write_u32(&mut out, sh, 17);
        write_u32(&mut out, sh + 4, Elf64SectionType::SHT_SYMTAB.raw());
        write_u64(&mut out, sh + 24, symtab_offset as u64);
        write_u64(&mut out, sh + 32, (SYMBOL_SIZE * 2) as u64);
        write_u32(&mut out, sh + 40, 4);
        write_u32(&mut out, sh + 44, 1);
        write_u64(&mut out, sh + 48, 8);
        write_u64(&mut out, sh + 56, SYMBOL_SIZE as u64);
        sh += SECTION_HEADER_SIZE;

        write_u32(&mut out, sh, 25);
        write_u32(&mut out, sh + 4, Elf64SectionType::SHT_STRTAB.raw());
        write_u64(&mut out, sh + 24, strtab_offset as u64);
        write_u64(&mut out, sh + 32, strtab.len() as u64);
        write_u64(&mut out, sh + 48, 1);
        sh += SECTION_HEADER_SIZE;

        write_u32(&mut out, sh, 33);
        write_u32(&mut out, sh + 4, Elf64SectionType::SHT_RELA.raw());
        write_u64(&mut out, sh + 24, rela_offset as u64);
        write_u64(&mut out, sh + 32, RELA_SIZE as u64);
        write_u32(&mut out, sh + 40, 3);
        write_u32(&mut out, sh + 44, 2);
        write_u64(&mut out, sh + 48, 8);
        write_u64(&mut out, sh + 56, RELA_SIZE as u64);

        out
    }

    fn build_minimal_exec_header() -> Vec<u8> {
        let mut out = vec![0u8; 64 + 56];
        out[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        out[4] = 2;
        out[5] = 1;
        out[6] = 1;

        write_u16(&mut out, 16, ElfFileType::ET_EXEC.raw());
        write_u16(&mut out, 18, ElfMachineType::EM_X86_64.raw());
        write_u32(&mut out, 20, 1);
        write_u64(&mut out, 24, 0x401000);
        write_u64(&mut out, 32, 64);
        write_u64(&mut out, 40, 0);
        write_u32(&mut out, 48, 0);
        write_u16(&mut out, 52, 64);
        write_u16(&mut out, 54, 56);
        write_u16(&mut out, 56, 1);
        write_u16(&mut out, 58, 0);
        write_u16(&mut out, 60, 0);
        write_u16(&mut out, 62, 0);
        out
    }

    #[test]
    fn new_rejects_too_short_slice() {
        let err = match Elf64::new(&[0u8; 63]) {
            Ok(_) => panic!("short ELF input should fail"),
            Err(err) => err,
        };
        assert_eq!(err.to_string(), "File too short");
    }

    #[test]
    fn new_accepts_unaligned_header_buffer() {
        let header = build_minimal_exec_header();
        let mut storage = vec![0u8; header.len() + 1];
        storage[1..].copy_from_slice(&header);

        let elf = Elf64::new(&storage[1..]).unwrap();
        assert_eq!(elf.arch(), ElfMachineType::EM_X86_64);
        assert_eq!(elf.endian(), ElfEndian::Little);
    }

    #[test]
    fn parses_relocatable_sections_symbols_and_relocations() {
        let bytes = build_minimal_rel_object();
        let elf = Elf64::new(&bytes).unwrap();

        assert_eq!(elf.elf_type(), ElfFileType::ET_REL);
        assert_eq!(elf.arch(), ElfMachineType::EM_X86_64);

        let sections = elf.sections().collect::<Vec<_>>();
        assert_eq!(sections.len(), 6);

        let text = sections
            .iter()
            .find(|section| section.name().unwrap() == ".text")
            .unwrap();
        assert_eq!(text.section_type(), Elf64SectionType::SHT_PROGBITS);
        assert_eq!(text.data().unwrap(), &[0x90, 0x90, 0x90, 0xC3]);

        let symtab = sections
            .iter()
            .find(|section| section.name().unwrap() == ".symtab")
            .unwrap();
        let symbols = symtab.symbols().unwrap().collect::<Vec<_>>();
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name().unwrap(), "");
        assert_eq!(symbols[1].name().unwrap(), "_start");
        assert_eq!(symbols[1].section_idx(), Elf64SymbolSectionIdx::Index(2));
        assert_eq!(
            symbols[1].info().get_enum(Elf64SymbolInfo::st_bind),
            Some(Elf64SymbolBinding::STB_GLOBAL)
        );

        let rela_text = sections
            .iter()
            .find(|section| section.name().unwrap() == ".rela.text")
            .unwrap();
        let rela = rela_text.rela().unwrap().collect::<Vec<_>>();
        assert_eq!(rela.len(), 1);
        assert_eq!(rela[0].offset(), 0);
        assert_eq!(rela[0].target_idx(), 2);
        assert_eq!(rela[0].addend(), -4);
        assert_eq!(rela[0].info().sym, 1);
        assert_eq!(rela[0].info().ty, X86_64RelocationType::Pc32 as u32);
    }
}
