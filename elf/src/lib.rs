//! ELF file parser for loading executables.
//!
//! Provides utilities for parsing ELF64 headers and loading program segments.
use anyhow::{Context, Result, bail, ensure};
use core::mem::{align_of, size_of};
use std::ffi::{CStr, c_char};
use typestate::{RawReg, bitregs};
use typestate_macro::RawReg;

#[allow(clippy::assertions_on_constants)]
const _: () = assert!(size_of::<Elf64Header>() == 64);
const _: () = assert!(size_of::<Elf64ProgramHeader>() == 56);

type Elf64Addr = u64;
type Elf64Off = u64;
type Elf64Half = u16;
type Elf64Word = u32;
type Elf64Sword = i32;
type Elf64Xword = u64;
type Elf64Sxword = i64;

#[repr(C)]
struct Elf64Header {
    e_ident: ElfHeaderIdent,                  // elf identification
    e_type: ElfEndianness<ElfFileType>,       // Object File Type
    e_machine: ElfEndianness<ElfMachineType>, // Machine Type
    e_version: ElfEndianness<Elf64Word>,      // Object File Version
    e_entry: ElfEndianness<Elf64Addr>,        // Entry Point Address
    e_phoff: ElfEndianness<Elf64Off>,         // Program Header Offset
    e_shoff: ElfEndianness<Elf64Off>,         // Section Header Offset
    e_flags: ElfEndianness<Elf64Word>,        // Processor Specific Flags
    e_ehsize: ElfEndianness<Elf64Half>,       // ELF Header Size
    e_phentsize: ElfEndianness<Elf64Half>,    // Size Of Program Header Entry
    e_phnum: ElfEndianness<Elf64Half>,        // Number Of Program Header Entries
    e_shentsize: ElfEndianness<Elf64Half>,    // Size Of Section Header Entry
    e_shnum: ElfEndianness<Elf64Half>,        // Number Of Section Header Entries
    e_shstrndx: ElfEndianness<Elf64Half>,     // Section Name String Table Index
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, RawReg, PartialEq, Eq)]
pub struct ElfFileType(Elf64Half);

impl ElfFileType {
    pub const ET_REL: Self = Self(1);
    pub const ET_EXEC: Self = Self(2);
    pub const ET_DYN: Self = Self(3);
    pub const ET_CORE: Self = Self(4);
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, RawReg, PartialEq, Eq)]
pub struct ElfMachineType(Elf64Half);

impl ElfMachineType {
    pub const EM_X86_64: Self = Self(62);
    pub const EM_AARCH64: Self = Self(183);
}

#[repr(C)]
struct ElfHeaderIdent {
    magic: [u8; 4],  // File Identification
    class: u8,       // File Class
    data: u8,        // Data Encoding
    version: u8,     // File Version
    os_abi: u8,      // OS/ABI Identification
    abi_version: u8, // ABI Version
    _reserved: [u8; 7],
}

#[repr(C)]
struct Elf64ProgramHeader {
    p_type: ElfProgramHeaderTypes, // Type Of Segment
    p_flags: Elf64Word,            // Segment Attributes
    p_offset: Elf64Off,            // Offset In File
    p_vaddr: Elf64Addr,            // Virtual Address In Memory
    p_paddr: Elf64Addr,            // Physical Address In Memory
    p_filesz: Elf64Xword,          // Size Of Segment In File
    p_memsz: Elf64Xword,           // Size Of Segment In Memory
    p_align: Elf64Xword,           // Alignment Of Segment
}

#[repr(transparent)]
#[derive(Clone, Copy, RawReg, PartialEq)]
struct ElfProgramHeaderTypes(Elf64Word);

impl ElfProgramHeaderTypes {
    const PT_NULL: Self = Self(0);
    const PT_LOAD: Self = Self(1);
    const PT_DYNAMIC: Self = Self(2);
    const PT_INTERP: Self = Self(3);
    const PT_NOTE: Self = Self(4);
    const PT_SHLIB: Self = Self(5);
    const PT_PHDR: Self = Self(6);
}

#[repr(C)]
struct Elf64SectionHeaderData {
    sh_name: ElfEndianness<Elf64Word>,          // Section Name
    sh_type: ElfEndianness<Elf64SectionType>,   // Section Type
    sh_flags: ElfEndianness<Elf64SectionFlags>, // Section Attributes
    sh_addr: ElfEndianness<Elf64Addr>,          // Virtual Address In Memory
    sh_offset: ElfEndianness<Elf64Off>,         // Offset In File
    sh_size: ElfEndianness<Elf64Xword>,         // Size Of Section
    sh_link: ElfEndianness<Elf64Word>,          // Link To Other Section
    sh_info: ElfEndianness<Elf64Word>,          // Miscellaneous Information
    sh_addralign: ElfEndianness<Elf64Xword>,    // Address Alignment Boundary
    sh_entsize: ElfEndianness<Elf64Xword>,      // Size Of Entries, If Section Has Table
}

#[repr(transparent)]
#[derive(Clone, Copy, RawReg, PartialEq, Debug)]
pub struct Elf64SectionType(Elf64Word);

impl Elf64SectionType {
    pub const SHT_NULL: Self = Self(0);
    pub const SHT_PROGBITS: Self = Self(1);
    pub const SHT_SYMTAB: Self = Self(2);
    pub const SHT_STRTAB: Self = Self(3);
    pub const SHT_RELA: Self = Self(4);
    pub const SHT_HASH: Self = Self(5);
    pub const SHT_DYNAMIC: Self = Self(6);
    pub const SHT_NOTE: Self = Self(7);
    pub const SHT_NOBITS: Self = Self(8);
    pub const SHT_REL: Self = Self(9);
    pub const SHT_SHLIB: Self = Self(10);
    pub const SHT_DYNSYM: Self = Self(11);
    pub const SHT_LOPROC: Self = Self(0x70000000);
    pub const SHT_HIPROC: Self = Self(0x7FFFFFFF);
    pub const SHT_LOUSER: Self = Self(0x80000000);
    pub const SHT_HIUSER: Self = Self(0xFFFFFFFF);
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, RawReg, PartialEq)]
pub struct Elf64SectionFlags(Elf64Xword);

impl Elf64SectionFlags {
    pub const SHF_WRITE: Self = Self(0x1);
    pub const SHF_ALLOC: Self = Self(0x2);
    pub const SHF_EXECINSTR: Self = Self(0x4);
    pub const SHF_MASKPROC: Self = Self(0xF000_0000);
}

#[derive(Clone, Copy, Debug)]
pub enum ElfEndian {
    Big,
    Little,
}

/// Program header data extracted from an ELF file.
#[derive(Clone, Copy, Debug)]
pub struct ProgramHeaderData {
    /// Segment permissions derived from `p_flags`.
    /// Only the lower 3 bits are meaningful: PF_X=0x1, PF_W=0x2, PF_R=0x4.
    permission: ElfPermissions,

    /// Destination load address for this segment on bare metal.
    /// In this implementation we use `p_paddr` (physical address).
    /// Many toolchains set `p_paddr == p_vaddr`, but they are allowed to differ.
    address: u64,

    /// Number of bytes to copy from the file into memory for this segment.
    /// Comes from `p_filesz`.
    file_len: u64,

    /// Total size of the segment in memory, including any zero-filled tail (.bss).
    /// Comes from `p_memsz` and must be >= `file_len`.
    mem_len: u64,

    /// File offset where this segment’s data begins.
    /// Comes from `p_offset`. Must satisfy alignment relation with `vaddr`:
    /// if `p_align > 0`, then `p_vaddr % p_align == p_offset % p_align`.
    offset: u64,

    /// Required alignment for the segment (from `p_align`), in bytes.
    /// If zero, callers may choose a sensible default (e.g., page size).
    align: u64,
}

/// ELF segment permission flags.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, RawReg)]
pub struct ElfPermissions(u8);

impl ElfPermissions {
    /// Executable permission flag.
    pub const EXECUTABLE: Self = Self(0x1);
    /// Writable permission flag.
    pub const WRITABLE: Self = Self(0x2);
    /// Readable permission flag.
    pub const READABLE: Self = Self(0x4);
}

#[repr(C)]
pub struct Elf64SymbolTable {
    st_name: ElfEndianness<Elf64Word>,  // Symbol Name
    st_info: Elf64SymbolInfo,           // Type and Binding Attributes
    st_other: u8,                       // Reserved
    st_shndx: ElfEndianness<Elf64Half>, // Section Index
    st_value: ElfEndianness<Elf64Addr>, // Symbol Value
    st_size: ElfEndianness<Elf64Xword>, // Size of Object (e.g., common)
}

bitregs! {
    pub struct Elf64SymbolInfo:u8 {
        pub st_type@[3:0] as Elf64SymbolType {
            STT_NOTYPE = 0,
            STT_OBJECT = 1,
            STT_FUNC = 2,
            STT_SECTION = 3,
            STT_FILE = 4,
            STT_LOOS = 10,
            STT_HIOS = 12,
            STT_LOPROC = 13,
            STT_HIPROC = 15,
        }, // Symbol Type (lower 4 bits)
        pub st_bind@[7:4] as Elf64SymbolBinding {
            STB_LOCAL = 0,
            STB_GLOBAL = 1,
            STB_WEAK = 2,
            STB_LOOS = 10,
            STB_HIOS = 12,
            STB_LOPROC = 13,
            STB_HIPROC = 15,
        }, // Symbol Binding (upper 4 bits)
    }
}

/// Parsed ELF64 file.
#[derive(Debug)]
pub struct Elf64<'a> {
    data: &'a [u8],
    endian: ElfEndian,
}

impl<'a> Elf64<'a> {
    fn header(&self) -> &Elf64Header {
        // SAFETY: `Elf64::new` ensures that `self.data` is at least `size_of::<Elf64Header>()` bytes long
        // and properly aligned, so reinterpreting the prefix as `&Elf64Header` is safe.
        unsafe { &*(self.data.as_ptr() as *const Elf64Header) }
    }

    fn checked_ref<T>(&self, offset: u64) -> Option<&'a T> {
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(size_of::<T>())?;
        let bytes = self.data.get(start..end)?;
        let ptr = bytes.as_ptr();

        if !(ptr as usize).is_multiple_of(align_of::<T>()) {
            return None;
        }

        // SAFETY:
        // - `bytes` was obtained from `self.data[start..end]`, so the range is in-bounds.
        // - `ptr` is checked to satisfy `align_of::<T>()`.
        // - `end - start == size_of::<T>()`, so reading `T` from `ptr` is within bounds.
        Some(unsafe { &*(ptr as *const T) })
    }

    /// Parses an ELF64 header from the start of `elf`.
    ///
    /// This function validates the header size and alignment before
    /// reinterpreting the leading bytes as [`Elf64Header`].
    pub fn new(elf: &'a [u8]) -> Result<Self> {
        ensure!(elf.len() >= size_of::<Elf64Header>(), "File too short");
        ensure!(
            elf.get(0..4) == Some(&[0x7F, b'E', b'L', b'F']),
            format!("Invalid ELF magic: {:?}", elf.get(0..4))
        );
        ensure!(
            (elf.as_ptr() as usize).is_multiple_of(align_of::<Elf64Header>()),
            "ELF header is not properly aligned"
        );
        // `elf` is at least `Elf64Header` bytes long, and its head pointer satisfies
        // `Elf64Header` alignment, so reinterpreting the prefix as `&Elf64Header` is safe.
        let header = unsafe { &*(elf.as_ptr() as *const Elf64Header) };
        ensure!(
            header.e_ident.class == 2,
            format!("Unsupported ELF class: {}", header.e_ident.class)
        );

        let endian = match header.e_ident.data {
            1 => ElfEndian::Little,
            2 => ElfEndian::Big,
            _ => bail!("Unsupported ELF data encoding: {}", header.e_ident.data),
        };
        // this program is ver1.4 elf specification compatible
        ensure!(
            header.e_ident.version == 1,
            format!("Unsupported ELF version: {}", header.e_ident.version)
        );
        let e_type = header.e_type.read(endian);
        ensure!(
            matches!(
                header.e_machine.read(endian),
                ElfMachineType::EM_X86_64 | ElfMachineType::EM_AARCH64
            ),
            format!(
                "Unsupported ELF machine type: {}",
                header.e_machine.read(endian).0
            )
        );
        ensure!(
            header.e_version.read(endian) == 1,
            format!("Unsupported ELF version: {}", header.e_version.read(endian))
        );
        ensure!(
            header.e_ehsize.read(endian) == size_of::<Elf64Header>() as u16,
            format!("Invalid ELF header size: {}", header.e_ehsize.read(endian))
        );
        match e_type {
            ElfFileType::ET_REL => {
                ensure!(
                    header.e_phnum.read(endian) == 0,
                    "Relocatable files should not have program headers"
                );
                ensure!(
                    header.e_shnum.read(endian) > 0,
                    "Relocatable files must have at least one section header"
                );
            }
            ElfFileType::ET_EXEC | ElfFileType::ET_DYN => {
                ensure!(
                    header.e_phnum.read(endian) > 0,
                    "Executable and shared object files must have at least one program header"
                );
            }
            ElfFileType::ET_CORE => {
                // Core files may have program headers, but it's not required. No check needed.
            }
            _ => bail!("Unsupported ELF file type: {}", e_type.0), // already checked above
        }
        Ok(Self { data: elf, endian })
    }

    pub fn arch(&self) -> ElfMachineType {
        self.header().e_machine.read(self.endian)
    }

    pub fn elf_type(&self) -> ElfFileType {
        self.header().e_type.read(self.endian)
    }

    pub fn endian(&self) -> ElfEndian {
        self.endian
    }

    pub fn sections(&self) -> Elf64SectionIter<'_, 'a> {
        Elf64SectionIter {
            elf: self,
            sh_idx: 0,
        }
    }

    fn sections_size(&self) -> u16 {
        self.header().e_shnum.read(self.endian)
    }

    fn get_section(&self, idx: u16) -> Option<Elf64Section<'_, 'a>> {
        if idx >= self.sections_size() {
            None
        } else {
            let header_offset = self
                .header()
                .e_shoff
                .read(self.endian)
                .checked_add(idx as u64 * self.header().e_shentsize.read(self.endian) as u64)?;

            Some(Elf64Section {
                elf: self,
                header: self.checked_ref::<Elf64SectionHeaderData>(header_offset)?,
                sh_idx: idx,
            })
        }
    }
}

pub struct Elf64SectionIter<'elf, 'data> {
    elf: &'elf Elf64<'data>,
    sh_idx: u16,
}

impl<'elf, 'data> Iterator for Elf64SectionIter<'elf, 'data> {
    type Item = Elf64Section<'elf, 'data>;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.sh_idx;
        if idx >= self.elf.header().e_shnum.read(self.elf.endian) {
            return None;
        }
        self.sh_idx += 1;

        self.elf.get_section(idx)
    }
}

pub struct Elf64Section<'elf, 'data> {
    elf: &'elf Elf64<'data>,
    header: &'data Elf64SectionHeaderData,
    sh_idx: u16,
}

impl<'elf, 'data> Elf64Section<'elf, 'data> {
    pub fn name(&self) -> Result<&'data str> {
        let section = self
            .elf
            .get_section(self.elf.header().e_shstrndx.read(self.elf.endian))
            .context("Failed to get section header string table")?;
        unsafe {
            CStr::from_ptr(
                (self.elf.data.as_ptr() as u64
                    + section.header.sh_offset.read(self.elf.endian)
                    + self.header.sh_name.read(self.elf.endian) as u64)
                    as *const c_char,
            )
            .to_str()
            .context("Section name is not valid UTF-8")
        }
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

    pub fn align(&self) -> u64 {
        self.header.sh_addralign.read(self.elf.endian)
    }

    pub fn data(&self) -> Option<&'data [u8]> {
        if self.section_type() == Elf64SectionType::SHT_NOBITS {
            None
        } else {
            Some(
                &self.elf.data[(self.header.sh_offset.read(self.elf.endian) as usize)
                    ..(self.header.sh_offset.read(self.elf.endian) as usize
                        + self.header.sh_size.read(self.elf.endian) as usize)],
            )
        }
    }

    pub fn size(&self) -> u64 {
        self.header.sh_size.read(self.elf.endian)
    }

    pub fn symbols(&'elf self) -> Result<Elf64SymbolIter<'elf, 'data>> {
        ensure!(
            matches!(
                self.section_type(),
                Elf64SectionType::SHT_SYMTAB | Elf64SectionType::SHT_DYNSYM
            ),
            "Section is not a symbol table"
        );
        ensure!(
            self.header
                .sh_size
                .read(self.elf.endian)
                .is_multiple_of(size_of::<Elf64SymbolTable>() as u64),
            "Section size is not a multiple of symbol entry size"
        );
        Ok(Elf64SymbolIter {
            section: self,
            sym_idx: 0,
        })
    }

    pub fn rela(&self) -> Result<Elf64RelaIter<'_, 'data>> {
        Ok(Elf64RelaIter {
            section: self,
            rela_idx: 0,
        })
    }
}

pub struct Elf64RelaIter<'elf, 'data> {
    section: &'elf Elf64Section<'elf, 'data>,
    rela_idx: u16,
}

impl<'elf, 'data> Iterator for Elf64RelaIter<'elf, 'data> {
    type Item = Elf64Rela<'elf, 'data>;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.rela_idx;

        let rela_size = size_of::<Elf64RelaTable>() as u64;
        let section_size = self.section.header.sh_size.read(self.section.elf.endian);
        let rela_offset_in_section = (idx as u64).checked_mul(rela_size)?;
        let rela_end_in_section = rela_offset_in_section.checked_add(rela_size)?;

        if rela_end_in_section > section_size {
            return None;
        }

        let header_offset = self
            .section
            .header
            .sh_offset
            .read(self.section.elf.endian)
            .checked_add(rela_offset_in_section)?;

        let header = self
            .section
            .elf
            .checked_ref::<Elf64RelaTable>(header_offset)?;

        self.rela_idx += 1;
        Some(Elf64Rela {
            section: self.section,
            header,
        })
    }
}

pub struct Elf64Rela<'elf, 'data> {
    section: &'elf Elf64Section<'elf, 'data>,
    header: &'data Elf64RelaTable,
}

impl<'elf, 'data> Elf64Rela<'elf, 'data> {
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
}

#[derive(Debug)]
pub struct Elf64RelaInfo {
    pub sym: u32,
    pub ty: u32,
}

#[repr(C)]
pub struct Elf64RelaTable {
    r_offset: ElfEndianness<Elf64Addr>,   // Address of Reference
    r_info: ElfEndianness<Elf64Xword>,    // Symbol index and type of relocation
    r_addend: ElfEndianness<Elf64Sxword>, // Constant part of expression
}

pub struct Elf64SymbolIter<'elf, 'data> {
    section: &'elf Elf64Section<'elf, 'data>,
    sym_idx: u16,
}

impl<'elf, 'data> Iterator for Elf64SymbolIter<'elf, 'data> {
    type Item = Elf64Symbol<'elf, 'data>;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.sym_idx;

        let sym_size = size_of::<Elf64SymbolTable>() as u64;
        let section_size = self.section.header.sh_size.read(self.section.elf.endian);
        let sym_offset_in_section = (idx as u64).checked_mul(sym_size)?;
        let sym_end_in_section = sym_offset_in_section.checked_add(sym_size)?;

        if sym_end_in_section > section_size {
            return None;
        }

        let header_offset = self
            .section
            .header
            .sh_offset
            .read(self.section.elf.endian)
            .checked_add(sym_offset_in_section)?;

        let header = self
            .section
            .elf
            .checked_ref::<Elf64SymbolTable>(header_offset)?;

        self.sym_idx += 1;
        Some(Elf64Symbol {
            section: self.section,
            header,
        })
    }
}

pub struct Elf64Symbol<'elf, 'data> {
    section: &'elf Elf64Section<'elf, 'data>,
    header: &'data Elf64SymbolTable,
}

impl<'elf, 'data> Elf64Symbol<'elf, 'data> {
    pub fn name(&self) -> Result<&'data str> {
        let section = self
            .section
            .elf
            .get_section(self.section.header.sh_link.read(self.section.elf.endian) as u16)
            .context("Failed to get section header string table")?;
        unsafe {
            CStr::from_ptr(
                (self.section.elf.data.as_ptr() as u64
                    + section.header.sh_offset.read(self.section.elf.endian)
                    + self.header.st_name.read(self.section.elf.endian) as u64)
                    as *const c_char,
            )
            .to_str()
            .context("Symbol name is not valid UTF-8")
        }
    }

    pub fn section_idx(&self) -> Elf64SymbolSectionIdx {
        match self.header.st_shndx.read(self.section.elf.endian) {
            0 => Elf64SymbolSectionIdx::Undefined,
            0xFFF1 => Elf64SymbolSectionIdx::AbsoluteSymbols,
            0xFFF2 => Elf64SymbolSectionIdx::Common,
            idx => Elf64SymbolSectionIdx::Index(idx),
        }
    }

    pub fn value(&self) -> u64 {
        self.header.st_value.read(self.section.elf.endian)
    }

    pub fn size(&self) -> u64 {
        self.header.st_size.read(self.section.elf.endian)
    }

    pub fn info(&self) -> Elf64SymbolInfo {
        self.header.st_info
    }
}

#[derive(Debug)]
pub enum Elf64SymbolSectionIdx {
    Undefined,
    AbsoluteSymbols,
    Common,
    Index(u16),
}

struct ElfEndianness<T> {
    inner: T,
}

impl<T> ElfEndianness<T> {
    fn read(&self, endian: ElfEndian) -> T
    where
        T: RawReg,
    {
        match endian {
            ElfEndian::Big => self.inner.from_be(),
            ElfEndian::Little => self.inner.from_le(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(8))]
    struct AlignedBytes<const N: usize>([u8; N]);

    fn valid_elf_header_bytes() -> [u8; size_of::<Elf64Header>()] {
        let mut header: Elf64Header = unsafe { core::mem::zeroed() };
        header.e_ident.magic = [0x7F, b'E', b'L', b'F'];
        header.e_ident.class = 2;
        header.e_ident.data = 1;
        header.e_ident.version = 1;
        header.e_type = ElfEndianness {
            inner: ElfFileType::ET_EXEC,
        };
        header.e_machine = ElfEndianness {
            inner: ElfMachineType::EM_X86_64,
        };
        header.e_version = ElfEndianness { inner: 1 };
        header.e_ehsize = ElfEndianness {
            inner: size_of::<Elf64Header>() as u16,
        };
        header.e_phnum = ElfEndianness { inner: 1 };
        header.e_shnum = ElfEndianness { inner: 1 };

        let mut bytes = [0u8; size_of::<Elf64Header>()];
        unsafe {
            core::ptr::copy_nonoverlapping(
                (&header as *const Elf64Header).cast::<u8>(),
                bytes.as_mut_ptr(),
                bytes.len(),
            );
        }
        bytes
    }

    #[test]
    fn new_rejects_too_short_slice() {
        let err = Elf64::new(&[0u8; size_of::<Elf64Header>() - 1]).unwrap_err();

        assert_eq!(err.to_string(), "File too short");
    }

    #[test]
    fn new_rejects_misaligned_slice() {
        let header = valid_elf_header_bytes();
        let mut storage = AlignedBytes([0u8; size_of::<Elf64Header>() + 1]);
        storage.0[1..].copy_from_slice(&header);

        let err = Elf64::new(&storage.0[1..]).unwrap_err();

        assert_eq!(err.to_string(), "ELF header is not properly aligned");
    }

    #[test]
    fn new_accepts_aligned_header_buffer() {
        let mut storage = AlignedBytes([0u8; size_of::<Elf64Header>()]);
        storage.0.copy_from_slice(&valid_elf_header_bytes());

        let elf = Elf64::new(&storage.0).unwrap();

        assert_eq!(elf.arch(), ElfMachineType::EM_X86_64);
    }
}
