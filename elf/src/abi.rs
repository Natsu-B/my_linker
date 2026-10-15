//! Define the fields and numbers stored in ELF64 files.
//!
//! The reader copies raw C-layout records, then `ElfEndianness` reads their
//! fields in the file's byte order. Numeric wrapper types keep unknown tag
//! values so the caller can report them. Bit fields split flags and symbol info.
//!
//! A symbol's section index is not always a section number.
//! [`Elf64SymbolSectionIdx`] also covers SHN_UNDEF (no definition),
//! SHN_ABS (an absolute value), and SHN_COMMON (storage to allocate).
//! These types describe ELF; the linker supports only part of the format.
//!
//! References: ELF gABI "Data Representation", "ELF Header", "Sections",
//! "Symbol Table", and "Relocation"; AMD64 psABI §§4.1–4.4.

#![allow(non_camel_case_types)]

use core::mem::size_of;
use typestate::{RawReg, bitregs};
use typestate_macro::RawReg;

pub(crate) type Elf64Addr = u64;
pub(crate) type Elf64Off = u64;
pub(crate) type Elf64Half = u16;
pub(crate) type Elf64Word = u32;
pub(crate) type Elf64Xword = u64;
pub(crate) type Elf64Sxword = i64;

/// EI_DATA chooses how to read every multi-byte field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfEndian {
    Big,
    Little,
}

/// Read these bytes first: the class and byte order give meaning to the rest.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ElfHeaderIdent {
    pub(crate) magic: [u8; 4],
    pub(crate) class: u8,
    pub(crate) data: u8,
    pub(crate) version: u8,
    pub(crate) os_abi: u8,
    pub(crate) abi_version: u8,
    pub(crate) reserved: [u8; 7],
}

/// Match the ELF64 header's field offsets; decode byte order only when reading.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Elf64Header {
    pub(crate) e_ident: ElfHeaderIdent,
    pub(crate) e_type: ElfEndianness<ElfFileType>,
    pub(crate) e_machine: ElfEndianness<ElfMachineType>,
    pub(crate) e_version: ElfEndianness<Elf64Word>,
    pub(crate) e_entry: ElfEndianness<Elf64Addr>,
    pub(crate) e_phoff: ElfEndianness<Elf64Off>,
    pub(crate) e_shoff: ElfEndianness<Elf64Off>,
    pub(crate) e_flags: ElfEndianness<Elf64Word>,
    pub(crate) e_ehsize: ElfEndianness<Elf64Half>,
    pub(crate) e_phentsize: ElfEndianness<Elf64Half>,
    pub(crate) e_phnum: ElfEndianness<Elf64Half>,
    pub(crate) e_shentsize: ElfEndianness<Elf64Half>,
    pub(crate) e_shnum: ElfEndianness<Elf64Half>,
    pub(crate) e_shstrndx: ElfEndianness<Elf64Half>,
}

/// Keep unknown e_type numbers so errors can show the file's actual value.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, RawReg, PartialEq, Eq)]
pub struct ElfFileType(pub(crate) Elf64Half);

impl ElfFileType {
    /// Relocatable input: definitions and patch sites usually use section offsets.
    pub const ET_REL: Self = Self(1);
    /// Executable with fixed virtual addresses.
    pub const ET_EXEC: Self = Self(2);
    /// Shared object or position-independent executable.
    pub const ET_DYN: Self = Self(3);
    /// A saved process image.
    pub const ET_CORE: Self = Self(4);

    pub const fn raw(self) -> u16 {
        self.0
    }
}

/// Keep e_machine as a number; each caller checks which machines it supports.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, RawReg, PartialEq, Eq)]
pub struct ElfMachineType(pub(crate) Elf64Half);

impl ElfMachineType {
    pub const EM_X86_64: Self = Self(62);
    pub const EM_AARCH64: Self = Self(183);

    pub const fn raw(self) -> u16 {
        self.0
    }
}

/// p_type says how a loader should use a segment; GNU adds types such as GNU_STACK.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, RawReg, PartialEq, Eq)]
pub struct ElfProgramHeaderType(pub(crate) Elf64Word);

impl ElfProgramHeaderType {
    pub const PT_NULL: Self = Self(0);
    /// Map a file prefix into memory and zero any remaining tail.
    pub const PT_LOAD: Self = Self(1);
    /// Locate the records used for dynamic linking.
    pub const PT_DYNAMIC: Self = Self(2);
    /// Name the program loader to run before the entry point.
    pub const PT_INTERP: Self = Self(3);
    pub const PT_NOTE: Self = Self(4);
    pub const PT_SHLIB: Self = Self(5);
    /// Locate the program-header table in memory.
    pub const PT_PHDR: Self = Self(6);
    /// Describe the initial bytes and zero fill for each thread's TLS block.
    pub const PT_TLS: Self = Self(7);
    /// Tell the kernel the stack permissions; this header has no file bytes.
    pub const PT_GNU_STACK: Self = Self(0x6474_e551);

    pub const fn raw(self) -> u32 {
        self.0
    }
}

pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

/// A segment's file range, memory range, flags, and alignment in the ELF byte order.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Elf64ProgramHeader {
    pub(crate) p_type: ElfEndianness<ElfProgramHeaderType>,
    pub(crate) p_flags: ElfEndianness<Elf64Word>,
    pub(crate) p_offset: ElfEndianness<Elf64Off>,
    pub(crate) p_vaddr: ElfEndianness<Elf64Addr>,
    pub(crate) p_paddr: ElfEndianness<Elf64Addr>,
    pub(crate) p_filesz: ElfEndianness<Elf64Xword>,
    pub(crate) p_memsz: ElfEndianness<Elf64Xword>,
    pub(crate) p_align: ElfEndianness<Elf64Xword>,
}

/// A section record as stored in the file; sh_type sets the meaning of link and info.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Elf64SectionHeaderData {
    pub(crate) sh_name: ElfEndianness<Elf64Word>,
    pub(crate) sh_type: ElfEndianness<Elf64SectionType>,
    pub(crate) sh_flags: ElfEndianness<Elf64SectionFlags>,
    pub(crate) sh_addr: ElfEndianness<Elf64Addr>,
    pub(crate) sh_offset: ElfEndianness<Elf64Off>,
    pub(crate) sh_size: ElfEndianness<Elf64Xword>,
    /// For a symbol table, this names its string table; meaning depends on sh_type.
    pub(crate) sh_link: ElfEndianness<Elf64Word>,
    /// For RELA, the target section; for SYMTAB, the first non-local symbol index.
    pub(crate) sh_info: ElfEndianness<Elf64Word>,
    /// Required alignment; zero and one mean no constraint.
    pub(crate) sh_addralign: ElfEndianness<Elf64Xword>,
    /// Bytes per entry, or zero for data without fixed-size records.
    pub(crate) sh_entsize: ElfEndianness<Elf64Xword>,
}

/// sh_type tells the reader how to use a section's data and linked tables.
#[repr(transparent)]
#[derive(Clone, Copy, RawReg, PartialEq, Eq, Debug)]
pub struct Elf64SectionType(pub(crate) Elf64Word);

impl Elf64SectionType {
    /// ELF reserves section zero as the null entry.
    pub const SHT_NULL: Self = Self(0);
    /// Store ordinary bytes in the file.
    pub const SHT_PROGBITS: Self = Self(1);
    /// The full symbol table used by tools such as nm.
    pub const SHT_SYMTAB: Self = Self(2);
    /// NUL-terminated names, addressed by byte offset.
    pub const SHT_STRTAB: Self = Self(3);
    /// Store each relocation's signed addend in the record.
    pub const SHT_RELA: Self = Self(4);
    pub const SHT_HASH: Self = Self(5);
    pub const SHT_DYNAMIC: Self = Self(6);
    pub const SHT_NOTE: Self = Self(7);
    /// Reserve memory without storing bytes in the file, as for .bss.
    pub const SHT_NOBITS: Self = Self(8);
    /// Read addends from the target bytes; this linker rejects this format.
    pub const SHT_REL: Self = Self(9);
    pub const SHT_SHLIB: Self = Self(10);
    /// The symbol table used for dynamic lookup.
    pub const SHT_DYNSYM: Self = Self(11);
    /// Function pointers run during startup.
    pub const SHT_INIT_ARRAY: Self = Self(14);
    /// Function pointers run at exit.
    pub const SHT_FINI_ARRAY: Self = Self(15);
    /// Function pointers run before other executable initializers.
    pub const SHT_PREINIT_ARRAY: Self = Self(16);
    /// Start of the processor-specific section-type range.
    pub const SHT_LOPROC: Self = Self(0x7000_0000);
    /// End of the processor-specific section-type range.
    pub const SHT_HIPROC: Self = Self(0x7FFF_FFFF);
    /// Start of the application's section-type range.
    pub const SHT_LOUSER: Self = Self(0x8000_0000);
    /// End of the application's section-type range.
    pub const SHT_HIUSER: Self = Self(0xFFFF_FFFF);

    pub const fn raw(self) -> u32 {
        self.0
    }
}

bitregs! {
    /// ALLOC puts a section in memory; WRITE and EXECINSTR set its load permissions.
    ///
    /// MERGE and STRINGS describe its entries. TLS marks bytes each thread needs.
    /// INFO_LINK makes sh_info a section index, as for a relocation target.
    pub struct Elf64SectionFlags: Elf64Xword {
        pub SHF_WRITE@[0:0],
        pub SHF_ALLOC@[1:1],
        pub SHF_EXECINSTR@[2:2],
        reserved@[3:3] [ignore],
        pub SHF_MERGE@[4:4],
        pub SHF_STRINGS@[5:5],
        pub SHF_INFO_LINK@[6:6],
        reserved@[9:7] [ignore],
        pub SHF_TLS@[10:10],
        reserved@[63:11] [ignore],
    }
}

/// No defining section: a symbol reference still needs a definition.
pub const SHN_UNDEF: u16 = 0;
/// Larger section indices need ELF's extended-index scheme.
pub const SHN_LORESERVE: u16 = 0xff00;
/// The symbol value is absolute and does not move with a section.
pub const SHN_ABS: u16 = 0xfff1;
/// The symbol asks the linker to allocate storage; this linker rejects it.
pub const SHN_COMMON: u16 = 0xfff2;

/// One symbol's name offset, kind, binding, section, value, and size in the file.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Elf64SymbolTable {
    pub(crate) st_name: ElfEndianness<Elf64Word>,
    pub(crate) st_info: Elf64SymbolInfo,
    pub(crate) st_other: u8,
    pub(crate) st_shndx: ElfEndianness<Elf64Half>,
    /// A section offset in ET_REL, an address in ET_EXEC, or a TLS template offset.
    pub(crate) st_value: ElfEndianness<Elf64Addr>,
    pub(crate) st_size: ElfEndianness<Elf64Xword>,
}

bitregs! {
    /// Split st_info into type and binding.
    ///
    /// LOCAL names belong to one file. GLOBAL and WEAK names join references across
    /// files. A TLS symbol's value in an executable is a template offset. An IFUNC
    /// symbol's value names a resolver, not the final function.
    pub struct Elf64SymbolInfo:u8 {
        pub st_type@[3:0] as Elf64SymbolType {
            STT_NOTYPE = 0,
            STT_OBJECT = 1,
            STT_FUNC = 2,
            STT_SECTION = 3,
            STT_FILE = 4,
            STT_TLS = 6,
            STT_GNU_IFUNC = 10,
            STT_HIOS = 12,
            STT_LOPROC = 13,
            STT_HIPROC = 15,
        },
        pub st_bind@[7:4] as Elf64SymbolBinding {
            STB_LOCAL = 0,
            STB_GLOBAL = 1,
            STB_WEAK = 2,
            STB_LOOS = 10,
            STB_HIOS = 12,
            STB_LOPROC = 13,
            STB_HIPROC = 15,
        },
    }
}

impl Elf64SymbolType {
    /// GNU_IFUNC uses the first OS-specific symbol-type value.
    pub const STT_LOOS: Self = Self::STT_GNU_IFUNC;
}

/// Separate real section numbers from ELF's special symbol meanings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Elf64SymbolSectionIdx {
    /// SHN_UNDEF: no definition in this file.
    Undefined,
    /// SHN_ABS: keep the value without adding a section address.
    AbsoluteSymbols,
    /// SHN_COMMON: storage to allocate, not an input section.
    Common,
    Index(u16),
}

/// Split r_info: the upper 32 bits select a symbol, the lower 32 bits give the kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elf64RelaInfo {
    pub sym: u32,
    pub ty: u32,
}

/// A patch site, symbol and kind, and signed addend; the target bytes hold no addend.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Elf64RelaTable {
    /// A target-section offset in ET_REL, or a virtual address in ET_EXEC.
    pub(crate) r_offset: ElfEndianness<Elf64Addr>,
    pub(crate) r_info: ElfEndianness<Elf64Xword>,
    pub(crate) r_addend: ElfEndianness<Elf64Sxword>,
}

/// Keep raw bits until EI_DATA tells the reader which byte order to use.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub(crate) struct ElfEndianness<T> {
    pub(crate) inner: T,
}

impl<T> ElfEndianness<T> {
    pub(crate) fn read(&self, endian: ElfEndian) -> T
    where
        T: RawReg,
    {
        match endian {
            ElfEndian::Big => self.inner.from_be(),
            ElfEndian::Little => self.inner.from_le(),
        }
    }
}

#[allow(clippy::assertions_on_constants)]
const _: () = assert!(size_of::<Elf64Header>() == 64);
const _: () = assert!(size_of::<Elf64ProgramHeader>() == 56);
const _: () = assert!(size_of::<Elf64SectionHeaderData>() == 64);
const _: () = assert!(size_of::<Elf64SymbolTable>() == 24);
const _: () = assert!(size_of::<Elf64RelaTable>() == 24);
