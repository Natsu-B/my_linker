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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfEndian {
    Big,
    Little,
}

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

#[repr(transparent)]
#[derive(Clone, Copy, Debug, RawReg, PartialEq, Eq)]
pub struct ElfFileType(pub(crate) Elf64Half);

impl ElfFileType {
    pub const ET_REL: Self = Self(1);
    pub const ET_EXEC: Self = Self(2);
    pub const ET_DYN: Self = Self(3);
    pub const ET_CORE: Self = Self(4);

    pub const fn raw(self) -> u16 {
        self.0
    }
}

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

#[repr(transparent)]
#[derive(Clone, Copy, Debug, RawReg, PartialEq, Eq)]
pub struct ElfProgramHeaderType(pub(crate) Elf64Word);

impl ElfProgramHeaderType {
    pub const PT_NULL: Self = Self(0);
    pub const PT_LOAD: Self = Self(1);
    pub const PT_DYNAMIC: Self = Self(2);
    pub const PT_INTERP: Self = Self(3);
    pub const PT_NOTE: Self = Self(4);
    pub const PT_SHLIB: Self = Self(5);
    pub const PT_PHDR: Self = Self(6);

    pub const fn raw(self) -> u32 {
        self.0
    }
}

pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

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

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Elf64SectionHeaderData {
    pub(crate) sh_name: ElfEndianness<Elf64Word>,
    pub(crate) sh_type: ElfEndianness<Elf64SectionType>,
    pub(crate) sh_flags: ElfEndianness<Elf64SectionFlags>,
    pub(crate) sh_addr: ElfEndianness<Elf64Addr>,
    pub(crate) sh_offset: ElfEndianness<Elf64Off>,
    pub(crate) sh_size: ElfEndianness<Elf64Xword>,
    pub(crate) sh_link: ElfEndianness<Elf64Word>,
    pub(crate) sh_info: ElfEndianness<Elf64Word>,
    pub(crate) sh_addralign: ElfEndianness<Elf64Xword>,
    pub(crate) sh_entsize: ElfEndianness<Elf64Xword>,
}

#[repr(transparent)]
#[derive(Clone, Copy, RawReg, PartialEq, Eq, Debug)]
pub struct Elf64SectionType(pub(crate) Elf64Word);

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
    pub const SHT_LOPROC: Self = Self(0x7000_0000);
    pub const SHT_HIPROC: Self = Self(0x7FFF_FFFF);
    pub const SHT_LOUSER: Self = Self(0x8000_0000);
    pub const SHT_HIUSER: Self = Self(0xFFFF_FFFF);

    pub const fn raw(self) -> u32 {
        self.0
    }
}

bitregs! {
    pub struct Elf64SectionFlags: Elf64Xword {
        pub SHF_WRITE@[0:0],
        pub SHF_ALLOC@[1:1],
        pub SHF_EXECINSTR@[2:2],
        reserved@[63:3],
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Elf64SymbolTable {
    pub(crate) st_name: ElfEndianness<Elf64Word>,
    pub(crate) st_info: Elf64SymbolInfo,
    pub(crate) st_other: u8,
    pub(crate) st_shndx: ElfEndianness<Elf64Half>,
    pub(crate) st_value: ElfEndianness<Elf64Addr>,
    pub(crate) st_size: ElfEndianness<Elf64Xword>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Elf64SymbolSectionIdx {
    Undefined,
    AbsoluteSymbols,
    Common,
    Index(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elf64RelaInfo {
    pub sym: u32,
    pub ty: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Elf64RelaTable {
    pub(crate) r_offset: ElfEndianness<Elf64Addr>,
    pub(crate) r_info: ElfEndianness<Elf64Xword>,
    pub(crate) r_addend: ElfEndianness<Elf64Sxword>,
}

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
