//! Read ELF64 records and write an executable into a byte buffer.
//!
//! [`read::Elf64`] borrows bytes and gives access to headers, sections, symbols,
//! and RELA relocations. [`write::ExecElf64Writer`] takes segment and section
//! records and fills a caller's buffer. [`abi`] defines the file fields;
//! [`x86_64`] names relocation kinds.
//!
//! ELF has two views of the same file: sections for the linker and segments for
//! the loader. This crate reads and writes those views. The linker crate picks
//! inputs and follows GNU ld script rules. The reader accepts both byte orders;
//! the writer accepts only little-endian x86-64.
//!
//! References: [ELF gABI], "ELF Header", "Sections", "String Table", "Symbol Table",
//! "Relocation", and "Program Loading"; [AMD64 psABI] §§4–5.
//!
//! [ELF gABI]: https://gabi.xinuos.com/elf.pdf
//! [AMD64 psABI]: https://gitlab.com/x86-psABIs/x86-64-ABI

pub mod abi;
pub mod read;
pub mod write;
pub mod x86_64;

/// Let callers get the raw bits from ELF bit-field types.
pub use typestate::RawReg;

pub use abi::{
    Elf64RelaInfo, Elf64SectionFlags, Elf64SectionType, Elf64SymbolBinding, Elf64SymbolInfo,
    Elf64SymbolSectionIdx, Elf64SymbolType, ElfEndian, ElfFileType, ElfMachineType,
    ElfProgramHeaderType, PF_R, PF_W, PF_X, SHN_ABS, SHN_COMMON, SHN_LORESERVE, SHN_UNDEF,
};
pub use read::{
    Elf64, Elf64ProgramHeader, Elf64ProgramHeaderIter, Elf64Rela, Elf64RelaIter, Elf64Section,
    Elf64SectionIter, Elf64Symbol, Elf64SymbolIter,
};
pub use write::{Elf64ProgramHeaderFlags, ExecElf64Writer, LoadSegment, ProgramHeader};
