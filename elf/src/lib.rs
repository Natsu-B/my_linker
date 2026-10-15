pub mod abi;
pub mod read;
pub mod write;
pub mod x86_64;

/// Lets callers read raw bits (`to_raw`) from the bit-register types below.
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
