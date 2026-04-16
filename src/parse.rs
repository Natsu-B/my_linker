use std::cell::OnceCell;

use anyhow::{Context, Result, ensure};
use elf::{
    self, Elf64RelaInfo, Elf64SectionFlags, Elf64SectionType, Elf64SymbolInfo,
    Elf64SymbolSectionIdx, ElfEndian, ElfFileType, ElfMachineType,
};
use memmap2::Mmap;

/// A parsed ELF relocatable object file (`ET_REL`).
///
/// This struct contains the subset of information needed by the linker stage:
/// section data, symbol table entries, and relocation entries extracted from
/// a single input object file.
#[derive(Debug)]
pub struct ObjectFile<'a> {
    /// Original input file name.
    pub file_name: String,

    /// Endianness of the ELF file.
    pub endian: ElfEndian,

    /// Loadable and allocatable sections collected from the object file.
    pub sections: Vec<ObjectSection<'a>>,

    /// Symbols defined or referenced by the object file.
    pub symbols: Vec<ObjectSymbol<'a>>,

    /// Relocation entries that must be applied during linking.
    pub relocations: Vec<ObjectRelocation>,
}

/// A section extracted from an ELF object file.
///
/// This represents one section such as `.text`, `.data`, or `.bss`,
/// together with its metadata and optional raw contents.
#[derive(Debug)]
pub struct ObjectSection<'a> {
    /// file idx
    pub file_idx: usize,

    /// Section index in the ELF section table.
    pub idx: u16,

    /// Section name from the section string table.
    pub name: &'a str,

    /// ELF section type.
    pub ty: Elf64SectionType,

    /// ELF section flags such as alloc, write, or execute.
    pub flags: Elf64SectionFlags,

    /// Required alignment of the section in bytes.
    pub align: u64,

    /// Raw section contents.
    ///
    /// This is `None` for `SHT_NOBITS` sections such as `.bss`,
    /// because they occupy memory but do not have bytes in the file.
    pub data: Option<&'a [u8]>,

    /// Total section size in bytes.
    pub size: u64,
}

/// A symbol entry from the ELF symbol table.
///
/// Symbols may represent definitions, undefined references, section symbols,
/// file symbols, or other linker-visible entities.
#[derive(Debug)]
pub struct ObjectSymbol<'a> {
    /// file idx
    pub file_idx: usize,

    /// Index of the symbol in the symbol table.
    pub idx: u16,

    /// Section index associated with the symbol.
    ///
    /// This indicates where the symbol is defined, or whether it is undefined,
    /// absolute, common, and so on.
    pub section_idx: Elf64SymbolSectionIdx,

    /// Symbol name from the symbol string table.
    pub name: &'a str,

    /// ELF symbol metadata, including binding and type.
    pub info: Elf64SymbolInfo,

    /// Symbol value as stored in the object file.
    ///
    /// For relocatable objects, this is usually an offset within the defining
    /// section rather than a final virtual address.
    pub value: u64,

    /// Size of the symbol in bytes.
    pub size: u64,

    /// Virtual address of the symbol after linking.
    pub va: OnceCell<u64>,
}

/// A relocation entry extracted from a relocation section.
///
/// Each relocation describes how a value at some location in a target section
/// must be adjusted once symbol addresses are known.
#[derive(Debug)]
pub struct ObjectRelocation {
    /// file idx
    pub file_idx: usize,

    /// Index of the relocation section that contains this entry.
    pub reloc_section_idx: u16,

    /// Index of the section to which this relocation applies.
    pub target_idx: u32,

    /// Offset within the target section where the relocation is applied.
    pub offset: u64,

    /// Relocation metadata, including referenced symbol index and relocation type.
    pub info: Elf64RelaInfo,

    /// Explicit addend stored in the relocation entry.
    pub addend: i64,
}

pub fn parse<'a>(mmap: &'a [u8], file_name: String, file_idx: usize) -> Result<ObjectFile<'a>> {
    let elf = elf::Elf64::new(mmap)
        .with_context(|| format!("failed to parse ELF file: {}", file_name))?;

    // check if the file is an ELF64 x86_64 relocatable file
    ensure!(
        elf.arch() == ElfMachineType::EM_X86_64,
        "unsupported architecture: {:?} in file: {}",
        elf.arch(),
        file_name
    );
    ensure!(
        elf.elf_type() == ElfFileType::ET_REL,
        "unsupported file type: {:?} in file: {}",
        elf.elf_type(),
        file_name
    );

    let mut object_file: ObjectFile<'a> = ObjectFile {
        file_name: file_name,
        endian: elf.endian(),
        sections: Vec::new(),
        symbols: Vec::new(),
        relocations: Vec::new(),
    };

    for section in elf.sections() {
        pr_debug!("Section: {}", section.name()?);
        match section.section_type() {
            Elf64SectionType::SHT_NULL => pr_debug!("  Type: NULL"),
            Elf64SectionType::SHT_PROGBITS | Elf64SectionType::SHT_NOBITS => {
                if section.section_type() == Elf64SectionType::SHT_PROGBITS {
                    pr_debug!("  Type: PROGBITS");
                } else {
                    pr_debug!("  Type: NOBITS");
                }
                let section = ObjectSection::<'a> {
                    file_idx,
                    idx: section.idx(),
                    name: section.name()?,
                    ty: section.section_type(),
                    flags: section.flags(),
                    align: section.align(),
                    data: section.data(),
                    size: section.size(),
                };
                object_file.sections.push(section);
            }
            Elf64SectionType::SHT_SYMTAB => {
                pr_debug!("  Type: SYMTAB");
                for (i, symbol) in section.symbols()?.enumerate() {
                    pr_debug!("    Symbol: {}", symbol.name()?);
                    let symbol = ObjectSymbol {
                        file_idx,
                        idx: i as u16,
                        section_idx: symbol.section_idx(),
                        name: symbol.name()?,
                        info: symbol.info(),
                        value: symbol.value(),
                        size: symbol.size(),
                        va: OnceCell::new(),
                    };
                    object_file.symbols.push(symbol);
                }
            }
            Elf64SectionType::SHT_STRTAB => pr_debug!("  Type: STRTAB"),
            Elf64SectionType::SHT_RELA => {
                pr_debug!("  Type: RELA");
                for relocation in section.rela()? {
                    pr_debug!(
                        "    Relocation: offset={:#x}, info={:?}, addend={}",
                        relocation.offset(),
                        relocation.info(),
                        relocation.addend()
                    );
                    let relocation = ObjectRelocation {
                        file_idx,
                        target_idx: relocation.target_idx(),
                        reloc_section_idx: section.idx(),
                        offset: relocation.offset(),
                        info: relocation.info(),
                        addend: relocation.addend(),
                    };
                    object_file.relocations.push(relocation);
                }
            }
            Elf64SectionType::SHT_REL => {
                pr_debug!("  Type: REL");
                todo!()
            }
            Elf64SectionType::SHT_NOTE => pr_debug!("  Type: NOTE"),
            _ => pr_debug!("  Type: Other({:?})", section.section_type()),
        }
    }

    Ok(object_file)
}
