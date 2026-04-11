use anyhow::{Context, Result, ensure};
use elf::{
    self, Elf64RelaInfo, Elf64SectionFlags, Elf64SectionType, Elf64SymbolInfo,
    Elf64SymbolSectionIdx, ElfEndian, ElfFileType, ElfMachineType,
};
use memmap2::Mmap;

#[derive(Debug)]
pub struct ObjectFile<'a> {
    pub file_name: String,
    pub endian: ElfEndian,
    pub sections: Vec<ObjectSection<'a>>,
    pub symbols: Vec<ObjectSymbol<'a>>,
    pub relocations: Vec<ObjectRelocation>,
}

#[derive(Debug)]
pub struct ObjectSection<'a> {
    pub idx: u16,
    pub name: &'a str,
    pub ty: Elf64SectionType,
    pub flags: Elf64SectionFlags,
    pub align: u64,
    pub data: Option<&'a [u8]>,
    pub size: u64,
    pub relocations: Vec<ObjectRelocation>,
}

#[derive(Debug)]
pub struct ObjectSymbol<'a> {
    pub idx: Elf64SymbolSectionIdx,
    pub name: &'a str,
    pub info: Elf64SymbolInfo,
    pub value: u64,
    pub size: u64,
}

#[derive(Debug)]
pub struct ObjectRelocation {
    pub target_idx: u16,
    pub offset: u64,
    pub info: Elf64RelaInfo,
    pub addend: i64,
}

pub fn parse<'a>(mmap: &'a Mmap, file_name: String) -> Result<ObjectFile<'a>> {
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
                    idx: section.idx(),
                    name: section.name()?,
                    ty: section.section_type(),
                    flags: section.flags(),
                    align: section.align(),
                    data: section.data(),
                    size: section.size(),
                    relocations: Vec::new(),
                };
                object_file.sections.push(section);
            }
            Elf64SectionType::SHT_SYMTAB => {
                pr_debug!("  Type: SYMTAB");
                for symbol in section.symbols()? {
                    pr_debug!("    Symbol: {}", symbol.name()?);
                    let symbol = ObjectSymbol {
                        idx: symbol.section_idx(),
                        name: symbol.name()?,
                        info: symbol.info(),
                        value: symbol.value(),
                        size: symbol.size(),
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
                        target_idx: section.idx(),
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
