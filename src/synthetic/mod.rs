mod got;
mod iplt;

pub(crate) use got::{Got, GotEntry};
pub(crate) use iplt::Iplt;

use std::borrow::Cow;

use anyhow::{Context, Result};
use elf::{Elf64SectionFlags, Elf64SectionType, Elf64SymbolInfo, Elf64SymbolType};

use crate::{
    input::{
        FileId,
        object::{InputSection, ObjectRelocation, ObjectSymbol},
    },
    layout::{OutputSection, SectionIndex, SectionLocation},
    script::mapping::{MappingInput, SectionMapping},
    symbols::SymbolTable,
};

pub(crate) struct SyntheticSections<'a, 's> {
    pub(crate) mapping: SectionMapping<'a, 's>,
    pub(crate) got: Got,
    pub(crate) iplt: Iplt,
}

/// Reserve stable input identities and attributes before script mapping.
/// Only sizes and contents change after resolution; script matching does not.
pub(crate) fn reserve_inputs(
    inputs: &mut Vec<MappingInput>,
    symbols: &[ObjectSymbol],
    relocations: &[ObjectRelocation],
) {
    let has_ifunc = symbols.iter().any(|symbol| {
        symbol.info.get_enum(Elf64SymbolInfo::st_type) == Some(Elf64SymbolType::STT_GNU_IFUNC)
    });
    let needs_got = has_ifunc
        || relocations
            .iter()
            .any(|relocation| Got::needs_entry(relocation.info.ty));
    for section in SyntheticSection::ALL {
        let needed = match section {
            SyntheticSection::Got => needs_got,
            SyntheticSection::Iplt | SyntheticSection::RelaIplt => has_ifunc,
        };
        if needed {
            inputs.push(MappingInput {
                file_name: "<linker>".to_string(),
                section: section.section(0),
            });
        }
    }
}

pub(crate) fn build<'a, 's>(
    mut mapping: SectionMapping<'a, 's>,
    symbols: &SymbolTable,
) -> Result<SyntheticSections<'a, 's>> {
    let got = Got::collect(&mapping.relocations, symbols)?;
    let iplt = Iplt::new(&got);
    for section in [got.section()].into_iter().chain(iplt.sections()) {
        if let Some(input) = mapping.inputs.iter_mut().find(|input| {
            input.section.file_id == FileId::LinkerGenerated && input.section.idx == section.idx
        }) {
            input.section = section;
        }
    }
    Ok(SyntheticSections { mapping, got, iplt })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SyntheticSection {
    Got = 0,
    Iplt = 1,
    RelaIplt = 2,
}

impl SyntheticSection {
    pub(crate) const ALL: [Self; 3] = [Self::Got, Self::Iplt, Self::RelaIplt];

    pub(crate) fn is_input(self, input: &InputSection) -> bool {
        input.file_id == FileId::LinkerGenerated && input.idx == self as u16
    }

    pub(crate) fn section(self, size: u64) -> InputSection<'static> {
        let (name, align) = match self {
            Self::Got => (".got", 8),
            Self::Iplt => (".iplt", 16),
            Self::RelaIplt => (".rela.iplt", 8),
        };
        InputSection {
            file_id: FileId::LinkerGenerated,
            idx: self as u16,
            name,
            flags: Elf64SectionFlags::new()
                .set(Elf64SectionFlags::SHF_ALLOC, 1)
                .set(Elf64SectionFlags::SHF_WRITE, u64::from(self == Self::Got))
                .set(
                    Elf64SectionFlags::SHF_EXECINSTR,
                    u64::from(self == Self::Iplt),
                ),
            section_type: if self == Self::RelaIplt {
                Elf64SectionType::SHT_RELA
            } else {
                Elf64SectionType::SHT_PROGBITS
            },
            entry_size: match self {
                Self::Got => 8,
                Self::Iplt => 16,
                Self::RelaIplt => 24,
            },
            align,
            size,
            data: Some(Cow::Owned(vec![0; size as usize])),
        }
    }

    pub(crate) fn location(self, index: &SectionIndex) -> Result<&SectionLocation> {
        index
            .get(&(FileId::LinkerGenerated, self as u16))
            .with_context(|| format!("synthetic {self:?} input section was discarded"))
    }

    pub(crate) fn address(self, sections: &[OutputSection], index: &SectionIndex) -> Result<u64> {
        let location = self.location(index)?;
        sections[location.output_idx]
            .address
            .get()
            .context("synthetic output section has no address")?
            .checked_add(location.offset)
            .context("synthetic input address exceeds u64")
    }

    pub(crate) fn write(
        self,
        sections: &mut [OutputSection],
        index: &SectionIndex,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        let location = self.location(index)?;
        let offset = location
            .offset
            .checked_add(offset)
            .and_then(|offset| usize::try_from(offset).ok())
            .context("synthetic section offset exceeds usize")?;
        let end = offset
            .checked_add(bytes.len())
            .context("synthetic section write exceeds usize")?;
        sections[location.output_idx]
            .data
            .as_mut()
            .context("synthetic output section has no data")?
            .get_mut(offset..end)
            .context("synthetic section write out of bounds")?
            .copy_from_slice(bytes);
        Ok(())
    }
}
