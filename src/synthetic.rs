use std::borrow::Cow;

use anyhow::{Context, Result};
use elf::{Elf64SectionFlags, Elf64SectionType};

use crate::{
    input_id::FileId,
    link::{SectionIndex, SectionLocation, SectionPlacement},
    parse::ObjectSection,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyntheticSection {
    Got = 0,
    Iplt = 1,
    RelaIplt = 2,
}

impl SyntheticSection {
    pub const ALL: [Self; 3] = [Self::Got, Self::Iplt, Self::RelaIplt];

    pub fn section(self, size: u64) -> ObjectSection<'static> {
        let (name, ty, align) = match self {
            Self::Got => (".got", Elf64SectionType::SHT_PROGBITS, 8),
            Self::Iplt => (".iplt", Elf64SectionType::SHT_PROGBITS, 16),
            Self::RelaIplt => (".rela.iplt", Elf64SectionType::SHT_RELA, 8),
        };
        ObjectSection {
            file_id: FileId::Synthetic,
            idx: self as u16,
            name,
            ty,
            flags: Elf64SectionFlags::new()
                .set(Elf64SectionFlags::SHF_ALLOC, 1)
                .set(Elf64SectionFlags::SHF_WRITE, u64::from(self == Self::Got))
                .set(
                    Elf64SectionFlags::SHF_EXECINSTR,
                    u64::from(self == Self::Iplt),
                ),
            align,
            size,
            data: Some(Cow::Owned(vec![0; size as usize])),
        }
    }

    pub fn location(self, index: &SectionIndex) -> Result<&SectionLocation> {
        index
            .get(&(FileId::Synthetic, self as u16))
            .with_context(|| format!("synthetic {self:?} input section was discarded"))
    }

    pub fn address(self, sections: &[SectionPlacement], index: &SectionIndex) -> Result<u64> {
        let location = self.location(index)?;
        sections[location.output_idx]
            .va
            .get()
            .context("synthetic output section has no address")?
            .checked_add(location.offset)
            .context("synthetic input address exceeds u64")
    }

    pub fn write(
        self,
        sections: &mut [SectionPlacement],
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
