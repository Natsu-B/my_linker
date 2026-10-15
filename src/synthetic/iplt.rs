use std::collections::HashMap;

use anyhow::{Context, Result};
use elf::x86_64::X86_64RelocationType;

use crate::{
    input::object::InputSection,
    layout::{OutputSection, SectionIndex},
    symbols::{SymbolId, SymbolTable},
};

use super::{Got, GotEntry, SyntheticSection};

const STUB_SIZE: u64 = 16;
const RELA_SIZE: u64 = 24;

#[derive(Default)]
pub(crate) struct Iplt {
    entries: Vec<SymbolId>,
    offsets: HashMap<SymbolId, u64>,
}

impl Iplt {
    pub(crate) fn new(got: &Got) -> Self {
        let entries = got
            .entries()
            .filter_map(|(entry, _)| match entry {
                GotEntry::Ifunc(id) => Some(id),
                _ => None,
            })
            .collect::<Vec<_>>();
        let offsets = entries
            .iter()
            .enumerate()
            .map(|(index, id)| (*id, index as u64 * STUB_SIZE))
            .collect();
        Self { entries, offsets }
    }

    pub(crate) fn sections(&self) -> [InputSection<'static>; 2] {
        [
            SyntheticSection::Iplt.section(self.entries.len() as u64 * STUB_SIZE),
            SyntheticSection::RelaIplt.section(self.entries.len() as u64 * RELA_SIZE),
        ]
    }

    pub(crate) fn address(
        &self,
        id: SymbolId,
        sections: &[OutputSection],
        index: &SectionIndex,
    ) -> Result<u64> {
        SyntheticSection::Iplt
            .address(sections, index)?
            .checked_add(*self.offsets.get(&id).context("missing IFUNC IPLT stub")?)
            .context("IPLT stub address exceeds u64")
    }

    pub(crate) fn write(
        &self,
        sections: &mut [OutputSection],
        index: &SectionIndex,
        got: &Got,
        symbols: &SymbolTable,
    ) -> Result<()> {
        if self.entries.is_empty() {
            return Ok(());
        }
        let iplt_va = SyntheticSection::Iplt.address(sections, index)?;
        let got_va = SyntheticSection::Got.address(sections, index)?;
        for (entry, id) in self.entries.iter().enumerate() {
            let offset = entry as u64 * STUB_SIZE;
            let slot = got_va + got.offset(GotEntry::Ifunc(*id))?;
            let resolver = *symbols.get(*id).address.get().with_context(|| {
                format!(
                    "IFUNC resolver has no output address: {}",
                    symbols.get(*id).name
                )
            })?;
            pr_debug!(
                "IFUNC {}: resolver {resolver:#x}, stub {:#x}, GOT slot {slot:#x}",
                symbols.get(*id).name,
                iplt_va + offset
            );
            SyntheticSection::Iplt.write(
                sections,
                index,
                offset,
                &Self::stub(iplt_va + offset, slot)?,
            )?;
            SyntheticSection::RelaIplt.write(
                sections,
                index,
                entry as u64 * RELA_SIZE,
                &Self::irelative(slot, resolver),
            )?;
        }
        Ok(())
    }

    fn stub(address: u64, slot: u64) -> Result<[u8; STUB_SIZE as usize]> {
        // jmp *slot(%rip), followed by int3 padding.
        let displacement = i32::try_from(i128::from(slot) - i128::from(address) - 6)
            .context("IPLT GOT slot is outside the signed 32-bit displacement range")?;
        let mut bytes = [0xcc; STUB_SIZE as usize];
        bytes[..2].copy_from_slice(&[0xff, 0x25]);
        bytes[2..6].copy_from_slice(&displacement.to_le_bytes());
        Ok(bytes)
    }

    fn irelative(slot: u64, resolver: u64) -> [u8; RELA_SIZE as usize] {
        let mut bytes = [0; RELA_SIZE as usize];
        // Elf64_Rela: r_offset, r_info (symbol 0), r_addend (resolver).
        for (field, value) in
            bytes
                .chunks_exact_mut(8)
                .zip([slot, X86_64RelocationType::IRelative as u64, resolver])
        {
            field.copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_encodes_a_rip_relative_jump_and_padding() {
        let bytes = Iplt::stub(0x401000, 0x403008).unwrap();
        assert_eq!(&bytes[..6], &[0xff, 0x25, 0x02, 0x20, 0, 0]);
        assert_eq!(&bytes[6..], &[0xcc; 10]);
        let backwards = Iplt::stub(0x403000, 0x401008).unwrap();
        assert_eq!(
            i32::from_le_bytes(backwards[2..6].try_into().unwrap()),
            -0x1ffe
        );
    }

    #[test]
    fn stub_checks_signed_displacement_bounds() {
        assert!(Iplt::stub(0, 6 + i32::MAX as u64).is_ok());
        assert!(Iplt::stub(0, 7 + i32::MAX as u64).is_err());
        assert!(Iplt::stub(i32::MAX as u64 - 5, 0).is_ok());
        assert!(Iplt::stub(i32::MAX as u64 - 4, 0).is_err());
    }

    #[test]
    fn irelative_encodes_slot_type_and_resolver_without_a_symbol() {
        let bytes = Iplt::irelative(0x403008, 0x401234);
        assert_eq!(u64::from_le_bytes(bytes[..8].try_into().unwrap()), 0x403008);
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 37);
        assert_eq!(
            i64::from_le_bytes(bytes[16..].try_into().unwrap()),
            0x401234
        );
    }
}
