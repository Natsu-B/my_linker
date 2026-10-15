use std::{borrow::Cow, collections::HashMap};

use anyhow::{Context, Result};
use elf::{Elf64SectionFlags, Elf64SectionType, x86_64::X86_64RelocationType};

use crate::{
    input_id::FileId,
    parse::{ObjectRelocation, ObjectSection},
    resolve::{SymbolId, SymbolTable},
};

pub const SECTION_IDX: u16 = 0;
const ENTRY_SIZE: u64 = 8;

// IPLT stubs (M6) can reserve their slots here before section layout as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GotEntry {
    Address(SymbolId),
    TpOff(SymbolId),
}

#[derive(Default)]
pub struct Got {
    entries: Vec<GotEntry>,
    offsets: HashMap<GotEntry, u64>,
}

impl Got {
    pub fn needs_entry(ty: u32) -> bool {
        matches!(
            X86_64RelocationType::try_from(ty),
            Ok(X86_64RelocationType::GotPcRel
                | X86_64RelocationType::GotPcRelX
                | X86_64RelocationType::RexGotPcRelX
                | X86_64RelocationType::GotTpOff)
        )
    }

    pub fn collect(relocations: &[ObjectRelocation], symbols: &SymbolTable) -> Result<Self> {
        let mut got = Self::default();
        for relocation in relocations {
            let ty = X86_64RelocationType::try_from(relocation.info)?;
            if ty == X86_64RelocationType::None {
                continue;
            }
            let symbol = symbols.input(relocation.file_id, relocation.info.sym)?;
            symbols.get(symbol).validate_relocation(ty)?;
            if Self::needs_entry(relocation.info.ty) {
                let entry = if ty == X86_64RelocationType::GotTpOff {
                    GotEntry::TpOff(symbol)
                } else {
                    GotEntry::Address(symbol)
                };
                got.allocate(entry);
                pr_debug!(
                    "GOT entry for {} ({:?})",
                    symbols.get(symbol).name,
                    symbols.get(symbol).ty
                );
            }
        }
        Ok(got)
    }

    fn allocate(&mut self, entry: GotEntry) {
        if !self.offsets.contains_key(&entry) {
            let offset = self.entries.len() as u64 * ENTRY_SIZE;
            self.offsets.insert(entry, offset);
            self.entries.push(entry);
        }
    }

    pub fn entries(&self) -> impl Iterator<Item = (GotEntry, u64)> + '_ {
        self.entries
            .iter()
            .enumerate()
            .map(|(index, entry)| (*entry, index as u64 * ENTRY_SIZE))
    }

    pub fn offset(&self, entry: GotEntry) -> Result<u64> {
        self.offsets
            .get(&entry)
            .copied()
            .context("missing GOT entry for resolved symbol")
    }

    pub fn section(&self) -> ObjectSection<'static> {
        let data = vec![0; self.entries.len() * ENTRY_SIZE as usize];
        ObjectSection {
            file_id: FileId::Synthetic,
            idx: SECTION_IDX,
            name: ".got",
            ty: Elf64SectionType::SHT_PROGBITS,
            flags: Elf64SectionFlags::new()
                .set(Elf64SectionFlags::SHF_ALLOC, 1)
                .set(Elf64SectionFlags::SHF_WRITE, 1),
            align: ENTRY_SIZE,
            size: data.len() as u64,
            data: Some(Cow::Owned(data)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        parse, resolve,
        test_utils::{TestRelocation, TestSymbol, build_rel_object},
    };
    use elf::{Elf64SymbolBinding, Elf64SymbolType};

    fn symbol(binding: Elf64SymbolBinding, section_idx: u16) -> TestSymbol<'static> {
        TestSymbol {
            name: "foo",
            binding,
            ty: Elf64SymbolType::STT_OBJECT,
            section_idx,
            value: 0,
            size: 0,
        }
    }

    #[test]
    fn deduplicates_all_gotpcrel_kinds_by_resolved_symbol_across_files() {
        let definition = build_rel_object(&[symbol(Elf64SymbolBinding::STB_GLOBAL, 2)], &[]);
        let reference = build_rel_object(
            &[symbol(Elf64SymbolBinding::STB_GLOBAL, 0)],
            &[9, 41, 42].map(|ty| TestRelocation {
                offset: 0,
                sym: 1,
                ty,
                addend: -4,
            }),
        );
        let mut objects = [
            parse::parse(&definition, "def.o".to_string(), FileId::Object(0)).unwrap(),
            parse::parse(&reference, "a.o".to_string(), FileId::Object(1)).unwrap(),
            parse::parse(&reference, "b.o".to_string(), FileId::Object(2)).unwrap(),
        ];
        let symbols = objects
            .iter_mut()
            .flat_map(|object| std::mem::take(&mut object.symbols))
            .collect::<Vec<_>>();
        let relocations = objects
            .into_iter()
            .flat_map(|object| object.relocations)
            .collect::<Vec<_>>();
        let symbols = resolve::resolve_names(&symbols, &[]).unwrap();
        let got = Got::collect(&relocations, &symbols).unwrap();
        assert_eq!(got.entries().count(), 1);
        assert_eq!(got.section().size, 8);
        assert_eq!(got.section().align, 8);
        let flags = got.section().flags;
        assert_eq!(flags.get(Elf64SectionFlags::SHF_ALLOC), 1);
        assert_eq!(flags.get(Elf64SectionFlags::SHF_WRITE), 1);
        for file in 0..3 {
            assert_eq!(
                got.offset(GotEntry::Address(
                    symbols.input(FileId::Object(file), 1).unwrap()
                ))
                .unwrap(),
                0
            );
        }
    }

    #[test]
    fn local_symbols_with_equal_names_and_indexes_have_separate_slots() {
        let bytes = build_rel_object(
            &[symbol(Elf64SymbolBinding::STB_LOCAL, 2)],
            &[TestRelocation {
                offset: 0,
                sym: 1,
                ty: 42,
                addend: -4,
            }],
        );
        let mut objects = [
            parse::parse(&bytes, "a.o".to_string(), FileId::Object(0)).unwrap(),
            parse::parse(&bytes, "b.o".to_string(), FileId::Object(1)).unwrap(),
        ];
        let symbols = objects
            .iter_mut()
            .flat_map(|object| std::mem::take(&mut object.symbols))
            .collect::<Vec<_>>();
        let relocations = objects
            .into_iter()
            .flat_map(|object| object.relocations)
            .collect::<Vec<_>>();
        let symbols = resolve::resolve_names(&symbols, &[]).unwrap();
        let got = Got::collect(&relocations, &symbols).unwrap();
        assert_eq!(got.entries().count(), 2);
        assert_eq!(got.section().size, 16);
        assert_eq!(
            got.offset(GotEntry::Address(
                symbols.input(FileId::Object(0), 1).unwrap()
            ))
            .unwrap(),
            0
        );
        assert_eq!(
            got.offset(GotEntry::Address(
                symbols.input(FileId::Object(1), 1).unwrap()
            ))
            .unwrap(),
            8
        );
    }

    #[test]
    fn tls_offsets_are_deduplicated_separately_from_addresses() {
        let bytes = build_rel_object(&[symbol(Elf64SymbolBinding::STB_GLOBAL, 2)], &[]);
        let object = parse::parse(&bytes, "a.o".to_string(), FileId::Object(0)).unwrap();
        let symbols = resolve::resolve_names(&object.symbols, &[]).unwrap();
        let id = symbols.input(FileId::Object(0), 1).unwrap();
        let mut got = Got::default();
        for _ in 0..2 {
            got.allocate(GotEntry::Address(id));
            got.allocate(GotEntry::TpOff(id));
        }
        assert_eq!(got.offset(GotEntry::Address(id)).unwrap(), 0);
        assert_eq!(got.offset(GotEntry::TpOff(id)).unwrap(), 8);
        assert_eq!(got.section().size, 16);
    }
}
