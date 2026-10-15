use std::{cell::OnceCell, collections::HashMap};

use anyhow::{Context, Result, ensure};
use elf::{
    Elf64SymbolBinding, Elf64SymbolSectionIdx, Elf64SymbolType, x86_64::X86_64RelocationType,
};

use crate::{
    input::FileId,
    layout::{OutputSection, SectionIndex},
    script::ast::{Assignment, AssignmentKind, Location},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SymbolId(usize);

#[derive(Debug, Clone, Copy)]
pub(crate) enum Definition {
    Input {
        file_id: FileId,
        section_idx: Elf64SymbolSectionIdx,
        value: u64,
    },
    Script {
        provide: Option<Location>,
    },
    UndefinedWeak,
}

#[derive(Debug)]
pub(crate) struct ResolvedSymbol {
    pub(crate) name: String,
    pub(crate) ty: Option<Elf64SymbolType>,
    pub(crate) definition: Definition,
    pub(crate) binding: Elf64SymbolBinding,
    pub(crate) size: u64,
    pub(crate) other: u8,
    pub(crate) address: OnceCell<u64>,
}

impl ResolvedSymbol {
    pub(crate) fn is_ifunc(&self) -> bool {
        self.ty == Some(Elf64SymbolType::STT_GNU_IFUNC)
            && matches!(self.definition, Definition::Input { .. })
    }

    pub(crate) fn validate_relocation(&self, ty: X86_64RelocationType) -> Result<()> {
        use X86_64RelocationType::*;
        ensure!(
            !matches!(
                ty,
                TlsGd
                    | TlsLd
                    | DtpMod64
                    | DtpOff32
                    | DtpOff64
                    | GotPc32TlsDesc
                    | TlsDescCall
                    | TlsDesc
            ),
            "unsupported TLS model: {ty:?} for symbol: {} (only local-exec and initial-exec are supported)",
            self.name
        );
        let tls = matches!(ty, TpOff32 | TpOff64 | GotTpOff);
        ensure!(
            tls || self.ty != Some(Elf64SymbolType::STT_TLS),
            "non-TLS relocation {ty:?} references TLS symbol: {}",
            self.name
        );
        // Local TLS variables may be referenced through their TLS section symbol.
        ensure!(
            !tls || matches!(
                self.ty,
                Some(Elf64SymbolType::STT_TLS | Elf64SymbolType::STT_SECTION)
            ),
            "TLS relocation {ty:?} references non-TLS symbol: {}",
            self.name
        );
        ensure!(
            !self.is_ifunc()
                || matches!(
                    ty,
                    None | Pc32 | Plt32 | R64 | R32 | R32S | GotPcRel | GotPcRelX | RexGotPcRelX
                ),
            "unsupported IFUNC relocation {ty:?} for symbol: {}",
            self.name
        );
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct SymbolTable {
    symbols: Vec<ResolvedSymbol>,
    pub(super) by_input: HashMap<(FileId, u16), SymbolId>,
    pub(super) by_name: HashMap<String, SymbolId>,
}

impl SymbolTable {
    pub(super) fn insert(
        &mut self,
        name: &str,
        ty: Option<Elf64SymbolType>,
        binding: Elf64SymbolBinding,
        size: u64,
        other: u8,
        definition: Definition,
    ) -> SymbolId {
        let id = SymbolId(self.symbols.len());
        self.symbols.push(ResolvedSymbol {
            name: name.to_string(),
            ty,
            definition,
            binding,
            size,
            other,
            address: OnceCell::new(),
        });
        id
    }

    pub(crate) fn get(&self, id: SymbolId) -> &ResolvedSymbol {
        &self.symbols[id.0]
    }

    pub(crate) fn input(&self, file_id: FileId, idx: u32) -> Result<SymbolId> {
        let idx = u16::try_from(idx).context("Failed to convert symbol index")?;
        self.by_input
            .get(&(file_id, idx))
            .copied()
            .with_context(|| format!("Failed to find symbol {idx} in file: {file_id}"))
    }

    pub(crate) fn named(&self, name: &str) -> Option<&ResolvedSymbol> {
        self.by_name.get(name).map(|id| self.get(*id))
    }

    pub(crate) fn all_symbols(&self) -> impl Iterator<Item = &ResolvedSymbol> {
        self.symbols.iter()
    }

    pub(crate) fn named_symbols(&self) -> impl Iterator<Item = &ResolvedSymbol> {
        self.by_name.values().map(|id| self.get(*id))
    }

    pub(crate) fn should_assign(&self, assignment: &Assignment) -> bool {
        if assignment.name == "." || assignment.kind == AssignmentKind::Define {
            return true;
        }
        matches!(
            self.named(&assignment.name).map(|symbol| symbol.definition),
            Some(Definition::Script { provide: Some(location) }) if location == assignment.location
        )
    }

    pub(crate) fn assign_addresses(
        &self,
        sections: &[OutputSection],
        section_index: &SectionIndex,
        script_symbols: &HashMap<String, u64>,
    ) -> Result<()> {
        pr_debug!("Assigning symbol addresses...");
        for symbol in &self.symbols {
            let address = match symbol.definition {
                Definition::Input {
                    file_id,
                    section_idx,
                    value,
                } => match section_idx {
                    Elf64SymbolSectionIdx::Index(idx) => section_index
                        .get(&(file_id, idx))
                        .map(|location| {
                            sections[location.output_idx]
                                .address
                                .get()
                                .unwrap()
                                .checked_add(location.offset)
                                .and_then(|address| address.checked_add(value))
                                .context("symbol address exceeds u64")
                        })
                        .transpose()?,
                    Elf64SymbolSectionIdx::AbsoluteSymbols => Some(value),
                    _ => unreachable!("only defined input symbols have input definitions"),
                },
                Definition::Script { .. } => {
                    Some(*script_symbols.get(&symbol.name).with_context(|| {
                        format!("script symbol was not assigned: {}", symbol.name)
                    })?)
                }
                Definition::UndefinedWeak => Some(0),
            };
            // Symbols in discarded/non-ALLOC sections have no output address.
            if let Some(address) = address {
                symbol.address.set(address).unwrap();
            }
        }
        Ok(())
    }
}
