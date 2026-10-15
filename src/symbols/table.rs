//! Keep the chosen definitions and let later steps look them up.
//!
//! [`SymbolTable`] maps input symbol indices and global names to [`SymbolId`].
//! Each [`ResolvedSymbol`] keeps a [`Definition`] before layout sets its address.
//! For example, a symbol at offset 8 in an input section needs that section's
//! output address and offset before we can give the symbol an address.
//!
//! Like GNU ld, absolute symbols keep their value and missing weak symbols get
//! zero. A discarded section has no output address. TLS values stay as template
//! addresses inside the linker; output changes them to TLS offsets for .symtab.
//!
//! References: ELF gABI "Symbol Table" and "Symbol Value"; AMD64 psABI §§4.3–4.4.1;
//! GNU ld [`PROVIDE`](https://sourceware.org/binutils/docs/ld/PROVIDE.html).

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

/// Map input indices and global names to the definitions this link chose.
#[derive(Default)]
pub(crate) struct SymbolTable {
    symbols: Vec<ResolvedSymbol>,
    pub(super) by_input: HashMap<(FileId, u16), SymbolId>,
    pub(super) by_name: HashMap<String, SymbolId>,
}

/// A table index shared by all input references to one chosen definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SymbolId(usize);

/// Keep where a value comes from until layout can compute it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Definition {
    /// An input value is a section offset unless its section index is SHN_ABS.
    Input {
        file_id: FileId,
        section_idx: Elf64SymbolSectionIdx,
        value: u64,
    },
    /// Layout computes the expression when it reaches this script assignment.
    Script {
        /// Location of the chosen PROVIDE; `None` means a plain assignment.
        provide: Option<Location>,
    },
    /// Missing weak references and the null symbol both get value zero.
    UndefinedWeak,
}

/// One chosen definition; layout sets its final value once.
#[derive(Debug)]
pub(crate) struct ResolvedSymbol {
    pub(crate) name: String,
    /// `None` covers the null symbol and type numbers the reader does not name.
    pub(crate) ty: Option<Elf64SymbolType>,
    pub(crate) definition: Definition,
    pub(crate) binding: Elf64SymbolBinding,
    pub(crate) size: u64,
    /// Raw `st_other`, including visibility bits.
    pub(crate) other: u8,
    /// Unset for discarded input sections. TLS keeps a template address here;
    /// output changes it to an offset only when writing .symtab.
    pub(crate) address: OnceCell<u64>,
}

impl ResolvedSymbol {
    pub(crate) fn is_ifunc(&self) -> bool {
        self.ty == Some(Elf64SymbolType::STT_GNU_IFUNC)
            && matches!(self.definition, Definition::Input { .. })
    }

    /// Reject TLS models and IFUNC references that this linker cannot handle.
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
        // An assembler may name the TLS section plus an addend for a local
        // variable, so STT_SECTION must work as well as STT_TLS.
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

    /// Find the chosen definition for a relocation's per-file symbol index.
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

    /// Visit all entries, including locals, in the order they were added.
    pub(crate) fn all_symbols(&self) -> impl Iterator<Item = &ResolvedSymbol> {
        self.symbols.iter()
    }

    /// Visit global and script definitions; hash-map order is not stable.
    pub(crate) fn named_symbols(&self) -> impl Iterator<Item = &ResolvedSymbol> {
        self.by_name.values().map(|id| self.get(*id))
    }

    /// Use only the PROVIDE chosen during resolution, even if the script has several.
    pub(crate) fn should_assign(&self, assignment: &Assignment) -> bool {
        if assignment.name == "." || assignment.kind == AssignmentKind::Define {
            return true;
        }
        matches!(
            self.named(&assignment.name).map(|symbol| symbol.definition),
            Some(Definition::Script { provide: Some(location) }) if location == assignment.location
        )
    }

    /// Set each final value after section addresses stop changing.
    ///
    /// For an input definition, add the output address, the input's output offset,
    /// and the symbol's input offset. Absolute and missing weak symbols need no
    /// section; symbols in discarded sections stay unset.
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
            // Discarded or non-allocated sections give no address to their symbols.
            if let Some(address) = address {
                symbol.address.set(address).unwrap();
            }
        }
        Ok(())
    }
}
