use std::{
    cell::OnceCell,
    collections::{HashMap, HashSet},
};

use anyhow::{Context, Result, bail, ensure};
use elf::{
    Elf64SymbolBinding, Elf64SymbolInfo, Elf64SymbolSectionIdx, Elf64SymbolType,
    x86_64::X86_64RelocationType,
};

use crate::{
    input_id::FileId,
    link::{SectionIndex, SectionPlacement},
    parse::ObjectSymbol,
    script::ast::{Assignment, AssignmentKind, Location},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SymbolId(usize);

#[derive(Debug, Clone, Copy)]
pub enum Definition {
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
pub struct ResolvedSymbol {
    pub name: String,
    pub ty: Option<Elf64SymbolType>,
    pub definition: Definition,
    pub va: OnceCell<u64>,
}

impl ResolvedSymbol {
    pub fn is_ifunc(&self) -> bool {
        self.ty == Some(Elf64SymbolType::STT_GNU_IFUNC)
            && matches!(self.definition, Definition::Input { .. })
    }

    pub fn validate_relocation(&self, ty: X86_64RelocationType) -> Result<()> {
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
                    None | Pc32
                        | Plt32
                        | Rel64
                        | Rel32
                        | Rel32S
                        | GotPcRel
                        | GotPcRelX
                        | RexGotPcRelX
                ),
            "unsupported IFUNC relocation {ty:?} for symbol: {}",
            self.name
        );
        Ok(())
    }
}

#[derive(Default)]
pub struct SymbolTable {
    symbols: Vec<ResolvedSymbol>,
    by_input: HashMap<(FileId, u16), SymbolId>,
    by_name: HashMap<String, SymbolId>,
}

impl SymbolTable {
    fn insert(
        &mut self,
        name: &str,
        ty: Option<Elf64SymbolType>,
        definition: Definition,
    ) -> SymbolId {
        let id = SymbolId(self.symbols.len());
        self.symbols.push(ResolvedSymbol {
            name: name.to_string(),
            ty,
            definition,
            va: OnceCell::new(),
        });
        id
    }

    pub fn get(&self, id: SymbolId) -> &ResolvedSymbol {
        &self.symbols[id.0]
    }

    pub fn input(&self, file_id: FileId, idx: u32) -> Result<SymbolId> {
        let idx = u16::try_from(idx).context("Failed to convert symbol index")?;
        self.by_input
            .get(&(file_id, idx))
            .copied()
            .with_context(|| format!("Failed to find symbol {idx} in file: {file_id}"))
    }

    pub fn named(&self, name: &str) -> Option<&ResolvedSymbol> {
        self.by_name.get(name).map(|id| self.get(*id))
    }

    pub fn named_symbols(&self) -> impl Iterator<Item = &ResolvedSymbol> {
        self.by_name.values().map(|id| self.get(*id))
    }

    pub fn should_assign(&self, assignment: &Assignment) -> bool {
        if assignment.name == "." || assignment.kind == AssignmentKind::Define {
            return true;
        }
        matches!(
            self.named(&assignment.name).map(|symbol| symbol.definition),
            Some(Definition::Script { provide: Some(location) }) if location == assignment.location
        )
    }

    pub fn assign_addresses(
        &self,
        sections: &[SectionPlacement],
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
                                .va
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
                symbol.va.set(address).unwrap();
            }
        }
        Ok(())
    }
}

pub fn resolve_names(symbols: &[ObjectSymbol], assignments: &[&Assignment]) -> Result<SymbolTable> {
    pr_debug!("Resolving symbol names...");
    let mut table = SymbolTable::default();
    let mut definitions: HashMap<&str, &ObjectSymbol> = HashMap::new();
    let mut references = HashSet::new();
    for symbol in symbols {
        ensure!(
            symbol.section_idx != Elf64SymbolSectionIdx::Common,
            "unsupported common symbol: {} in file: {}",
            symbol.name,
            symbol.file_id
        );
        if symbol.name.is_empty()
            || symbol.info.get_enum(Elf64SymbolInfo::st_bind) == Some(Elf64SymbolBinding::STB_LOCAL)
        {
            continue;
        }
        if symbol.section_idx == Elf64SymbolSectionIdx::Undefined {
            references.insert(symbol.name);
        } else if let Some(old) = definitions.get(symbol.name) {
            let weak = symbol.info.get_enum(Elf64SymbolInfo::st_bind)
                == Some(Elf64SymbolBinding::STB_WEAK);
            let old_weak =
                old.info.get_enum(Elf64SymbolInfo::st_bind) == Some(Elf64SymbolBinding::STB_WEAK);
            if !weak && !old_weak {
                bail!(
                    "multiple definition of symbol: {} in files: {} and {}",
                    symbol.name,
                    symbol.file_id,
                    old.file_id
                );
            }
            if !weak {
                definitions.insert(symbol.name, symbol);
            }
        } else {
            definitions.insert(symbol.name, symbol);
        }
    }

    // Insert winners in input order so symbol identities are deterministic.
    for symbol in symbols {
        if definitions
            .get(symbol.name)
            .is_some_and(|winner| std::ptr::eq(*winner, symbol))
        {
            let id = insert_input(&mut table, symbol);
            table.by_name.insert(symbol.name.to_string(), id);
        }
    }
    // Unconditional script definitions always win over PROVIDE, including a
    // PROVIDE that appears earlier in the script. Input duplicates are errors.
    for assignment in assignments {
        if assignment.name == "." || assignment.kind != AssignmentKind::Define {
            continue;
        }
        ensure!(
            !definitions.contains_key(assignment.name.as_str()),
            "{}: multiple definition of symbol: {} in input and linker script",
            assignment.location,
            assignment.name
        );
        if !table.by_name.contains_key(&assignment.name) {
            let id = table.insert(
                &assignment.name,
                Some(Elf64SymbolType::STT_NOTYPE),
                Definition::Script { provide: None },
            );
            table.by_name.insert(assignment.name.clone(), id);
        }
    }
    for assignment in assignments {
        if assignment.kind != AssignmentKind::Define
            && references.contains(assignment.name.as_str())
            && !table.by_name.contains_key(&assignment.name)
        {
            let id = table.insert(
                &assignment.name,
                Some(Elf64SymbolType::STT_NOTYPE),
                Definition::Script {
                    provide: Some(assignment.location),
                },
            );
            table.by_name.insert(assignment.name.clone(), id);
        }
    }
    // Check strong references before the loop below registers undefined weak
    // symbols; otherwise an earlier weak reference would hide a strong one.
    for symbol in symbols {
        if !symbol.name.is_empty()
            && symbol.section_idx == Elf64SymbolSectionIdx::Undefined
            && symbol.info.get_enum(Elf64SymbolInfo::st_bind)
                == Some(Elf64SymbolBinding::STB_GLOBAL)
            && !table.by_name.contains_key(symbol.name)
        {
            bail!(
                "undefined symbol: {} in file: {}",
                symbol.name,
                symbol.file_id
            );
        }
    }
    for symbol in symbols {
        let binding = symbol.info.get_enum(Elf64SymbolInfo::st_bind);
        let id = if !symbol.name.is_empty() && binding != Some(Elf64SymbolBinding::STB_LOCAL) {
            if let Some(id) = table.by_name.get(symbol.name) {
                *id
            } else if binding == Some(Elf64SymbolBinding::STB_WEAK) {
                let id = table.insert(
                    symbol.name,
                    symbol.info.get_enum(Elf64SymbolInfo::st_type),
                    Definition::UndefinedWeak,
                );
                table.by_name.insert(symbol.name.to_string(), id);
                id
            } else {
                bail!(
                    "undefined symbol: {} in file: {}",
                    symbol.name,
                    symbol.file_id
                );
            }
        } else if symbol.section_idx == Elf64SymbolSectionIdx::Undefined {
            // The null symbol (index zero) denotes the absolute value zero.
            table.insert("", None, Definition::UndefinedWeak)
        } else {
            insert_input(&mut table, symbol)
        };
        table.by_input.insert((symbol.file_id, symbol.idx), id);
    }
    Ok(table)
}

fn insert_input(table: &mut SymbolTable, symbol: &ObjectSymbol) -> SymbolId {
    table.insert(
        symbol.name,
        symbol.info.get_enum(Elf64SymbolInfo::st_type),
        Definition::Input {
            file_id: symbol.file_id,
            section_idx: symbol.section_idx,
            value: symbol.value,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::{ast::Statement, parser};

    fn symbol(
        file: usize,
        name: &'static str,
        binding: Elf64SymbolBinding,
        ty: Elf64SymbolType,
        section_idx: Elf64SymbolSectionIdx,
    ) -> ObjectSymbol<'static> {
        ObjectSymbol {
            file_id: FileId::Object(file),
            idx: 1,
            name,
            info: Elf64SymbolInfo::from_bits(((binding as u8) << 4) | ty as u8),
            section_idx,
            value: 42,
            size: 0,
        }
    }

    #[test]
    fn selects_strong_definition_and_preserves_its_type_before_layout() {
        let weak = symbol(
            0,
            "foo",
            Elf64SymbolBinding::STB_WEAK,
            Elf64SymbolType::STT_FUNC,
            Elf64SymbolSectionIdx::AbsoluteSymbols,
        );
        let strong = symbol(
            1,
            "foo",
            Elf64SymbolBinding::STB_GLOBAL,
            Elf64SymbolType::STT_GNU_IFUNC,
            Elf64SymbolSectionIdx::AbsoluteSymbols,
        );
        let reference = symbol(
            2,
            "foo",
            Elf64SymbolBinding::STB_GLOBAL,
            Elf64SymbolType::STT_NOTYPE,
            Elf64SymbolSectionIdx::Undefined,
        );
        let symbols = vec![weak, strong, reference];
        let table = resolve_names(&symbols, &[]).unwrap();
        let id = table.input(FileId::Object(0), 1).unwrap();
        assert_eq!(table.input(FileId::Object(1), 1).unwrap(), id);
        assert_eq!(table.input(FileId::Object(2), 1).unwrap(), id);
        assert_eq!(table.get(id).ty, Some(Elf64SymbolType::STT_GNU_IFUNC));
        assert_eq!(table.get(id).va.get(), None);
        table
            .assign_addresses(&[], &HashMap::new(), &HashMap::new())
            .unwrap();
        assert_eq!(table.get(id).va.get(), Some(&42));
    }

    #[test]
    fn undefined_weak_symbols_share_a_zero_definition() {
        let symbols = [0, 1].map(|file| {
            symbol(
                file,
                "optional",
                Elf64SymbolBinding::STB_WEAK,
                Elf64SymbolType::STT_NOTYPE,
                Elf64SymbolSectionIdx::Undefined,
            )
        });
        let table = resolve_names(&symbols, &[]).unwrap();
        let id = table.input(FileId::Object(0), 1).unwrap();
        assert_eq!(table.input(FileId::Object(1), 1).unwrap(), id);
        table
            .assign_addresses(&[], &HashMap::new(), &HashMap::new())
            .unwrap();
        assert_eq!(table.get(id).va.get(), Some(&0));
    }

    #[test]
    fn weak_reference_does_not_hide_an_undefined_strong_reference() {
        for bindings in [
            [Elf64SymbolBinding::STB_WEAK, Elf64SymbolBinding::STB_GLOBAL],
            [Elf64SymbolBinding::STB_GLOBAL, Elf64SymbolBinding::STB_WEAK],
        ] {
            let symbols = bindings
                .into_iter()
                .enumerate()
                .map(|(file, binding)| {
                    symbol(
                        file,
                        "missing",
                        binding,
                        Elf64SymbolType::STT_NOTYPE,
                        Elf64SymbolSectionIdx::Undefined,
                    )
                })
                .collect::<Vec<_>>();
            let error = resolve_names(&symbols, &[]).err().unwrap();
            assert!(error.to_string().contains("undefined symbol: missing"));
        }
    }

    #[test]
    fn duplicate_strong_definitions_fail_before_layout() {
        let symbols = [0, 1].map(|file| {
            symbol(
                file,
                "duplicate",
                Elf64SymbolBinding::STB_GLOBAL,
                Elf64SymbolType::STT_FUNC,
                Elf64SymbolSectionIdx::Index(1),
            )
        });
        let error = resolve_names(&symbols, &[]).err().unwrap();
        assert!(
            error
                .to_string()
                .contains("multiple definition of symbol: duplicate")
        );
    }

    #[test]
    fn provide_is_selected_before_layout_for_an_undefined_weak_reference() {
        let symbols = [symbol(
            0,
            "provided",
            Elf64SymbolBinding::STB_WEAK,
            Elf64SymbolType::STT_NOTYPE,
            Elf64SymbolSectionIdx::Undefined,
        )];
        let script =
            parser::parse("PROVIDE_HIDDEN(provided = 42); PROVIDE(unused = missing);").unwrap();
        let assignments = script
            .statements
            .iter()
            .map(|statement| {
                let Statement::Assignment(assignment) = statement else {
                    panic!()
                };
                assignment
            })
            .collect::<Vec<_>>();
        let table = resolve_names(&symbols, &assignments).unwrap();
        assert!(table.should_assign(assignments[0]));
        assert_eq!(table.should_assign(assignments[1]), false);
        let id = table.input(FileId::Object(0), 1).unwrap();
        assert!(matches!(
            table.get(id).definition,
            Definition::Script { .. }
        ));
        assert_eq!(table.get(id).va.get(), None);
        table
            .assign_addresses(
                &[],
                &HashMap::new(),
                &HashMap::from([("provided".to_string(), 42)]),
            )
            .unwrap();
        assert_eq!(table.get(id).va.get(), Some(&42));
    }

    #[test]
    fn tls_type_is_available_before_address_assignment() {
        let symbols = [symbol(
            0,
            "tls",
            Elf64SymbolBinding::STB_GLOBAL,
            Elf64SymbolType::STT_TLS,
            Elf64SymbolSectionIdx::Index(1),
        )];
        let table = resolve_names(&symbols, &[]).unwrap();
        assert_eq!(
            table.named("tls").unwrap().ty,
            Some(Elf64SymbolType::STT_TLS)
        );
        assert_eq!(table.named("tls").unwrap().va.get(), None);
    }
}
