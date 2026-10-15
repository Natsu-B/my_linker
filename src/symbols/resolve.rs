use std::collections::{HashMap, HashSet};

use anyhow::{Result, bail, ensure};
use elf::{Elf64SymbolBinding, Elf64SymbolInfo, Elf64SymbolSectionIdx, Elf64SymbolType};

use super::table::{Definition, SymbolId, SymbolTable};
use crate::{
    input::object::ObjectSymbol,
    script::{
        ast::{Assignment, AssignmentKind},
        mapping::SectionMapping,
    },
};

pub(crate) fn resolve(mapping: &SectionMapping) -> Result<SymbolTable> {
    resolve_inputs(&mapping.symbols, &mapping.assignments())
}

pub(crate) fn resolve_inputs(
    symbols: &[ObjectSymbol],
    assignments: &[&Assignment],
) -> Result<SymbolTable> {
    pr_debug!("Resolving symbol names...");
    let mut table = SymbolTable::default();
    let mut definitions: HashMap<&str, &ObjectSymbol> = HashMap::new();
    let mut references = HashSet::new();
    for symbol in symbols {
        let binding = symbol_binding(symbol)?;
        ensure!(
            symbol.section_idx != Elf64SymbolSectionIdx::Common,
            "unsupported common symbol: {} in file: {}",
            symbol.name,
            symbol.file_id
        );
        if symbol.name.is_empty() || binding == Elf64SymbolBinding::STB_LOCAL {
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
            let id = insert_input(&mut table, symbol)?;
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
                Elf64SymbolBinding::STB_GLOBAL,
                0,
                0,
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
            // Static output has no dynamic lookup for hidden script symbols.
            // Like GNU ld, publish them as local symbols in .symtab.
            let binding = if assignment.kind == AssignmentKind::ProvideHidden {
                Elf64SymbolBinding::STB_LOCAL
            } else {
                Elf64SymbolBinding::STB_GLOBAL
            };
            let id = table.insert(
                &assignment.name,
                Some(Elf64SymbolType::STT_NOTYPE),
                binding,
                0,
                0,
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
                    Elf64SymbolBinding::STB_WEAK,
                    symbol.size,
                    symbol.other,
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
            table.insert(
                "",
                None,
                Elf64SymbolBinding::STB_LOCAL,
                0,
                0,
                Definition::UndefinedWeak,
            )
        } else {
            insert_input(&mut table, symbol)?
        };
        table.by_input.insert((symbol.file_id, symbol.idx), id);
    }
    Ok(table)
}

fn symbol_binding(symbol: &ObjectSymbol) -> Result<Elf64SymbolBinding> {
    match symbol.info.get_enum(Elf64SymbolInfo::st_bind) {
        Some(
            binding @ (Elf64SymbolBinding::STB_LOCAL
            | Elf64SymbolBinding::STB_GLOBAL
            | Elf64SymbolBinding::STB_WEAK),
        ) => Ok(binding),
        _ => bail!(
            "unsupported symbol binding {} for symbol: {} in file: {} (expected LOCAL, GLOBAL, or WEAK)",
            symbol.info.get(Elf64SymbolInfo::st_bind),
            symbol.name,
            symbol.file_id
        ),
    }
}

fn insert_input(table: &mut SymbolTable, symbol: &ObjectSymbol) -> Result<SymbolId> {
    Ok(table.insert(
        symbol.name,
        symbol.info.get_enum(Elf64SymbolInfo::st_type),
        symbol_binding(symbol)?,
        symbol.size,
        symbol.other,
        Definition::Input {
            file_id: symbol.file_id,
            section_idx: symbol.section_idx,
            value: symbol.value,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        input::FileId,
        script::{ast::Statement, parser},
    };

    fn symbol(
        file: usize,
        name: &'static str,
        binding: Elf64SymbolBinding,
        ty: Elf64SymbolType,
        section_idx: Elf64SymbolSectionIdx,
    ) -> ObjectSymbol<'static> {
        ObjectSymbol {
            file_id: FileId::InputObject { input_index: file },
            idx: 1,
            name,
            info: Elf64SymbolInfo::from_bits(((binding as u8) << 4) | ty as u8),
            section_idx,
            value: 42,
            size: 0,
            other: 0,
        }
    }

    #[test]
    fn unsupported_bindings_report_an_error_instead_of_panicking() {
        for binding in [3, Elf64SymbolBinding::STB_LOOS as u8] {
            let mut input = symbol(
                0,
                "unsupported",
                Elf64SymbolBinding::STB_GLOBAL,
                Elf64SymbolType::STT_OBJECT,
                Elf64SymbolSectionIdx::AbsoluteSymbols,
            );
            input.info = input.info.set(Elf64SymbolInfo::st_bind, binding);
            let error = resolve_inputs(&[input], &[]).err().unwrap().to_string();
            assert!(error.contains(&format!("unsupported symbol binding {binding}")));
            assert!(error.contains("unsupported"));
            assert!(error.contains("file:"));
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
        let table = resolve_inputs(&symbols, &[]).unwrap();
        let id = table
            .input(FileId::InputObject { input_index: 0 }, 1)
            .unwrap();
        assert_eq!(
            table
                .input(FileId::InputObject { input_index: 1 }, 1)
                .unwrap(),
            id
        );
        assert_eq!(
            table
                .input(FileId::InputObject { input_index: 2 }, 1)
                .unwrap(),
            id
        );
        assert_eq!(table.get(id).ty, Some(Elf64SymbolType::STT_GNU_IFUNC));
        assert_eq!(table.get(id).address.get(), None);
        table
            .assign_addresses(&[], &HashMap::new(), &HashMap::new())
            .unwrap();
        assert_eq!(table.get(id).address.get(), Some(&42));
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
        let table = resolve_inputs(&symbols, &[]).unwrap();
        let id = table
            .input(FileId::InputObject { input_index: 0 }, 1)
            .unwrap();
        assert_eq!(
            table
                .input(FileId::InputObject { input_index: 1 }, 1)
                .unwrap(),
            id
        );
        table
            .assign_addresses(&[], &HashMap::new(), &HashMap::new())
            .unwrap();
        assert_eq!(table.get(id).address.get(), Some(&0));
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
            let error = resolve_inputs(&symbols, &[]).err().unwrap();
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
        let error = resolve_inputs(&symbols, &[]).err().unwrap();
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
        let table = resolve_inputs(&symbols, &assignments).unwrap();
        assert!(table.should_assign(assignments[0]));
        assert_eq!(table.should_assign(assignments[1]), false);
        let id = table
            .input(FileId::InputObject { input_index: 0 }, 1)
            .unwrap();
        assert!(matches!(
            table.get(id).definition,
            Definition::Script { .. }
        ));
        assert_eq!(table.get(id).address.get(), None);
        table
            .assign_addresses(
                &[],
                &HashMap::new(),
                &HashMap::from([("provided".to_string(), 42)]),
            )
            .unwrap();
        assert_eq!(table.get(id).address.get(), Some(&42));
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
        let table = resolve_inputs(&symbols, &[]).unwrap();
        assert_eq!(
            table.named("tls").unwrap().ty,
            Some(Elf64SymbolType::STT_TLS)
        );
        assert_eq!(table.named("tls").unwrap().address.get(), None);
    }
}
