use std::collections::HashMap;

use anyhow::{Context, Ok, Result, bail};
use elf::{Elf64SymbolBinding, Elf64SymbolInfo};

use crate::{link::SectionPlacement, parse::ObjectSymbol};

pub fn resolve<'a>(
    section_placements: &Vec<SectionPlacement>,
    symbol_tables: &Vec<ObjectSymbol<'a>>,
) -> Result<()> {
    pr_debug!("Resolving symbols...");

    let mut resolved_symbols = HashMap::new();
    for symbol_table in symbol_tables {
        if let Some(section_addr) = match symbol_table.section_idx {
            elf::Elf64SymbolSectionIdx::Common => todo!(),
            elf::Elf64SymbolSectionIdx::Index(idx) => {
                let mut sym_section_placement = None;
                let mut sym_section_offset = None;

                for section_placement in section_placements {
                    for (object_section, offset) in &section_placement.sections_data {
                        if object_section.file_idx == symbol_table.file_idx
                            && object_section.idx == idx
                        {
                            sym_section_placement = Some(section_placement);
                            sym_section_offset = Some(*offset);
                        }
                    }
                }

                let sym_section_placement =
                    sym_section_placement.context("failed to find symbol section placement")?;
                let sym_section_offset =
                    sym_section_offset.context("failed to find symbol section offset")?;

                Some(
                    sym_section_placement.va.get().unwrap()
                        + sym_section_offset
                        + symbol_table.value,
                )
            }
            elf::Elf64SymbolSectionIdx::AbsoluteSymbols => Some(symbol_table.value),
            elf::Elf64SymbolSectionIdx::Undefined => None,
        } {
            symbol_table.va.set(section_addr).unwrap();
            if !symbol_table.name.is_empty()
                && let Some(old_section) =
                    resolved_symbols.insert(symbol_table.name, (symbol_table, section_addr))
            {
                if symbol_table.info.get_enum(Elf64SymbolInfo::st_bind)
                    == Some(Elf64SymbolBinding::STB_WEAK)
                {
                    let _ = resolved_symbols.insert(old_section.0.name, old_section);
                } else if old_section.0.info.get_enum(Elf64SymbolInfo::st_bind)
                    != Some(Elf64SymbolBinding::STB_WEAK)
                {
                    bail!(
                        "multiple definition of symbol: {} in files: {} and {}",
                        symbol_table.name,
                        symbol_table.file_idx,
                        old_section.0.file_idx
                    );
                }
            }
        };
    }

    for symbol_table in symbol_tables {
        if symbol_table.name.is_empty() {
            continue;
        }
        if matches!(
            symbol_table.section_idx,
            elf::Elf64SymbolSectionIdx::Undefined
        ) {
            let resolved = resolved_symbols.get(symbol_table.name).with_context(|| {
                format!(
                    "undefined symbol: {} in file: {}",
                    symbol_table.name, symbol_table.file_idx
                )
            })?;
            symbol_table.va.set(resolved.1).unwrap();
        }
    }
    Ok(())
}
