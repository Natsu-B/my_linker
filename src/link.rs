use std::collections::{HashMap, HashSet};

use anyhow::{Result, ensure};
use elf::{Elf64SymbolInfo, Elf64SymbolType};

use crate::{
    input::object::{ObjectFile, ObjectRelocation},
    layout::{self, Layout},
    script::{
        ast::Script,
        mapping::{MappedItem, MappedStatement, MappingInput, input_name, map_sections},
    },
    symbols::{self, SymbolTable},
    synthetic::{Got, Iplt, SyntheticSection},
};

pub(crate) struct LinkedImage<'a> {
    pub(crate) layout: Layout<'a>,
    pub(crate) symbols: SymbolTable,
    pub(crate) relocations: Vec<ObjectRelocation>,
    pub(crate) got: Got,
    pub(crate) iplt: Iplt,
}

pub(crate) fn link<'a>(
    object_files: Vec<ObjectFile<'a>>,
    script: &Script,
) -> Result<LinkedImage<'a>> {
    pr_debug!("Linking {} object files", object_files.len());
    let mut inputs = Vec::new();
    let mut symbols = Vec::new();
    let mut relocations = Vec::new();
    ensure!(!object_files.is_empty(), "no object files to link");
    for object in object_files {
        for section in object.sections {
            ensure!(
                section.align == 0 || section.align.is_power_of_two(),
                "invalid alignment for section {} in {}",
                section.name,
                object.file_name
            );
            inputs.push(MappingInput {
                file_name: input_name(&object.file_name, object.file_id).to_string(),
                section,
            });
        }
        symbols.extend(object.symbols);
        relocations.extend(object.relocations);
    }
    // Reserve synthetic identities and attributes before script mapping.
    // Their sizes depend on resolved symbols and are filled in before layout.
    let has_ifunc = symbols.iter().any(|symbol| {
        symbol.info.get_enum(Elf64SymbolInfo::st_type) == Some(Elf64SymbolType::STT_GNU_IFUNC)
    });
    let needs_got = has_ifunc
        || relocations
            .iter()
            .any(|relocation| Got::needs_entry(relocation.info.ty));
    let mut synthetic_inputs = HashMap::new();
    for section in SyntheticSection::ALL {
        let needed = match section {
            SyntheticSection::Got => needs_got,
            SyntheticSection::Iplt | SyntheticSection::RelaIplt => has_ifunc,
        };
        if needed {
            synthetic_inputs.insert(section as u16, inputs.len());
            inputs.push(MappingInput {
                file_name: "<linker>".to_string(),
                section: section.section(0),
            });
        }
    }
    let items = map_sections(script, &inputs)?;
    let mut assignments = Vec::new();
    let mut placed = HashSet::new();
    for item in &items {
        match item {
            MappedItem::Assignment(assignment) => assignments.push(*assignment),
            MappedItem::Output(output) => {
                for statement in &output.statements {
                    match statement {
                        MappedStatement::Assignment(assignment) => assignments.push(*assignment),
                        MappedStatement::Input(index) => {
                            let section = &inputs[*index].section;
                            placed.insert((section.file_id, u32::from(section.idx)));
                        }
                    }
                }
            }
        }
    }
    let symbols = symbols::resolve(&symbols, &assignments)?;
    relocations.retain(|relocation| placed.contains(&(relocation.file_id, relocation.target_idx)));
    let got = Got::collect(&relocations, &symbols)?;
    let iplt = Iplt::new(&got);
    for section in [got.section()].into_iter().chain(iplt.sections()) {
        if let Some(index) = synthetic_inputs.get(&section.idx) {
            inputs[*index].section = section;
        }
    }
    let layout = layout::assign_addresses(&items, &inputs, &symbols)?;
    Ok(LinkedImage {
        layout,
        symbols,
        relocations,
        got,
        iplt,
    })
}
