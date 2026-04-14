use crate::{
    link::SectionPlacement,
    parse::{ObjectRelocation, ObjectSymbol},
};

use anyhow::{Context, Ok, Result, bail};
use elf::{Elf64SymbolSectionIdx, x86_64::X86_64RelocationType};

pub fn relocate(
    section_placements: Vec<SectionPlacement>,
    symbols: Vec<ObjectSymbol>,
    relocations: Vec<ObjectRelocation>,
) -> Result<()> {
    pr_debug!("Relocating sections...");

    for relocation in relocations {
        pr_debug!(
            "Relocating symbol idx: {} in file idx: {} at offset: {:#x} in section idx: {}",
            relocation.target_idx,
            relocation.file_idx,
            relocation.offset,
            relocation.reloc_section_idx
        );
        // find the symbol and target
        let target_idx: u16 = relocation
            .target_idx
            .try_into()
            .context("Failed to convert target index")?;
        let target_symbol_idx: u16 = relocation
            .info
            .sym
            .try_into()
            .context("Failed to convert symbol index")?;
        let mut target = None;
        let mut target_object_section = None;
        let mut target_symbol = None;
        for section_placement in &section_placements {
            for (object_section, offset) in &section_placement.output_data {
                if object_section.file_idx == relocation.file_idx
                    && object_section.idx == target_idx
                {
                    pr_debug!(
                        "  Found target section: {} in file idx: {} at offset: {:#x}",
                        object_section.name,
                        object_section.file_idx,
                        offset
                    );
                    target_object_section = Some(object_section);
                    target = Some(object_section);
                }
            }
        }
        for symbol in &symbols {
            if symbol.file_idx == relocation.file_idx && target_symbol_idx == symbol.idx {
                pr_debug!(
                    "  Found target symbol: {} in file idx: {} at offset: {:#x}",
                    symbol.name,
                    symbol.file_idx,
                    symbol.value
                );
                target_symbol = Some(symbol);
            }
        }

        let target = target.context("Failed to find target section for relocation")?;
        let target_object_section =
            target_object_section.context("Failed to find target object section for relocation")?;
        let target_symbol = target_symbol.context("Failed to find target symbol for relocation")?;

        let reloc_type = X86_64RelocationType::try_from(relocation.info)?;
        pr_debug!("Relocation type: {:?}", reloc_type);
        match reloc_type {
            X86_64RelocationType::None => {}
            x => {
                bail!("Unsupported relocation type: {:?}", x);
            }
        }
    }

    Ok(())
}
