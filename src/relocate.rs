use crate::{
    link::SectionPlacement,
    parse::{ObjectRelocation, ObjectSymbol},
    script,
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
        let mut section_placement_info = None;
        let mut target_offset = None;
        let mut target_symbol = None;
        for section_placement in &section_placements {
            for (object_section, offset) in &section_placement.sections_data {
                if object_section.file_idx == relocation.file_idx
                    && object_section.idx == target_idx
                {
                    pr_debug!(
                        "  Found target section: {} in file idx: {} at offset: {:#x}",
                        object_section.name,
                        object_section.file_idx,
                        offset
                    );
                    section_placement_info = Some(section_placement);
                    target_offset = Some(offset);
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

        let section_placement_info = section_placement_info
            .context("Failed to find section placement info for relocation")?;
        let target_symbol = target_symbol.context("Failed to find target symbol for relocation")?;
        let target_offset = target_offset.context("Failed to find target offset for relocation")?;

        // S
        let symbol_addr = match target_symbol.section_idx {
            Elf64SymbolSectionIdx::Undefined => bail!("Undefined Symbol: {}", target_symbol.name),
            Elf64SymbolSectionIdx::AbsoluteSymbols => target_symbol.value,
            Elf64SymbolSectionIdx::Common => todo!(),
            Elf64SymbolSectionIdx::Index(sym_sec_idx) => {
                let mut sym_section_placement = None;
                let mut sym_section_offset = None;

                for section_placement in &section_placements {
                    for (object_section, offset) in &section_placement.sections_data {
                        if object_section.file_idx == target_symbol.file_idx
                            && object_section.idx == sym_sec_idx
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

                sym_section_placement.va.get().unwrap() + sym_section_offset + target_symbol.value
            }
        };
        // A
        let addend = relocation.addend;
        // P
        let place_addr =
            section_placement_info.va.get().unwrap() + *target_offset + relocation.offset;
        // B
        let base_addr = script::LINKER_DATA.read().unwrap().vart_addr;

        let reloc_type = X86_64RelocationType::try_from(relocation.info)?;
        pr_debug!("Relocation type: {:?}", reloc_type);
        match reloc_type {
            X86_64RelocationType::None => {}
            X86_64RelocationType::Pc32 => {}
            x => {
                bail!("Unsupported relocation type: {:?}", x);
            }
        }
    }

    Ok(())
}
