use crate::{
    link::{ElfData, SectionPlacement},
    parse::{ObjectRelocation, ObjectSymbol},
    script,
};

use anyhow::{Context, Ok, Result, bail};
use elf::{ElfEndian, x86_64::X86_64RelocationType};
use num::traits::ToBytes;

pub fn relocate(
    section_placements: &mut Vec<SectionPlacement>,
    symbols: Vec<ObjectSymbol>,
    relocations: Vec<ObjectRelocation>,
    elf_data: &ElfData,
) -> Result<u64 /* start address */> {
    pr_debug!("Relocating sections...");

    for relocation in relocations {
        pr_debug!(
            "Relocating symbol idx: {} in file id: {} at offset: {:#x} in section idx: {}",
            relocation.target_idx,
            relocation.file_id,
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
        let mut section_va = None;
        let mut target_offset = None;
        let mut target_symbol = None;
        let mut target_data = None;
        for section_placement in section_placements.iter_mut() {
            for (object_section, offset) in section_placement.sections_data.iter_mut() {
                if object_section.file_id == relocation.file_id && object_section.idx == target_idx
                {
                    pr_debug!(
                        "  Found target section: {} in file id: {} at offset: {:#x}",
                        object_section.name,
                        object_section.file_id,
                        offset
                    );
                    section_va = Some(*section_placement.va.get().unwrap());
                    target_offset = Some(*offset);
                    target_data = section_placement.data.as_mut();
                    break;
                }
            }
        }
        for symbol in &symbols {
            if symbol.file_id == relocation.file_id && target_symbol_idx == symbol.idx {
                pr_debug!(
                    "  Found target symbol: {} in file id: {} at offset: {:#x}",
                    symbol.name,
                    symbol.file_id,
                    symbol.value
                );
                target_symbol = Some(symbol);
                break;
            }
        }

        let section_va =
            section_va.context("Failed to find section virtual address for relocation")?;
        let target_symbol = target_symbol.context("Failed to find target symbol for relocation")?;
        let target_offset = target_offset.context("Failed to find target offset for relocation")?;
        let target_data = target_data.context("Failed to find target data for relocation")?;
        let endianness = elf_data.endianness;

        // S
        let symbol_addr = *target_symbol.va.get().unwrap();

        // A
        let addend = relocation.addend;
        // P
        let place_addr = section_va + target_offset + relocation.offset;
        // B
        // let base_addr = script::LINKER_DATA.read().unwrap().vart_addr;

        let reloc_type = X86_64RelocationType::try_from(relocation.info)?;
        pr_debug!("Relocation type: {:?}", reloc_type);
        match reloc_type {
            X86_64RelocationType::None => {}
            X86_64RelocationType::Pc32 | X86_64RelocationType::Plt32 => {
                // S + A - P
                let addr: i32 = symbol_addr
                    .checked_add_signed(addend)
                    .context("Relocation PC32 calculation failed")?
                    .checked_sub(place_addr)
                    .context("Relocation PC32 calculation failed")?
                    .try_into()
                    .context("Relocation PC32 calculation failed")?;
                pr_debug!("Relocation PC32: {:#x}", addr);

                write_data(
                    target_data,
                    target_offset + relocation.offset,
                    addr,
                    endianness,
                )?;
            }
            X86_64RelocationType::Rel64 => {
                // S + A
                let addr: u64 = symbol_addr
                    .checked_add_signed(addend)
                    .context("Relocation REL64 calculation failed")?;
                pr_debug!("Relocation REL64: {:#x}", addr);

                write_data(
                    target_data,
                    target_offset + relocation.offset,
                    addr,
                    endianness,
                )?;
            }
            X86_64RelocationType::Rel32S => {
                // S + A
                let addr: i32 = symbol_addr
                    .checked_add_signed(addend)
                    .context("Relocation REL32S calculation failed")?
                    .try_into()
                    .context("Relocation REL32S calculation failed")?;
                pr_debug!("Relocation REL32S: {:#x}", addr);

                write_data(
                    target_data,
                    target_offset + relocation.offset,
                    addr,
                    endianness,
                )?;
            }
            x => {
                bail!("Unsupported relocation type: {:?}", x);
            }
        }
    }

    let start_name = script::LINKER_DATA.read().unwrap();
    let start_name = start_name
        ._start_name
        .get()
        .context("Failed to get _start symbol name from script data")?;
    let entry = symbols
        .iter()
        .find_map(|x| {
            if x.name == *start_name {
                Some(x.va.get().unwrap())
            } else {
                None
            }
        })
        .context("Failed to find entry point")?;
    Ok(*entry)
}

fn write_data<T: ToBytes>(data: &mut [u8], offset: u64, value: T, endian: ElfEndian) -> Result<()> {
    let offset = offset as usize;
    let bytes = match endian {
        ElfEndian::Little => value.to_le_bytes(),
        ElfEndian::Big => value.to_be_bytes(),
    };
    let bytes = bytes.as_ref();
    if offset + size_of::<T>() > data.len() {
        bail!(
            "Write out of bounds: offset {} + size {} > data length {}",
            offset,
            size_of::<T>(),
            data.len()
        );
    }
    data[offset..offset + size_of::<T>()].copy_from_slice(&bytes);
    Ok(())
}
