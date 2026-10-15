use crate::{got::GotEntry, input_id::FileId, link::Linked, synthetic::SyntheticSection};

use anyhow::{Context, Result, bail};
use elf::x86_64::X86_64RelocationType;
use num::traits::ToBytes;

pub fn relocate(linked: &mut Linked, entry_name: &str) -> Result<u64 /* start address */> {
    pr_debug!("Relocating sections...");
    let Linked {
        sections,
        symbols,
        relocations,
        section_index,
        got,
        iplt,
        elf_data,
    } = linked;
    let got_location = section_index.get(&(FileId::Synthetic, SyntheticSection::Got as u16));
    let got_va = got_location
        .map(|location| sections[location.output_idx].va.get().unwrap() + location.offset);
    for (entry, offset) in got.entries() {
        let location = got_location.context("synthetic GOT input section was discarded")?;
        let (GotEntry::Address(id) | GotEntry::TpOff(id) | GotEntry::Ifunc(id)) = entry;
        let address = *symbols.get(id).va.get().with_context(|| {
            format!("GOT target has no output address: {}", symbols.get(id).name)
        })?;
        let data = sections[location.output_idx]
            .data
            .as_mut()
            .context("GOT output section has no data")?;
        match entry {
            GotEntry::Address(_) => {
                write_data(data, location.offset + offset, address)?;
            }
            GotEntry::TpOff(_) => {
                let tpoff = elf_data
                    .tls
                    .context("TLS GOT entry has no TLS segment")?
                    .tpoff(address)
                    .with_context(|| {
                        format!(
                            "invalid TLS GOT target: {} at {address:#x}",
                            symbols.get(id).name
                        )
                    })?;
                write_data(data, location.offset + offset, tpoff)?;
            }
            // Startup applies IRELATIVE before any IFUNC calls. Leave the
            // reserved slot zero until it stores the resolver's result.
            GotEntry::Ifunc(_) => {}
        }
    }
    iplt.write(sections, section_index, got, symbols)?;

    for relocation in relocations {
        pr_debug!(
            "Relocating symbol idx: {} in file id: {} at offset: {:#x} in section idx: {}",
            relocation.target_idx,
            relocation.file_id,
            relocation.offset,
            relocation.reloc_section_idx
        );
        let target_idx =
            u16::try_from(relocation.target_idx).context("Failed to convert target index")?;
        let Some(location) = section_index.get(&(relocation.file_id, target_idx)) else {
            continue;
        };
        let reloc_type = X86_64RelocationType::try_from(relocation.info)?;
        if reloc_type == X86_64RelocationType::None {
            continue;
        }
        let symbol_id = symbols.input(relocation.file_id, relocation.info.sym)?;
        let target_symbol = symbols.get(symbol_id);
        // Direct references use the canonical IPLT address; resolver addresses
        // remain available separately for the IRELATIVE addends.
        let canonical_address = if target_symbol.is_ifunc()
            && matches!(
                reloc_type,
                X86_64RelocationType::Pc32
                    | X86_64RelocationType::Plt32
                    | X86_64RelocationType::R64
                    | X86_64RelocationType::R32
                    | X86_64RelocationType::R32S
            ) {
            Some(iplt.address(symbol_id, sections, section_index)?)
        } else {
            None
        };
        let section = &mut sections[location.output_idx];
        let section_va = *section
            .va
            .get()
            .context("relocation section has no address")?;
        let target_offset = location.offset;
        let target_data = section
            .data
            .as_mut()
            .context("Failed to find target data for relocation")?;
        // S comes from the winning definition, including references within
        // an object whose weak definition was replaced by a strong one.
        let symbol_addr = canonical_address
            .or_else(|| target_symbol.va.get().copied())
            .with_context(|| {
                format!(
                    "relocation target has no output address: {}",
                    target_symbol.name
                )
            })?;

        // A
        let addend = relocation.addend;
        // P
        let place_addr = section_va + target_offset + relocation.offset;
        pr_debug!("Relocation type: {:?}", reloc_type);
        match reloc_type {
            X86_64RelocationType::None => {}
            X86_64RelocationType::Pc32 | X86_64RelocationType::Plt32 => {
                // S + A - P
                let value = (symbol_addr as i128) + (addend as i128) - (place_addr as i128);
                let addr: i32 = value
                    .try_into()
                    .with_context(|| format!("Relocation PC32 calculation failed: symbol_addr={:#x}, addend={:#x}, place_addr={:#x}", symbol_addr, addend, place_addr))?;
                pr_debug!("Relocation PC32: {:#x}", addr);

                write_data(target_data, target_offset + relocation.offset, addr)?;
            }
            X86_64RelocationType::GotPcRel
            | X86_64RelocationType::GotPcRelX
            | X86_64RelocationType::RexGotPcRelX
            | X86_64RelocationType::GotTpOff => {
                // G + GOT + A - P. Keep the original instruction unchanged.
                let entry = if reloc_type == X86_64RelocationType::GotTpOff {
                    GotEntry::TpOff(symbol_id)
                } else if target_symbol.is_ifunc() {
                    GotEntry::Ifunc(symbol_id)
                } else {
                    GotEntry::Address(symbol_id)
                };
                let slot_addr = got_va.context("GOT has no output address")? + got.offset(entry)?;
                let value = (slot_addr as i128) + (addend as i128) - (place_addr as i128);
                let addr: i32 = value.try_into().with_context(|| {
                    format!(
                        "Relocation {reloc_type:?} calculation failed: slot_addr={slot_addr:#x}, addend={addend:#x}, place_addr={place_addr:#x}"
                    )
                })?;
                write_data(target_data, target_offset + relocation.offset, addr)?;
            }
            X86_64RelocationType::TpOff32 | X86_64RelocationType::TpOff64 => {
                let tpoff = elf_data
                    .tls
                    .context("TLS relocation has no TLS segment")?
                    .tpoff(symbol_addr)
                    .with_context(|| {
                        format!(
                            "invalid TLS relocation target: {} at {symbol_addr:#x}",
                            target_symbol.name
                        )
                    })?;
                let value = i128::from(tpoff) + i128::from(addend);
                let offset = target_offset + relocation.offset;
                if reloc_type == X86_64RelocationType::TpOff32 {
                    let value = i32::try_from(value).with_context(|| {
                        format!(
                            "Relocation TPOFF32 calculation failed: tpoff={tpoff}, addend={addend}"
                        )
                    })?;
                    write_data(target_data, offset, value)?;
                } else {
                    let value = i64::try_from(value).with_context(|| {
                        format!(
                            "Relocation TPOFF64 calculation failed: tpoff={tpoff}, addend={addend}"
                        )
                    })?;
                    write_data(target_data, offset, value)?;
                }
            }
            X86_64RelocationType::R32 => {
                // S + A
                let value = (symbol_addr as i128) + (addend as i128);
                let addr: u32 = value.try_into().with_context(|| {
                    format!(
                        "Relocation REL32 calculation failed: symbol_addr={:#x}, addend={:#x}",
                        symbol_addr, addend
                    )
                })?;
                pr_debug!("Relocation REL32: {:#x}", addr);

                write_data(target_data, target_offset + relocation.offset, addr)?;
            }
            X86_64RelocationType::R64 => {
                // S + A
                let value = (symbol_addr as i128) + (addend as i128);
                let addr: u64 = value.try_into().with_context(|| {
                    format!(
                        "Relocation REL64 calculation failed: symbol_addr={:#x}, addend={:#x}",
                        symbol_addr, addend
                    )
                })?;
                pr_debug!("Relocation REL64: {:#x}", addr);

                write_data(target_data, target_offset + relocation.offset, addr)?;
            }
            X86_64RelocationType::R32S => {
                // S + A
                let value = (symbol_addr as i128) + (addend as i128);
                let addr: i32 = value.try_into().with_context(|| {
                    format!(
                        "Relocation REL32S calculation failed: symbol_addr={:#x}, addend={:#x}",
                        symbol_addr, addend
                    )
                })?;
                pr_debug!("Relocation REL32S: {:#x}", addr);

                write_data(target_data, target_offset + relocation.offset, addr)?;
            }
            x => {
                bail!("Unsupported relocation type: {:?}", x);
            }
        }
    }

    symbols
        .named(entry_name)
        .and_then(|symbol| symbol.va.get().copied())
        .context("Failed to find entry point")
}

fn write_data<T: ToBytes>(data: &mut [u8], offset: u64, value: T) -> Result<()> {
    let offset = offset as usize;
    let bytes = value.to_le_bytes();
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
