mod x86_64;

use anyhow::{Context, Result};
use elf::x86_64::X86_64RelocationType;

use crate::{
    layout::{Layout, LinkedImage},
    symbols::SymbolTable,
    synthetic::{Got, GotEntry, SyntheticSection},
};
use x86_64::{Operands, RelocationSite};

pub(crate) fn apply(image: &mut LinkedImage) -> Result<()> {
    pr_debug!("Relocating sections...");
    initialize_got(&mut image.layout, &image.got, &image.symbols)?;
    let LinkedImage {
        layout,
        symbols,
        relocations,
        got,
        iplt,
        ..
    } = image;
    let Layout {
        sections,
        section_index,
        tls,
        ..
    } = layout;
    iplt.write(sections, section_index, got, symbols)?;
    for relocation in relocations {
        let target_idx =
            u16::try_from(relocation.target_idx).context("invalid relocation target index")?;
        let location = section_index
            .get(&(relocation.file_id, target_idx))
            .context("relocation input section has no output location")?;
        let ty = X86_64RelocationType::try_from(relocation.info)?;
        if ty == X86_64RelocationType::None {
            continue;
        }
        let symbol_id = symbols.input(relocation.file_id, relocation.info.sym)?;
        let symbol = symbols.get(symbol_id);
        let address = *symbol
            .address
            .get()
            .with_context(|| format!("relocation target has no output address: {}", symbol.name))?;
        let offset = location
            .offset
            .checked_add(relocation.offset)
            .context("relocation offset exceeds u64")?;
        let place = sections[location.output_idx]
            .address
            .get()
            .context("relocation output section has no address")?
            .checked_add(offset)
            .context("relocation place exceeds u64")?;

        // GOT references name the slot, not its contents. IFUNC slots are
        // filled at startup; initial-exec TLS slots hold a signed TP offset.
        let got_slot = if Got::needs_entry(relocation.info.ty) {
            let entry = if ty == X86_64RelocationType::GotTpOff {
                GotEntry::TpOff(symbol_id)
            } else if symbol.is_ifunc() {
                GotEntry::Ifunc(symbol_id)
            } else {
                GotEntry::Address(symbol_id)
            };
            Some(
                SyntheticSection::Got
                    .address(sections, section_index)?
                    .checked_add(got.offset(entry)?)
                    .context("GOT slot address exceeds u64")?,
            )
        } else {
            None
        };
        let tls_offset = if matches!(
            ty,
            X86_64RelocationType::TpOff32 | X86_64RelocationType::TpOff64
        ) {
            Some(
                tls.context("TLS relocation has no TLS segment")?
                    .tpoff(address)
                    .with_context(|| {
                        format!("invalid TLS target: {} at {address:#x}", symbol.name)
                    })?,
            )
        } else {
            None
        };
        // Direct references to an IFUNC use its canonical IPLT address.
        // Keep the resolver address in the symbol table for IRELATIVE addends.
        let iplt_address = if symbol.is_ifunc()
            && matches!(
                ty,
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
        let operands = Operands {
            symbol: address,
            addend: relocation.addend,
            place,
            got_slot,
            tls_offset,
            iplt_address,
        };
        let site = RelocationSite {
            ty,
            symbol: &symbol.name,
            place,
        };
        let value = x86_64::compute(ty, &operands).with_context(|| {
            format!(
                "relocation {ty:?} for symbol '{}' at {place:#x}",
                symbol.name
            )
        })?;
        let data = sections[location.output_idx]
            .data
            .as_mut()
            .context("relocation output section has no data")?;
        x86_64::write_value(data, offset, value, &site)?;
    }
    Ok(())
}

fn initialize_got(layout: &mut Layout, got: &Got, symbols: &SymbolTable) -> Result<()> {
    for (entry, offset) in got.entries() {
        let (GotEntry::Address(id) | GotEntry::TpOff(id) | GotEntry::Ifunc(id)) = entry;
        let symbol = symbols.get(id);
        let address = *symbol
            .address
            .get()
            .with_context(|| format!("GOT target has no output address: {}", symbol.name))?;
        let bytes = match entry {
            GotEntry::Address(_) => address.to_le_bytes(),
            GotEntry::TpOff(_) => layout
                .tls
                .context("TLS GOT entry has no TLS segment")?
                .tpoff(address)
                .with_context(|| {
                    format!("invalid TLS GOT target: {} at {address:#x}", symbol.name)
                })?
                .to_le_bytes(),
            // Startup applies IRELATIVE before IFUNC calls. Leave the slot
            // zero until it stores the resolver's result.
            GotEntry::Ifunc(_) => continue,
        };
        SyntheticSection::Got.write(&mut layout.sections, &layout.section_index, offset, &bytes)?;
    }
    Ok(())
}
