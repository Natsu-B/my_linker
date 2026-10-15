//! Patch symbol references after layout has set all addresses.
//!
//! [`apply`] takes a [`LinkedImage`], fills linker-made bytes, and patches kept
//! relocations. It returns [`AppliedRelocation`] records only for requested
//! traces. File and section indices locate the patch; [`SymbolId`] finds the
//! chosen definition. [`x86_64`] computes and writes the value.
//!
//! A relocation's addend comes from the input RELA record, not the bytes we
//! patch. GOT references need the slot's address; TLS references need a thread
//! offset. Like GNU ld, direct IFUNC calls use a stub, while IRELATIVE records
//! keep the resolver address for startup.
//!
//! References: ELF gABI "Relocation"; AMD64 psABI §4.4.1.
//! This linker supports local-exec and initial-exec TLS.

mod x86_64;

use anyhow::{Context, Result};
use elf::x86_64::X86_64RelocationType;

use crate::{
    input::FileId,
    layout::{Layout, LinkedImage},
    symbols::{SymbolId, SymbolTable},
    synthetic::{Got, GotEntry, SyntheticSection},
};
use x86_64::{Operands, RelocationSite};

/// Fill GOT/IPLT bytes and patch all kept relocations using final addresses.
///
/// With no trace filter, keep no patch records. An empty filter records all
/// patches; a nonempty filter matches exact symbol names.
pub(crate) fn apply(
    image: &mut LinkedImage,
    trace_symbols: Option<&[String]>,
) -> Result<Vec<AppliedRelocation>> {
    let mut applied = Vec::new();
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
            // NONE does not use its symbol index. Tracing must not turn an
            // ignored, invalid index into a link error.
            if let Some(names) = trace_symbols {
                let symbol_id = symbols.input(relocation.file_id, relocation.info.sym).ok();
                let symbol = symbol_id.map(|id| symbols.get(id));
                if names.is_empty() || symbol.is_some_and(|symbol| names.contains(&symbol.name)) {
                    let place = sections[location.output_idx]
                        .address
                        .get()
                        .unwrap()
                        .checked_add(location.offset)
                        .and_then(|place| place.checked_add(relocation.offset))
                        .context("relocation place exceeds u64")?;
                    applied.push(AppliedRelocation {
                        file_id: relocation.file_id,
                        symbol: symbol_id,
                        ty,
                        place,
                        address: symbol
                            .and_then(|symbol| symbol.address.get().copied())
                            .unwrap_or(0),
                        addend: relocation.addend,
                        value: 0,
                        got_slot: None,
                        tls_offset: None,
                        iplt_address: None,
                    });
                }
            }
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

        // Patch a GOT reference with the slot's address, not its contents.
        // Startup fills IFUNC slots; initial-exec slots hold signed TP offsets.
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
        // Calls and function pointers need one shared IFUNC address: the stub.
        // Keep the resolver value too, since IRELATIVE must call it at startup.
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
        let computed = value.value;
        x86_64::write_value(data, offset, value, &site)?;
        if trace_symbols.is_some_and(|names| names.is_empty() || names.contains(&symbol.name)) {
            applied.push(AppliedRelocation {
                file_id: relocation.file_id,
                symbol: Some(symbol_id),
                ty,
                place,
                address,
                addend: relocation.addend,
                value: computed,
                got_slot,
                tls_offset,
                iplt_address,
            });
        }
    }
    Ok(applied)
}

/// Keep the inputs and result of one patch when its trace is requested.
pub(crate) struct AppliedRelocation {
    pub(crate) file_id: FileId,
    /// NONE may have no valid symbol index, so its trace can leave this unset.
    pub(crate) symbol: Option<SymbolId>,
    pub(crate) ty: X86_64RelocationType,
    /// P: virtual address of the field being patched.
    pub(crate) place: u64,
    /// S: final symbol value; for an IFUNC this still names the resolver.
    pub(crate) address: u64,
    /// A: signed addend from the input RELA record.
    pub(crate) addend: i64,
    /// Result before checking field range and writing bytes.
    pub(crate) value: i128,
    /// G + GOT: slot address, not the value stored in the slot.
    pub(crate) got_slot: Option<u64>,
    /// Signed offset from the thread pointer for local-exec TLS.
    pub(crate) tls_offset: Option<i64>,
    /// The shared IFUNC stub address used by direct references.
    pub(crate) iplt_address: Option<u64>,
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
            // Startup calls the resolver and fills this slot before any IFUNC
            // call. It has no function address to store yet.
            GotEntry::Ifunc(_) => continue,
        };
        SyntheticSection::Got.write(&mut layout.sections, &layout.section_index, offset, &bytes)?;
    }
    Ok(())
}
