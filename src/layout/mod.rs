//! Set section and symbol addresses for the executable.
//!
//! [`assign_addresses`] takes sized inputs and chosen definitions and returns a
//! [`LinkedImage`]. [`OutputSection`] holds the joined bytes; [`SectionIndex`]
//! finds each input's offset within them. [`HeaderInfo`] marks space for the ELF
//! and program headers. The entry address tells the kernel where to start.
//!
//! SIZEOF_HEADERS depends on the segment count. A script can use that size to
//! move sections, which can change the segment count again. We repeat the pass
//! until the count agrees with the size the script used.
//!
//! References: ELF gABI "Program Header", "Segment Permissions", and "Thread-Local
//! Storage"; AMD64 psABI §5.1; GNU ld [SIZEOF_HEADERS](https://sourceware.org/binutils/docs/ld/Builtin-Functions.html).

mod place;
pub(crate) mod segments;
pub(crate) mod tls;

use std::{cell::OnceCell, collections::HashMap};

use anyhow::{Context, Result, bail};
use elf::{
    Elf64ProgramHeaderFlags,
    write::{ELF_HEADER_SIZE, PROGRAM_HEADER_SIZE},
};

use crate::{
    input::{
        FileId,
        object::{InputSection, ObjectRelocation},
    },
    symbols::SymbolTable,
    synthetic::{Got, Iplt, SyntheticSections},
};
use place::SectionPlacer;
use segments::load_segment_count;
use tls::TlsSegment;

pub(crate) const PAGE_SIZE: u64 = 0x1000;

/// Hold the placed bytes, final symbols, and relocation plans for the rest of the link.
pub(crate) struct LinkedImage<'a> {
    pub(crate) layout: Layout<'a>,
    pub(crate) symbols: SymbolTable,
    pub(crate) relocations: Vec<ObjectRelocation>,
    pub(crate) got: Got,
    pub(crate) iplt: Iplt,
    pub(crate) entry: u64,
}

/// Join input sections with alignment gaps and padding from script assignments.
pub(crate) struct OutputSection<'a> {
    pub(crate) name: String,
    pub(crate) flags: Elf64ProgramHeaderFlags,
    /// Memory size, including gaps even when no file bytes cover them.
    pub(crate) size: u64,
    pub(crate) align: u64,
    pub(crate) address: OnceCell<u64>,
    /// `None` means zero fill only. `size` may exceed the stored bytes.
    pub(crate) data: Option<Vec<u8>>,
    /// Each input and its byte offset from this output section's start.
    pub(crate) inputs: Vec<(InputSection<'a>, u64)>,
}

/// Reserve memory for file offset zero through the last program header.
pub(crate) struct HeaderInfo {
    pub(crate) address: u64,
    pub(crate) size: u64,
}

/// Keep both a script symbol's value and which section it belongs to.
pub(crate) struct ScriptSymbols {
    pub(crate) values: HashMap<String, u64>,
    /// Output indices; a missing name means the symbol's value is absolute.
    pub(crate) sections: HashMap<String, usize>,
}

/// Share placed sections, input offsets, script values, and TLS bounds with later steps.
pub(crate) struct Layout<'a> {
    pub(crate) sections: Vec<OutputSection<'a>>,
    pub(crate) section_index: SectionIndex,
    pub(crate) headers: HeaderInfo,
    pub(crate) script_symbols: ScriptSymbols,
    pub(crate) tls: Option<TlsSegment>,
}

/// Find an input's first byte in the placed output sections.
pub(crate) struct SectionLocation {
    /// Index in the output-section vector, not an ELF section number.
    pub(crate) output_idx: usize,
    /// Byte offset within that output section.
    pub(crate) offset: u64,
}

/// Find each input section by its original file ID and section index.
pub(crate) type SectionIndex = HashMap<(FileId, u16), SectionLocation>;

/// Place sections and set final symbol and entry addresses.
///
/// Repeat while SIZEOF_HEADERS changes with the program-header count.
/// Fail after eight passes if the count does not settle.
pub(crate) fn assign_addresses<'a>(
    synthetic: SyntheticSections<'a, '_>,
    symbols: SymbolTable,
    entry_name: &str,
) -> Result<LinkedImage<'a>> {
    let SyntheticSections { mapping, got, iplt } = synthetic;
    // Adding a load or PT_TLS changes SIZEOF_HEADERS. A script can use that
    // size to move sections and change the load count again, so repeat until
    // the count matches the size used in the pass.
    let mut phnum = 2;
    for _ in 0..8 {
        let sizeof_headers = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE * phnum;
        let mut placer = SectionPlacer::new(&symbols, sizeof_headers);
        let sections = placer.place(&mapping.items, &mapping.inputs)?;
        let tls = TlsSegment::from_sections(&sections)?;
        let actual_phnum = load_segment_count(&sections) + 1 + u64::from(tls.is_some());
        if actual_phnum == phnum {
            let headers = HeaderInfo {
                address: placer
                    .header_address
                    .context("script places no allocatable output sections")?,
                size: sizeof_headers,
            };
            let script_symbols = placer.into_script_symbols();
            let section_index = index_sections(&sections);
            symbols.assign_addresses(&sections, &section_index, &script_symbols.values)?;
            let entry = symbols
                .named(entry_name)
                .and_then(|symbol| symbol.address.get().copied())
                .context("Failed to find entry point")?;
            return Ok(LinkedImage {
                layout: Layout {
                    sections,
                    section_index,
                    headers,
                    script_symbols,
                    tls,
                },
                symbols,
                entry,
                relocations: mapping.relocations,
                got,
                iplt,
            });
        }
        phnum = actual_phnum;
    }
    bail!("script layout did not converge after updating SIZEOF_HEADERS")
}

fn index_sections(sections: &[OutputSection]) -> SectionIndex {
    sections
        .iter()
        .enumerate()
        .flat_map(|(output_idx, section)| {
            section.inputs.iter().map(move |(input, offset)| {
                (
                    (input.file_id, input.idx),
                    SectionLocation {
                        output_idx,
                        offset: *offset,
                    },
                )
            })
        })
        .collect()
}
