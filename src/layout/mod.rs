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

pub(crate) struct LinkedImage<'a> {
    pub(crate) layout: Layout<'a>,
    pub(crate) symbols: SymbolTable,
    pub(crate) relocations: Vec<ObjectRelocation>,
    pub(crate) got: Got,
    pub(crate) iplt: Iplt,
    pub(crate) entry: u64,
}

pub(crate) struct OutputSection<'a> {
    pub(crate) name: String,
    pub(crate) flags: Elf64ProgramHeaderFlags,
    pub(crate) size: u64,
    pub(crate) align: u64,
    pub(crate) address: OnceCell<u64>,
    pub(crate) data: Option<Vec<u8>>,
    pub(crate) inputs: Vec<(InputSection<'a>, u64 /* offset */)>,
}

pub(crate) struct HeaderInfo {
    pub(crate) address: u64,
    pub(crate) size: u64,
}

pub(crate) struct ScriptSymbols {
    pub(crate) values: HashMap<String, u64>,
    pub(crate) sections: HashMap<String, usize>,
}

pub(crate) struct Layout<'a> {
    pub(crate) sections: Vec<OutputSection<'a>>,
    pub(crate) section_index: SectionIndex,
    pub(crate) headers: HeaderInfo,
    pub(crate) script_symbols: ScriptSymbols,
    pub(crate) tls: Option<TlsSegment>,
}

pub(crate) struct SectionLocation {
    pub(crate) output_idx: usize,
    pub(crate) offset: u64,
}

pub(crate) type SectionIndex = HashMap<(FileId, u16), SectionLocation>;

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

pub(crate) fn assign_addresses<'a>(
    synthetic: SyntheticSections<'a, '_>,
    symbols: SymbolTable,
    entry_name: &str,
) -> Result<LinkedImage<'a>> {
    let SyntheticSections { mapping, got, iplt } = synthetic;
    // SIZEOF_HEADERS includes the program-header table, whose length depends
    // on PT_LOAD groups and optional PT_TLS. Script expressions using that size
    // can move sections and change the groups again, so repeat placement until
    // the program-header count agrees with the size used to evaluate the script.
    let mut phnum = 2;
    for _ in 0..8 {
        let sizeof_headers = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE * phnum;
        let mut layout = SectionPlacer::new(&symbols, sizeof_headers);
        let sections = layout.place(&mapping.items, &mapping.inputs)?;
        let tls = TlsSegment::from_sections(&sections)?;
        let actual_phnum = load_segment_count(&sections) + 1 + u64::from(tls.is_some());
        if actual_phnum == phnum {
            let headers = HeaderInfo {
                address: layout
                    .header_vaddr
                    .context("script places no allocatable output sections")?,
                size: sizeof_headers,
            };
            let script_symbols = ScriptSymbols {
                values: layout.script_symbols,
                sections: layout.script_symbol_sections,
            };
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
