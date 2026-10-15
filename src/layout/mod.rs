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
    input::{FileId, object::InputSection},
    script::mapping::{MappedItem, MappingInput},
    symbols::SymbolTable,
};
use place::SectionPlacer;
use segments::load_segment_count;
use tls::TlsSegment;

pub(crate) const PAGE_SIZE: u64 = 0x1000;

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
    items: &[MappedItem],
    inputs: &[MappingInput<'a>],
    symbols: &SymbolTable,
) -> Result<Layout<'a>> {
    // PT_LOAD groups, PT_GNU_STACK and optional PT_TLS. Reevaluate
    // SIZEOF_HEADERS when the count differs from the initial estimate.
    let mut phnum = 2;
    for _ in 0..8 {
        let sizeof_headers = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE * phnum;
        let mut layout = SectionPlacer::new(symbols, sizeof_headers);
        let sections = layout.place(items, inputs)?;
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
            return Ok(Layout {
                sections,
                section_index,
                headers,
                script_symbols,
                tls,
            });
        }
        phnum = actual_phnum;
    }
    bail!("script layout did not converge after updating SIZEOF_HEADERS")
}
