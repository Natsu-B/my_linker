//! Turn each stage's result into a stable text view.
//!
//! [`Phase`] chooses which views to show. Functions take stage results and
//! [`Reporter`] file names and return text. Rows follow input or section order;
//! named symbols sort by name so hash-map order cannot change the output.
//!
//! Relocation rows show the symbol address S, addend A, patch address P, and
//! result, plus GOT, TLS, or stub values when needed. The views use our own
//! format; GNU ld's trace option serves the same need to show input choices.
//!
//! References: ELF gABI "Sections", "Symbol Table", and "Program Header";
//! AMD64 psABI §4.4.1; [GNU ld trace](https://sourceware.org/binutils/docs/ld/Options.html).

use std::{fmt::Write, str::FromStr};

use anyhow::Result;
use elf::{Elf64ProgramHeaderFlags, Elf64SymbolBinding, x86_64::X86_64RelocationType};

use super::Reporter;
use crate::{
    input::{InputFile, LoadedInputs},
    layout::{LinkedImage, segments::load_segment_layouts},
    relocate::AppliedRelocation,
    script::mapping::{MappedItem, MappedStatement, SectionMapping},
    symbols::{Definition, ExtractedObjects, SymbolTable},
    synthetic::{GotEntry, SyntheticSections},
};

/// Choose a stage view separately from the log level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Inputs,
    Archive,
    Symbols,
    Mapping,
    Got,
    Layout,
    Relocations,
}

impl FromStr for Phase {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "inputs" => Ok(Self::Inputs),
            "archive" => Ok(Self::Archive),
            "symbols" => Ok(Self::Symbols),
            "mapping" => Ok(Self::Mapping),
            "got" => Ok(Self::Got),
            "layout" => Ok(Self::Layout),
            "relocations" => Ok(Self::Relocations),
            _ => Err(format!(
                "unknown trace phase '{value}'; valid phases: inputs, archive, symbols, mapping, got, layout, relocations"
            )),
        }
    }
}

pub(super) fn inputs(inputs: &LoadedInputs) -> String {
    let mut text = String::from("[inputs]\nKIND     MEMBERS FILE\n");
    for input in &inputs.files {
        let (kind, count, name) = match input {
            InputFile::Object(object) => ("object", 0, &object.file_name),
            InputFile::Archive(archive) => ("archive", archive.members.len(), &archive.file_name),
        };
        writeln!(text, "{kind:<8} {count:>7} {name}").unwrap();
    }
    text
}

pub(super) fn archive(objects: &ExtractedObjects, report: &Reporter) -> String {
    let mut text = String::from("[archive]\nMEMBER <- FILE (SYMBOL)\n");
    for extraction in &objects.extractions {
        let file = extraction
            .referencer
            .map(|id| report.file_name(id))
            .unwrap_or("<entry>");
        writeln!(
            text,
            "{} <- {file} ({})",
            extraction.member, extraction.symbol
        )
        .unwrap();
    }
    text
}

pub(super) fn symbols(symbols: &SymbolTable, report: &Reporter) -> String {
    let mut text = String::from("[symbols]\nSYMBOL BINDING TYPE DEFINITION\n");
    let mut symbols = symbols.named_symbols().collect::<Vec<_>>();
    symbols.sort_by_key(|symbol| &symbol.name);
    for symbol in symbols {
        let definition = match symbol.definition {
            Definition::Input { file_id, .. } => report.file_name(file_id).to_string(),
            Definition::Script { provide: None } => "<script>".to_string(),
            Definition::Script { provide: Some(_) } => {
                if symbol.binding == Elf64SymbolBinding::STB_LOCAL {
                    "<script> PROVIDE_HIDDEN"
                } else {
                    "<script> PROVIDE"
                }
                .to_string()
            }
            Definition::UndefinedWeak => "undefined weak -> 0".to_string(),
        };
        writeln!(
            text,
            "{} {:?} {} {definition}",
            symbol.name,
            symbol.binding,
            symbol
                .ty
                .map_or("<none>".to_string(), |ty| format!("{ty:?}")),
        )
        .unwrap();
    }
    text
}

pub(super) fn mapping(mapping: &SectionMapping, report: &Reporter) -> String {
    let mut text = String::from("[mapping]\nOUTPUT <- FILE(SECTION)\n");
    for item in &mapping.items {
        if let MappedItem::Output(output) = item {
            if output.statements.is_empty() {
                continue;
            }
            writeln!(
                text,
                "{}{}",
                output.name,
                if output.orphan { " [orphan]" } else { "" }
            )
            .unwrap();
            for statement in &output.statements {
                if let MappedStatement::Input(index) = statement {
                    let input = &mapping.inputs[*index].section;
                    writeln!(
                        text,
                        "  {}({})",
                        report.file_name(input.file_id),
                        input.name
                    )
                    .unwrap();
                }
            }
        }
    }
    text
}

pub(super) fn got(synthetic: &SyntheticSections, symbols: &SymbolTable) -> Result<String> {
    // Addresses wait for layout. Input names and offsets still let the reader
    // follow each stub to its GOT slot and startup record.
    let mut text = String::from("[got]\nINPUT+OFFSET KIND SYMBOL CONTENTS\n");
    for (entry, offset) in synthetic.got.entries() {
        let (GotEntry::Address(id) | GotEntry::TpOff(id) | GotEntry::Ifunc(id)) = entry;
        let symbol = &symbols.get(id).name;
        let (kind, contents) = match entry {
            GotEntry::Address(_) => ("address", format!("address({symbol})")),
            GotEntry::TpOff(_) => ("tpoff", format!("tpoff({symbol})")),
            GotEntry::Ifunc(_) => ("ifunc", "0 (filled at startup)".to_string()),
        };
        writeln!(text, ".got+{offset:#x} {kind} {symbol} {contents}").unwrap();
    }
    for entry in synthetic.iplt.entries() {
        let symbol = &symbols.get(entry.symbol).name;
        let offset = synthetic.got.offset(GotEntry::Ifunc(entry.symbol))?;
        writeln!(
            text,
            ".iplt+{:#x} stub {symbol} jmp *.got+{offset:#x}",
            entry.stub_offset,
        )
        .unwrap();
        writeln!(
            text,
            ".rela.iplt+{:#x} R_X86_64_IRELATIVE {symbol} offset=.got+{offset:#x} addend=address({symbol})",
            entry.relocation_offset,
        ).unwrap();
    }
    Ok(text)
}

pub(super) fn permissions(flags: Elf64ProgramHeaderFlags) -> String {
    [
        (flags.get(Elf64ProgramHeaderFlags::readable), 'R'),
        (flags.get(Elf64ProgramHeaderFlags::writable), 'W'),
        (flags.get(Elf64ProgramHeaderFlags::executable), 'X'),
    ]
    .into_iter()
    .map(|(set, letter)| if set != 0 { letter } else { '-' })
    .collect()
}

pub(super) fn layout(image: &LinkedImage) -> Result<String> {
    let layout = &image.layout;
    let mut text = String::from("[layout]\nSECTION ADDRESS SIZE ALIGN FLAGS\n");
    for section in &layout.sections {
        writeln!(
            text,
            "{} {:#018x} {:#x} {:#x} {}",
            section.name,
            section.address.get().unwrap(),
            section.size,
            section.align,
            permissions(section.flags),
        )
        .unwrap();
    }
    writeln!(text, "SEGMENT ADDRESS FILESZ MEMSZ ALIGN FLAGS").unwrap();
    for segment in load_segment_layouts(&layout.sections, &layout.headers, layout.tls)? {
        writeln!(
            text,
            "PT_LOAD {:#018x} {:#x} {:#x} {:#x} {}",
            segment.address,
            segment.file_size,
            segment.mem_size,
            segment.align,
            permissions(segment.flags),
        )
        .unwrap();
    }
    if let Some(tls) = layout.tls {
        writeln!(
            text,
            "PT_TLS {:#018x} {:#x} {:#x} {:#x} R--",
            tls.vaddr, tls.file_size, tls.mem_size, tls.align,
        )
        .unwrap();
    }
    Ok(text)
}

pub(super) fn relocations(
    image: &LinkedImage,
    relocations: &[AppliedRelocation],
    report: &Reporter,
) -> String {
    let mut text = String::from("[relocations]\nTYPE P S A VALUE SYMBOL FILE\n");
    for relocation in relocations {
        let name = relocation
            .symbol
            .map(|id| image.symbols.get(id).name.as_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("<none>");
        write!(
            text,
            "{} {:#018x} {:#018x} {} {} {name} {}",
            relocation_name(relocation.ty),
            relocation.place,
            relocation.address,
            signed_hex(i128::from(relocation.addend)),
            signed_hex(relocation.value),
            report.file_name(relocation.file_id),
        )
        .unwrap();
        if let Some(slot) = relocation.got_slot {
            write!(text, " GOT={slot:#x}").unwrap();
        }
        if let Some(offset) = relocation.tls_offset {
            write!(text, " TP={}", signed_hex(i128::from(offset))).unwrap();
        }
        if let Some(stub) = relocation.iplt_address {
            write!(text, " L={stub:#x}").unwrap();
        }
        text.push('\n');
    }
    text
}

/// Show a negative addend or displacement as `-0x4`, not an unsigned bit pattern.
fn signed_hex(value: i128) -> String {
    if value < 0 {
        format!("-{:#x}", value.unsigned_abs())
    } else {
        format!("{value:#x}")
    }
}

fn relocation_name(ty: X86_64RelocationType) -> &'static str {
    use X86_64RelocationType::*;
    match ty {
        None => "R_X86_64_NONE",
        R64 => "R_X86_64_64",
        R32 => "R_X86_64_32",
        R32S => "R_X86_64_32S",
        Pc32 => "R_X86_64_PC32",
        Plt32 => "R_X86_64_PLT32",
        GotPcRel => "R_X86_64_GOTPCREL",
        GotPcRelX => "R_X86_64_GOTPCRELX",
        RexGotPcRelX => "R_X86_64_REX_GOTPCRELX",
        GotTpOff => "R_X86_64_GOTTPOFF",
        TpOff32 => "R_X86_64_TPOFF32",
        TpOff64 => "R_X86_64_TPOFF64",
        _ => unreachable!("only supported relocation types reach reporting"),
    }
}
