//! Show why archive members entered the link and where their bytes went.
//!
//! [`render`] takes a [`LinkedImage`] and [`Reporter`] and returns map text.
//! The archive list uses GNU ld's member, requesting file, and symbol format.
//! The body lists output sections and their input parts, then symbols sorted by
//! address and name. TLS values here are template addresses, as used inside
//! the linker; the ELF symbol table instead holds TLS offsets.
//!
//! References: [GNU ld map output](https://sourceware.org/binutils/docs/ld/Options.html);
//! ELF gABI "Sections" and "Symbol Value".

use std::fmt::Write;

use elf::Elf64SymbolType;

use super::Reporter;
use crate::layout::LinkedImage;

pub(super) fn render(image: &LinkedImage, report: &Reporter) -> String {
    let mut text = archive_preamble(report);
    text.push_str("Linker script and memory map\n\n");
    for output in &image.layout.sections {
        let address = *output.address.get().unwrap();
        writeln!(text, "{} {address:#018x} {:#x}", output.name, output.size).unwrap();
        for (input, offset) in &output.inputs {
            writeln!(
                text,
                " {} {:#018x} {:#x} {}",
                input.name,
                address + offset,
                input.size,
                report.file_name(input.file_id),
            )
            .unwrap();
        }
    }
    text.push_str("\nSymbol addresses\n\n");
    let mut symbols = image
        .symbols
        .all_symbols()
        .filter(|symbol| {
            !symbol.name.is_empty()
                && symbol.address.get().is_some()
                && !matches!(
                    symbol.ty,
                    Some(Elf64SymbolType::STT_FILE | Elf64SymbolType::STT_SECTION)
                )
        })
        .collect::<Vec<_>>();
    symbols.sort_by_key(|symbol| (*symbol.address.get().unwrap(), &symbol.name));
    for symbol in symbols {
        writeln!(
            text,
            " {:#018x} {}",
            symbol.address.get().unwrap(),
            symbol.name
        )
        .unwrap();
    }
    text
}

fn archive_preamble(report: &Reporter) -> String {
    let mut text =
        String::from("Archive member included to satisfy reference by file (symbol)\n\n");
    for extraction in &report.extractions {
        write!(text, "{}", extraction.member).unwrap();
        // Match GNU ld: the requesting file starts in column 30; long member
        // names force it onto the next line.
        if extraction.member.len() >= 30 {
            text.push('\n');
            text.push_str(&" ".repeat(30));
        } else {
            text.push_str(&" ".repeat(30 - extraction.member.len()));
        }
        if let Some(id) = extraction.referencer {
            write!(text, "{} ", report.file_name(id)).unwrap();
        }
        writeln!(text, "({})", extraction.symbol).unwrap();
    }
    text.push('\n');
    text
}
