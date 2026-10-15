//! Pick the objects to link, then pick each symbol's definition.
//!
//! [`extract_archive_members`] takes loaded inputs and returns [`ExtractedObjects`]
//! with the reasons for pulling archive members. After section mapping,
//! [`resolve()`] returns a [`SymbolTable`]. Each [`SymbolId`] points to one
//! definition, so references to the same global share a result.
//!
//! Picking a definition does not set its address. Layout sets [`ResolvedSymbol`]
//! values after it places the sections. Like GNU ld, a strong definition beats a
//! weak one, and an undefined weak symbol can stay at zero.
//!
//! References: ELF gABI "Symbol Binding" and "Symbol Value"; AMD64 psABI §4.3;
//! GNU ld archive search and [`PROVIDE`](https://sourceware.org/binutils/docs/ld/PROVIDE.html).

mod extract;
mod resolve;
mod table;

pub(crate) use extract::{ArchiveExtraction, ExtractedObjects, extract_archive_members};
pub(crate) use resolve::resolve;
#[cfg(test)]
pub(crate) use resolve::resolve_inputs;
pub(crate) use table::{Definition, ResolvedSymbol, SymbolId, SymbolTable};
