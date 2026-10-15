//! Show stage results and write an optional link map.
//!
//! [`Reporter`] takes [`Options`] and borrows each stage's result. It keeps file
//! names and archive reasons so [`trace`] and [`map`] can explain where bytes and
//! symbols came from. Traces go to stderr; the map goes to the chosen file.
//!
//! Like GNU ld's map, the archive list names the member, the file that needed
//! it, and the missing symbol. Other rows show ELF sections, segment flags,
//! and relocation values. We collect per-relocation details only for a trace.
//!
//! References: [GNU ld map and trace options](https://sourceware.org/binutils/docs/ld/Options.html);
//! ELF gABI "Sections", "Symbol Table", and "Program Header"; AMD64 psABI §4.4.1.

mod map;
mod trace;

use std::{collections::HashMap, path::PathBuf};

use anyhow::{Context, Result};
use clap::Args;

use crate::{
    input::{FileId, LoadedInputs},
    layout::LinkedImage,
    relocate::AppliedRelocation,
    script::mapping::SectionMapping,
    symbols::{ArchiveExtraction, ExtractedObjects, SymbolTable},
    synthetic::SyntheticSections,
};
use trace::Phase;

/// Choose trace stages and a map path without changing which inputs enter the link.
#[derive(Args, Debug)]
pub(crate) struct Options {
    /// Trace stages: inputs, archive, symbols, mapping, got, layout, relocations
    #[arg(long, value_delimiter = ',', value_name = "PHASE")]
    trace: Vec<Phase>,

    /// Show relocations for this exact symbol name (repeatable)
    #[arg(long, value_name = "NAME")]
    trace_symbol: Vec<String>,

    /// Write a link map (also accepts -Map FILE and -Map=FILE)
    #[arg(long, visible_alias = "Map", value_name = "FILE")]
    map: Option<PathBuf>,
}

/// Keep file names and archive reasons long enough to explain the final image.
pub(crate) struct Reporter {
    options: Options,
    files: HashMap<FileId, String>,
    extractions: Vec<ArchiveExtraction>,
}

impl Reporter {
    pub(crate) fn new(options: Options) -> Self {
        Self {
            options,
            files: HashMap::from([(FileId::LinkerGenerated, "<linker>".to_string())]),
            extractions: Vec::new(),
        }
    }

    pub(crate) fn inputs(&self, inputs: &LoadedInputs) -> Result<()> {
        self.emit(Phase::Inputs, || Ok(trace::inputs(inputs)))
    }

    /// Keep object names and, if a map needs them, the reasons for pulling members.
    pub(crate) fn archive(&mut self, objects: &ExtractedObjects) -> Result<()> {
        for object in &objects.files {
            self.files.insert(object.file_id, object.file_name.clone());
        }
        if self.options.map.is_some() {
            self.extractions = objects.extractions.clone();
        }
        self.emit(Phase::Archive, || Ok(trace::archive(objects, self)))
    }

    pub(crate) fn mapping(&self, mapping: &SectionMapping) -> Result<()> {
        self.emit(Phase::Mapping, || Ok(trace::mapping(mapping, self)))
    }

    pub(crate) fn symbols(&self, symbols: &SymbolTable) -> Result<()> {
        self.emit(Phase::Symbols, || Ok(trace::symbols(symbols, self)))
    }

    pub(crate) fn synthetic(
        &self,
        synthetic: &SyntheticSections,
        symbols: &SymbolTable,
    ) -> Result<()> {
        self.emit(Phase::Got, || trace::got(synthetic, symbols))
    }

    pub(crate) fn layout(&self, image: &LinkedImage) -> Result<()> {
        self.emit(Phase::Layout, || trace::layout(image))
    }

    /// `None` skips patch records; an empty list records all; names filter exact matches.
    pub(crate) fn relocation_symbols(&self) -> Option<&[String]> {
        self.options
            .trace
            .contains(&Phase::Relocations)
            .then_some(self.options.trace_symbol.as_slice())
    }

    pub(crate) fn relocations(
        &self,
        image: &LinkedImage,
        relocations: &[AppliedRelocation],
    ) -> Result<()> {
        self.emit(Phase::Relocations, || {
            Ok(trace::relocations(image, relocations, self))
        })
    }

    /// Write the optional map after addresses are final, with context on file errors.
    pub(crate) fn write_map(&self, image: &LinkedImage) -> Result<()> {
        if let Some(path) = &self.options.map {
            std::fs::write(path, map::render(image, self))
                .with_context(|| format!("failed to write link map: {}", path.display()))?;
        }
        Ok(())
    }

    fn file_name(&self, id: FileId) -> &str {
        self.files
            .get(&id)
            .map(String::as_str)
            .unwrap_or("<unknown>")
    }

    fn emit(&self, phase: Phase, render: impl FnOnce() -> Result<String>) -> Result<()> {
        if self.options.trace.contains(&phase) {
            use std::io::Write;
            std::io::stderr().lock().write_all(render()?.as_bytes())?;
        }
        Ok(())
    }
}
