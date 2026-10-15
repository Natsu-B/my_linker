//! Read the rules that choose sections and set addresses.
//!
//! [`parse_script`] takes an optional path and returns an [`ast::Script`].
//! Without a path it uses [`DEFAULT_SCRIPT`]. [`mapping`] matches input sections
//! to the rules; [`eval`] computes expressions during layout.
//!
//! The script's location counter, `.`, is the address where the next bytes go.
//! ENTRY names the start symbol. We read it before archive search so that name
//! can pull a member. The syntax follows the GNU ld subset this linker supports.
//!
//! References: [GNU ld scripts](https://sourceware.org/binutils/docs/ld/Scripts.html);
//! ELF gABI "Sections" and "Symbol Table".

pub(crate) mod ast;
pub(crate) mod eval;
mod lexer;
pub(crate) mod mapping;
pub(crate) mod parser;
pub(crate) mod pattern;

pub(crate) use mapping::map_sections;

use anyhow::{Context, Result};

use ast::{Script, Statement};

pub(crate) const DEFAULT_SCRIPT: &str = include_str!("elf_x86_64_static.ld");

/// Read `-T` or the built-in script, and report syntax errors with the source name.
pub(crate) fn parse_script(path: Option<&str>) -> Result<Script> {
    pr_debug!("Parsing script...");

    let source = match path {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("failed to read linker script {path}"))?,
        None => DEFAULT_SCRIPT.to_string(),
    };
    parser::parse(&source).with_context(|| {
        format!(
            "failed to parse linker script {}",
            path.unwrap_or("<built-in>")
        )
    })
}

impl ast::Script {
    /// Use the last ENTRY command; without one, start at `_start`.
    pub(crate) fn entry_name(&self) -> &str {
        self.statements
            .iter()
            .rev()
            .find_map(|statement| {
                if let Statement::Entry(name) = statement {
                    Some(name.as_str())
                } else {
                    None
                }
            })
            .unwrap_or("_start")
    }
}
