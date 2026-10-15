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

/// Parse the linker script given by `-T`, or the built-in script.
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
