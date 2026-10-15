pub mod ast;
pub mod eval;
mod lexer;
pub mod parser;

use anyhow::{Context, Result};

use ast::{Script, SectionStatement, Statement};

pub const DEFAULT_SCRIPT: &str = include_str!("elf_x86_64_static.ld");

/// Parse the linker script given by `-T`, or the built-in script.
pub fn parse_script(path: Option<&str>) -> Result<Script> {
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
    pub fn entry_name(&self) -> &str {
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

    // M2 bridge to the existing four-way layout. SIZEOF_HEADERS is zero here
    // because link.rs still reserves the header page itself. M3 will evaluate
    // the complete script with the actual headers and input sections.
    pub fn initial_address(&self) -> Result<u64> {
        let mut context = eval::Context {
            dot: 0x400000,
            ..Default::default()
        };
        for statement in &self.statements {
            match statement {
                Statement::Assignment(assignment) => {
                    if apply_initial_assignment(assignment, &mut context)? {
                        return Ok(context.dot);
                    }
                }
                Statement::Sections(statements) => {
                    for statement in statements {
                        match statement {
                            SectionStatement::Assignment(assignment) => {
                                if apply_initial_assignment(assignment, &mut context)? {
                                    return Ok(context.dot);
                                }
                            }
                            SectionStatement::Output(section) => {
                                return section.address.as_ref().map_or(Ok(context.dot), |expr| {
                                    eval::evaluate(expr, &context)
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(context.dot)
    }
}

fn apply_initial_assignment(
    assignment: &ast::Assignment,
    context: &mut eval::Context,
) -> Result<bool> {
    let value = eval::evaluate(&assignment.value, context)?;
    if assignment.name == "." {
        context.dot = value;
        Ok(true)
    } else {
        context.symbols.insert(assignment.name.clone(), value);
        Ok(false)
    }
}
