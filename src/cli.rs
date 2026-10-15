//! Command-line interface. GNU ld spells some long options with one dash
//! (`-Map`), which clap does not accept, so those are rewritten first.

use std::{ffi::OsString, os::unix::ffi::OsStringExt};

use clap::Parser;

use crate::report;

#[derive(Parser, Debug)]
pub(crate) struct Args {
    #[command(flatten)]
    pub(crate) report: report::Options,

    /// Output file
    #[clap(short, long, required = true)]
    pub(crate) output: String,

    /// Linker script (replaces the built-in static x86-64 script)
    #[clap(short = 'T', long, value_name = "FILE")]
    pub(crate) script: Option<String>,

    /// Input file
    #[clap(value_name = "InputFile", required = true)]
    pub(crate) input: Vec<String>,

    /// Debug Level 0: None, 1: Error, 2: Warning, 3: Info, 4: Debug
    #[clap(short, long, default_value_t = 2)]
    pub(crate) debug: u8,
}

/// Parse the process arguments, accepting GNU ld's `-Map` spellings.
pub(crate) fn parse() -> Args {
    Args::parse_from(gnu_style_arguments())
}

/// Clap accepts GNU long options with two dashes. Translate ld's spelling
/// before parsing, preserving non-UTF-8 paths and the `--` positional boundary.
fn gnu_style_arguments() -> Vec<OsString> {
    let mut positional = false;
    std::env::args_os()
        .map(|arg| {
            if arg == "--" {
                positional = true;
            }
            if !positional {
                if arg == "-Map" {
                    return "--map".into();
                }
                if let Some(path) = arg.as_encoded_bytes().strip_prefix(b"-Map=") {
                    let mut option = b"--map=".to_vec();
                    option.extend_from_slice(path);
                    return OsString::from_vec(option);
                }
            }
            arg
        })
        .collect()
}
