//! Read command-line options for the link.
//!
//! [`parse`] turns process arguments into [`Args`]: input paths in search order,
//! an output path, an optional script, and [`report::Options`].
//! GNU ld accepts `-Map` with one dash. We change that spelling for clap before
//! parsing; `--` still ends option parsing.
//!
//! Reference: [GNU ld options](https://sourceware.org/binutils/docs/ld/Options.html).

use std::{ffi::OsString, os::unix::ffi::OsStringExt};

use clap::Parser;

use crate::report;

/// Input order matters: an archive cannot meet a reference from a later object.
///
/// Keep clap's command description empty so Rust docs do not change CLI help.
#[derive(Parser, Debug)]
#[command(about = None, long_about = None)]
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

/// Read process arguments; clap prints help or errors and exits when needed.
pub(crate) fn parse() -> Args {
    Args::parse_from(gnu_style_arguments())
}

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
