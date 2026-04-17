use std::{collections::HashSet, mem::MaybeUninit, ptr};

use anyhow::{Context, Result};
use clap::Parser;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::{
    archive_index::ArchiveState, input_id::FileId, input_symbol::FileType, parse::ObjectFile,
};

#[macro_use]
pub mod debug;
mod archive;
mod archive_index;
mod input_id;
mod input_symbol;
mod link;
mod open;
mod parse;
mod relocate;
mod resolve;
pub mod script;
#[cfg(test)]
mod test_utils;
mod write;

#[derive(Parser, Debug)]
struct Args {
    /// Output file
    #[clap(short, long, required = true)]
    output: String,

    /// Input file
    #[clap(value_name = "InputFile", required = true)]
    input: Vec<String>,

    /// Debug Level 0: None, 1: Error, 2: Warning, 3: Info, 4: Debug
    #[clap(short, long, default_value_t = 2)]
    debug: u8,
}

static mut DEBUG_LEVEL: MaybeUninit<u8> = MaybeUninit::uninit();

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // # Safety
    // This is safe because we only write to DEBUG_LEVEL once and it is not accessed before.
    unsafe {
        ptr::write((&raw mut DEBUG_LEVEL) as *mut u8, args.debug);
    }

    pr_debug!("Arguments: {:?}", args);

    script::parse_script()?;

    let mmaps_result = args
        .input
        .par_iter()
        .map(open::open_file_and_mmap)
        .collect::<Vec<Result<_>>>();

    let mut has_err = 0;
    let mut mmaps = Vec::with_capacity(mmaps_result.len());

    for mmap_result in mmaps_result.iter().zip(&args.input) {
        match mmap_result {
            (Ok(mmap), _) => mmaps.push(mmap),
            (Err(err), file_name) => {
                debugs_or!(
                    pr_err!("file:{}: {:?}", file_name, err),
                    pr_err!("file:{}: {}", file_name, err)
                );
                has_err += 1;
            }
        }
    }

    anyhow::ensure!(has_err == 0, "{} file(s) failed to open", has_err);

    pr_debug!("Start parsing files...");
    let parse_result = mmaps
        .par_iter()
        .zip(args.input.par_iter())
        .enumerate()
        .map(|(input_idx, (mmap, file_name))| {
            if elf::Elf64::check_elf_magic(mmap) {
                parse::parse(mmap, file_name.clone(), FileId::Object(input_idx))
                    .map(FileType::Object)
            } else {
                archive_index::index_archive(mmap, file_name.clone(), input_idx)
                    .map(FileType::Archive)
            }
        })
        .collect::<Vec<Result<_>>>();

    let parsed = input_symbol::resolve_symbols(parse_result)?;

    pr_debug!("Start linking files...");
    let mut linked = link::link(parsed)?;
    resolve::resolve(&linked.0, &mut linked.1)?;
    let entry = relocate::relocate(&mut linked.0, linked.1, linked.2, &linked.3)?;
    write::output(linked.0, linked.3, args.output, entry)?;

    Ok(())
}
