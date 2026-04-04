use std::{mem::MaybeUninit, ptr};

use anyhow::Result;
use clap::Parser;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::open::open_file_and_mmap;

#[macro_use]
pub mod debug;
mod open;

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
    // This is safe because we only write to DEBUG_LEVEL once and it is not accessed before
    unsafe {
        ptr::write((&raw mut DEBUG_LEVEL) as *mut u8, args.debug);
    }

    pr_debug!("Arguments: {:?}", args);

    // open files and create memory maps in parallel
    let mmaps_result = args
        .input
        .par_iter()
        .map(open_file_and_mmap)
        .collect::<Vec<Result<_>>>();

    let mut has_err = 0;
    let mut mmaps = Vec::with_capacity(mmaps_result.len());

    for mmap_result in mmaps_result {
        match mmap_result {
            Ok(mmap) => mmaps.push(mmap),
            Err(err) => {
                debugs_or!(pr_err!("{:?}", err), pr_err!("{}", err));
                has_err += 1;
            }
        }
    }

    anyhow::ensure!(has_err == 0, "{} file(s) failed to process", has_err);

    Ok(())
}
