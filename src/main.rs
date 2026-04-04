use std::{mem::MaybeUninit, ptr};

use clap::Parser;

#[macro_use]
pub mod debug;

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

fn main() {
    let args = Args::parse();
    // # Safety
    // This is safe because we only write to DEBUG_LEVEL once and it is not accessed before
    unsafe {
        ptr::write((&raw mut DEBUG_LEVEL) as *mut u8, args.debug);
    }

    pr_debug!("Arguments: {:?}", args);
}
