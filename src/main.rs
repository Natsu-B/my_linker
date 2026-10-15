use std::{mem::MaybeUninit, ptr};

use clap::Parser;

#[macro_use]
mod debug;
mod input;
mod layout;
mod output;
mod relocate;
mod script;
mod symbols;
mod synthetic;
#[cfg(test)]
mod test_utils;

#[derive(Parser, Debug)]
struct Args {
    /// Output file
    #[clap(short, long, required = true)]
    output: String,

    /// Linker script (replaces the built-in static x86-64 script)
    #[clap(short = 'T', long, value_name = "FILE")]
    script: Option<String>,

    /// Input file
    #[clap(value_name = "InputFile", required = true)]
    input: Vec<String>,

    /// Debug Level 0: None, 1: Error, 2: Warning, 3: Info, 4: Debug
    #[clap(short, long, default_value_t = 2)]
    debug: u8,
}

static mut DEBUG_LEVEL: MaybeUninit<u8> = MaybeUninit::new(0);

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // # Safety
    // This is safe because we only write to DEBUG_LEVEL once and it is not accessed before.
    unsafe {
        ptr::write((&raw mut DEBUG_LEVEL) as *mut u8, args.debug);
    }

    pr_debug!("Arguments: {:?}", args);

    // Linker script: parse the output-section rules and expressions.
    let script = script::parse_script(args.script.as_deref())?;
    // Input files: mmap and parse objects and archive indexes in parallel.
    let mut storage = input::MappedFiles::default();
    let files = input::load(&args.input, &mut storage)?;
    // Archive extraction: select members needed by strong undefined references.
    let objects = symbols::extract_archive_members(files, script.entry_name())?;
    // Script mapping: assign input sections to output-section rules.
    let mapping = script::map_sections(&script, objects)?;
    // Symbol resolution: select definitions before assigning addresses.
    let symbols = symbols::resolve(&mapping)?;
    // Synthetic sections: size the reserved GOT, IPLT and IRELATIVE inputs.
    let synthetic = synthetic::build(mapping, &symbols)?;
    // Layout: assign section and symbol addresses, including the entry point.
    let mut image = layout::assign_addresses(synthetic, symbols, script.entry_name())?;
    // Relocation: compute and write references using the final addresses.
    relocate::apply(&mut image)?;
    // Output: emit the executable and its section and symbol tables.
    output::write(image, args.output)?;
    Ok(())
}
