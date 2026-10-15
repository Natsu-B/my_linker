use std::{mem::MaybeUninit, ptr};

mod cli;
#[macro_use]
mod debug;
mod input;
mod layout;
mod output;
mod relocate;
mod report;
mod script;
mod symbols;
mod synthetic;
#[cfg(test)]
mod test_utils;

static mut DEBUG_LEVEL: MaybeUninit<u8> = MaybeUninit::new(0);

fn main() -> anyhow::Result<()> {
    let args = cli::parse();

    // # Safety
    // This is safe because we only write to DEBUG_LEVEL once and it is not accessed before.
    unsafe {
        ptr::write((&raw mut DEBUG_LEVEL) as *mut u8, args.debug);
    }

    pr_debug!("Arguments: {:?}", args);

    let mut report = report::Reporter::new(args.report);

    // Linker script: parse the output-section rules and expressions.
    let script = script::parse_script(args.script.as_deref())?;
    // Input files: mmap and parse objects and archive indexes in parallel.
    let mut storage = input::MappedFiles::default();
    let files = input::load(&args.input, &mut storage)?;
    report.inputs(&files)?;
    // Archive extraction: select members needed by strong undefined references.
    let objects = symbols::extract_archive_members(files, script.entry_name())?;
    report.archive(&objects)?;
    // Script mapping: assign input sections to output-section rules.
    let mapping = script::map_sections(&script, objects)?;
    report.mapping(&mapping)?;
    // Symbol resolution: select definitions before assigning addresses.
    let symbols = symbols::resolve(&mapping)?;
    report.symbols(&symbols)?;
    // Synthetic sections: size the reserved GOT, IPLT and IRELATIVE inputs.
    let synthetic = synthetic::build(mapping, &symbols)?;
    report.synthetic(&synthetic, &symbols)?;
    // Layout: assign section and symbol addresses, including the entry point.
    let mut image = layout::assign_addresses(synthetic, symbols, script.entry_name())?;
    report.layout(&image)?;
    // Relocation: compute and write references using the final addresses.
    let relocations = relocate::apply(&mut image, report.relocation_symbols())?;
    report.relocations(&image, &relocations)?;
    report.write_map(&image)?;
    // Output: emit the executable and its section and symbol tables.
    output::write(image, args.output)?;
    Ok(())
}
