use crate::{
    link::SectionPlacement,
    parse::{ObjectRelocation, ObjectSymbol},
};

use anyhow::{Ok, Result};

pub fn relocate(
    section_placements: Vec<SectionPlacement>,
    symbols: Vec<ObjectSymbol>,
    relocations: Vec<ObjectRelocation>,
) -> Result<()> {
    pr_debug!("Relocating sections...");

    Ok(())
}
