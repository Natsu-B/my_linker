use std::sync::{OnceLock, RwLock};

pub struct ScriptData {
    pub vart_addr: u64,
    pub _start_name: OnceLock<String>,
}

pub static LINKER_DATA: RwLock<ScriptData> = RwLock::new(ScriptData {
    vart_addr: 0x400000,
    _start_name: OnceLock::new(),
});

pub fn parse_script() -> anyhow::Result<()> {
    pr_debug!("Parsing script...");

    let _ = LINKER_DATA
        .write()
        .unwrap()
        ._start_name
        .set("_start".to_string());

    Ok(())
}
