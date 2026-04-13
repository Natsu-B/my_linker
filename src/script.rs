use std::sync::RwLock;

pub struct ScriptData {
    pub vart_addr: u64,
}

pub static LINKER_DATA: RwLock<ScriptData> = RwLock::new(ScriptData {
    vart_addr: 0x400000,
});
