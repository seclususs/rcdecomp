pub mod engine;
pub mod instruction;

use self::engine::DisasmEngine;

pub struct DisassemblerContext {
    pub engine: DisasmEngine,
    pub arch_type: String,
}

impl DisassemblerContext {
    pub fn init_context(arch: &str) -> Self {
        Self {
            engine: DisasmEngine::buat_engine_baru(arch),
            arch_type: arch.to_string(),
        }
    }
    pub fn dapatkan_engine(&self) -> &DisasmEngine {
        &self.engine
    }
}