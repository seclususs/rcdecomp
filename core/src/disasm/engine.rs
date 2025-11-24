use super::instruction::InstructionNormalized;
use capstone::prelude::*;
use capstone::arch::x86::{ArchMode, ArchSyntax};

pub struct DisasmEngine {
    arch: String,
    _mode: String,
}

impl DisasmEngine {
    pub fn buat_engine_baru(arch: &str) -> Self {
        Self {
            arch: arch.to_string(),
            _mode: "64-bit".to_string(),
        }
    }
    pub fn disassemble_buffer(&self, buffer: &[u8], start_addr: u64) -> Vec<InstructionNormalized> {
        let cs_mode = if self.arch == "x86_64" {
            ArchMode::Mode64
        } else {
            ArchMode::Mode32
        };
        let cs = Capstone::new()
            .x86()
            .mode(cs_mode)
            .syntax(ArchSyntax::Intel)
            .build()
            .expect("Gagal inisialisasi Capstone");
        let mut instructions = Vec::new();
        if let Ok(insns) = cs.disasm_all(buffer, start_addr) {
            for i in insns.iter() {
                let mnemonic = i.mnemonic().unwrap_or("???");
                let op_str = i.op_str().unwrap_or("");
                let mut norm = InstructionNormalized::new(i.address(), mnemonic, op_str);
                norm.bytes = i.bytes().to_vec();
                instructions.push(norm);
            }
        }
        instructions
    }
}