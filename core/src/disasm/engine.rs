use super::instruction::{InstructionNormalized, JenisOperandDisasm};
use capstone::prelude::*;
use capstone::arch::x86::{ArchMode, ArchSyntax, X86OperandType};

pub struct DisasmEngine {
    pub arch: String,
    _mode: String,
}

impl DisasmEngine {
    pub fn buat_engine_baru(arch: &str) -> Self {
        Self {
            arch: arch.to_string(),
            _mode: "64-bit".to_string(),
        }
    }
    fn init_capstone(&self) -> Capstone {
         if self.arch == "aarch64" || self.arch == "arm64" {
            Capstone::new()
                .arm64()
                .mode(capstone::arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
                .expect("Gagal inisialisasi Capstone ARM64")
        } else {
            let cs_mode = if self.arch == "x86_64" {
                ArchMode::Mode64
            } else {
                ArchMode::Mode32
            };
            Capstone::new()
                .x86()
                .mode(cs_mode)
                .syntax(ArchSyntax::Intel)
                .detail(true)
                .build()
                .expect("Gagal inisialisasi Capstone x86")
        }
    }
    pub fn ambil_satu_instruksi(&self, buffer: &[u8], address: u64) -> Option<InstructionNormalized> {
        let cs = self.init_capstone();
        match cs.disasm_count(buffer, address, 1) {
            Ok(insns) => {
                if let Some(i) = insns.first() {
                    Some(self.normalisasi_instruksi(&cs, i))
                } else {
                    None
                }
            },
            Err(_) => None
        }
    }
    pub fn lakukan_disassembly(&self, buffer: &[u8], start_addr: u64) -> Vec<InstructionNormalized> {
        let cs = self.init_capstone();
        let mut instructions = Vec::new();
        if let Ok(insns) = cs.disasm_all(buffer, start_addr) {
            for i in insns.iter() {
                instructions.push(self.normalisasi_instruksi(&cs, i));
            }
        }
        instructions
    }
    fn normalisasi_instruksi(&self, cs: &Capstone, i: &capstone::Insn) -> InstructionNormalized {
        let mnemonic = i.mnemonic().unwrap_or("???");
        let op_str = i.op_str().unwrap_or("");
        let mut norm = InstructionNormalized::new(i.address(), mnemonic, op_str);
        norm.bytes = i.bytes().to_vec();
        if let Ok(detail) = cs.insn_detail(i) {
            let arch_detail = detail.arch_detail();
            if let capstone::arch::ArchDetail::X86Detail(x86_det) = arch_detail {
                    for op in x86_det.operands() {
                    let op_data = match op.op_type {
                        X86OperandType::Reg(reg_id) => {
                            let reg_name = cs.reg_name(reg_id).unwrap_or_else(|| format!("r{}", reg_id.0));
                            JenisOperandDisasm::Register(reg_name)
                        },
                        X86OperandType::Imm(val) => {
                            JenisOperandDisasm::Immediate(val)
                        },
                        X86OperandType::Mem(mem) => {
                            let base = if mem.base().0 == 0 { None } else {
                                Some(cs.reg_name(mem.base()).unwrap_or_default())
                            };
                            let index = if mem.index().0 == 0 { None } else {
                                Some(cs.reg_name(mem.index()).unwrap_or_default())
                            };
                            JenisOperandDisasm::Memory {
                                base,
                                index,
                                scale: mem.scale(),
                                disp: mem.disp(),
                            }
                        },
                        _ => JenisOperandDisasm::Unknown,
                    };
                    norm.operands_detail.push(op_data);
                }
            } else if let capstone::arch::ArchDetail::Arm64Detail(arm_det) = arch_detail {
                 for op in arm_det.operands() {
                     match op.op_type {
                         capstone::arch::arm64::Arm64OperandType::Reg(reg) => {
                             let name = cs.reg_name(reg).unwrap_or("reg".to_string());
                             norm.operands_detail.push(JenisOperandDisasm::Register(name));
                         },
                         capstone::arch::arm64::Arm64OperandType::Imm(val) => {
                             norm.operands_detail.push(JenisOperandDisasm::Immediate(val));
                         },
                         _ => {}
                     }
                 }
            }
        }
        norm
    }
}