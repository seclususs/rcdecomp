use super::instruction::{InstructionNormalized, JenisOperandDisasm};
use capstone::prelude::*;
use capstone::arch::x86::{ArchMode, ArchSyntax, X86OperandType};
use capstone::arch::arm64::Arm64OperandType;

pub struct DisasmEngine {
    cs: Capstone,
    pub arch: String,
}

unsafe impl Send for DisasmEngine {}
unsafe impl Sync for DisasmEngine {}

impl DisasmEngine {
    pub fn buat_engine_baru(arch_target: &str) -> Self {
        let cs_instance = Self::inisialisasi_capstone_instance(arch_target);
        Self {
            cs: cs_instance,
            arch: arch_target.to_string(),
        }
    }
    fn inisialisasi_capstone_instance(arch_target: &str) -> Capstone {
        if arch_target == "aarch64" || arch_target == "arm64" {
            Capstone::new()
                .arm64()
                .mode(capstone::arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
                .expect("Gagal inisialisasi Capstone ARM64 - Fatal Error")
        } else {
            let cs_mode = if arch_target == "x86_64" {
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
                .expect("Gagal inisialisasi Capstone x86 - Fatal Error")
        }
    }
    pub fn ambil_satu_instruksi(&self, buffer_data: &[u8], address_loc: u64) -> Option<InstructionNormalized> {
        match self.cs.disasm_count(buffer_data, address_loc, 1) {
            Ok(insns) => {
                if let Some(single_instr) = insns.first() {
                    Some(self.normalisasi_instruksi(single_instr))
                } else {
                    None
                }
            },
            Err(_) => {
                None
            }
        }
    }
    pub fn lakukan_disassembly(&self, buffer_data: &[u8], start_addr: u64) -> Vec<InstructionNormalized> {
        let mut list_instruksi = Vec::new();
        if let Ok(insns) = self.cs.disasm_all(buffer_data, start_addr) {
            for raw_instr in insns.iter() {
                list_instruksi.push(self.normalisasi_instruksi(raw_instr));
            }
        }
        list_instruksi
    }
    fn normalisasi_instruksi(&self, i: &capstone::Insn) -> InstructionNormalized {
        let mnemonic_str = i.mnemonic().unwrap_or("INVALID");
        let op_str_val = i.op_str().unwrap_or("");
        let mut norm_result = InstructionNormalized::new(i.address(), mnemonic_str, op_str_val);
        norm_result.bytes = i.bytes().to_vec();
        if let Ok(detail_info) = self.cs.insn_detail(i) {
            let arch_detail = detail_info.arch_detail();
            if let capstone::arch::ArchDetail::X86Detail(x86_det) = arch_detail {
                for op in x86_det.operands() {
                    let op_data = match op.op_type {
                        X86OperandType::Reg(reg_id) => {
                            let reg_name = self.cs.reg_name(reg_id).unwrap_or_else(|| "INVALID_REG".to_string());
                            JenisOperandDisasm::Register(reg_name)
                        },
                        X86OperandType::Imm(val) => {
                            JenisOperandDisasm::Immediate(val)
                        },
                        X86OperandType::Mem(mem) => {
                            let base_reg = if mem.base().0 == 0 { 
                                None 
                            } else {
                                Some(self.cs.reg_name(mem.base()).unwrap_or("INVALID_BASE".to_string()))
                            };
                            let index_reg = if mem.index().0 == 0 { 
                                None 
                            } else {
                                Some(self.cs.reg_name(mem.index()).unwrap_or("INVALID_IDX".to_string()))
                            };
                            JenisOperandDisasm::Memory {
                                base: base_reg,
                                index: index_reg,
                                scale: mem.scale(),
                                disp: mem.disp(),
                            }
                        },
                        _ => JenisOperandDisasm::Unknown,
                    };
                    norm_result.operands_detail.push(op_data);
                }
            } else if let capstone::arch::ArchDetail::Arm64Detail(arm_det) = arch_detail {
                 for op in arm_det.operands() {
                     match op.op_type {
                         Arm64OperandType::Reg(reg_id) => {
                             let name_reg = self.cs.reg_name(reg_id).unwrap_or("INVALID_REG".to_string());
                             norm_result.operands_detail.push(JenisOperandDisasm::Register(name_reg));
                         },
                         Arm64OperandType::Imm(val) => {
                             norm_result.operands_detail.push(JenisOperandDisasm::Immediate(val));
                         },
                         Arm64OperandType::Mem(mem_op) => {
                             let base_reg_str = if mem_op.base().0 == 0 {
                                 None
                             } else {
                                 Some(self.cs.reg_name(mem_op.base()).unwrap_or("INVALID_BASE".to_string()))
                             };
                             let index_reg_str = if mem_op.index().0 == 0 {
                                 None
                             } else {
                                 Some(self.cs.reg_name(mem_op.index()).unwrap_or("INVALID_IDX".to_string()))
                             };
                             let disp_val = mem_op.disp() as i64;
                             let scale_val = if index_reg_str.is_some() { 1 } else { 0 };
                             norm_result.operands_detail.push(JenisOperandDisasm::Memory {
                                 base: base_reg_str,
                                 index: index_reg_str,
                                 scale: scale_val,
                                 disp: disp_val,
                             });
                         },
                         _ => {
                             norm_result.operands_detail.push(JenisOperandDisasm::Unknown);
                         }
                     }
                 }
            }
        }
        norm_result
    }
}