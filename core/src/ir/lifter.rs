use crate::disasm::instruction::InstructionNormalized;
use super::types::{StatementIr, TipeOperand, OperasiIr};

pub struct IrLifter {
    _optimization_level: u8,
}

impl IrLifter {
    pub fn new() -> Self {
        Self { _optimization_level: 1 }
    }
    pub fn konversi_instruksi_ke_ir(&self, instr: &InstructionNormalized) -> StatementIr {
        let op_code = self.terjemahkan_mnemonic(&instr.mnemonic);
        let (op1, op2) = self.urai_string_operand(&instr.op_str);
        StatementIr::new(instr.address, op_code, op1, op2)
    }
    fn terjemahkan_mnemonic(&self, mnemonic: &str) -> OperasiIr {
        match mnemonic {
            "mov" => OperasiIr::Mov,
            "add" => OperasiIr::Add,
            "sub" => OperasiIr::Sub,
            "imul" => OperasiIr::Imul,
            "jmp" => OperasiIr::Jmp,
            "je" | "jz" => OperasiIr::Je,
            "jne" | "jnz" => OperasiIr::Jne,
            "jg" | "ja" => OperasiIr::Jg,
            "jge" | "jae" => OperasiIr::Jge,
            "jl" | "jb" => OperasiIr::Jl,
            "jle" | "jbe" => OperasiIr::Jle,
            "cmp" => OperasiIr::Cmp,
            "test" => OperasiIr::Test,
            "call" => OperasiIr::Call,
            "ret" => OperasiIr::Ret,
            "nop" => OperasiIr::Nop,
            _ => OperasiIr::Unknown,
        }
    }
    fn urai_string_operand(&self, op_str: &str) -> (TipeOperand, TipeOperand) {
        if op_str.is_empty() {
            return (TipeOperand::None, TipeOperand::None);
        }
        let parts: Vec<&str> = op_str.splitn(2, ',').map(|s| s.trim()).collect();
        let op1 = if !parts.is_empty() {
            self.identifikasi_tipe_operand(parts[0])
        } else {
            TipeOperand::None
        };
        let op2 = if parts.len() > 1 {
            self.identifikasi_tipe_operand(parts[1])
        } else {
            TipeOperand::None
        };
        (op1, op2)
    }
    fn identifikasi_tipe_operand(&self, raw: &str) -> TipeOperand {
        if raw.starts_with("0x") {
            if let Ok(val) = u64::from_str_radix(&raw[2..], 16) {
                return TipeOperand::Immediate(val as i64);
            }
        }
        if let Ok(val) = raw.parse::<i64>() {
            return TipeOperand::Immediate(val);
        }
        if let Some(start) = raw.find('[') {
            if let Some(end) = raw.find(']') {
                let inner = &raw[start+1..end];
                let is_minus = inner.contains('-');
                let is_plus = inner.contains('+');
                if is_minus {
                    let parts: Vec<&str> = inner.split('-').map(|s| s.trim()).collect();
                    if parts.len() == 2 {
                        let reg = parts[0].to_string();
                        let offset_str = parts[1];
                        let offset = if offset_str.starts_with("0x") {
                            i64::from_str_radix(&offset_str[2..], 16).unwrap_or(0)
                        } else {
                            offset_str.parse::<i64>().unwrap_or(0)
                        };
                        return TipeOperand::MemoryRef { base: reg, offset: -offset };
                    }
                } else if is_plus {
                    let parts: Vec<&str> = inner.split('+').map(|s| s.trim()).collect();
                    if parts.len() == 2 {
                        let reg = parts[0].to_string();
                        let offset_str = parts[1];
                        let offset = if offset_str.starts_with("0x") {
                            i64::from_str_radix(&offset_str[2..], 16).unwrap_or(0)
                        } else {
                            offset_str.parse::<i64>().unwrap_or(0)
                        };
                        return TipeOperand::MemoryRef { base: reg, offset };
                    }
                } else {
                    return TipeOperand::MemoryRef { base: inner.trim().to_string(), offset: 0 };
                }
            }
        }
        let clean_raw = raw.replace("DWORD PTR", "")
                           .replace("QWORD PTR", "")
                           .replace("BYTE PTR", "")
                           .trim()
                           .to_string();
        if !clean_raw.is_empty() {
             TipeOperand::Register(clean_raw)
        } else {
             TipeOperand::None
        }
    }
}