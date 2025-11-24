use crate::disasm::instruction::InstructionNormalized;
use super::types::{StatementIr, TipeOperand, OperasiIr};

pub struct IrLifter {
    _optimization_level: u8,
}

impl IrLifter {
    pub fn new() -> Self {
        Self { _optimization_level: 1 }
    }
    pub fn lift_instruksi_asm(&self, instr: &InstructionNormalized) -> StatementIr {
        let op_code = self.terjemahkan_mnemonic(&instr.mnemonic);
        let (op1, op2) = self.parse_operand_string(&instr.op_str);
        StatementIr::new(instr.address, op_code, op1, op2)
    }
    fn terjemahkan_mnemonic(&self, mnemonic: &str) -> OperasiIr {
        match mnemonic {
            "mov" => OperasiIr::Mov,
            "add" => OperasiIr::Add,
            "sub" => OperasiIr::Sub,
            "imul" => OperasiIr::Imul,
            "jmp" => OperasiIr::Jmp,
            "je" => OperasiIr::Je,
            "jne" => OperasiIr::Jne,
            "call" => OperasiIr::Call,
            "ret" => OperasiIr::Ret,
            "nop" => OperasiIr::Nop,
            _ => OperasiIr::Unknown,
        }
    }
    fn parse_operand_string(&self, op_str: &str) -> (TipeOperand, TipeOperand) {
        if op_str.is_empty() {
            return (TipeOperand::None, TipeOperand::None);
        }
        let parts: Vec<&str> = op_str.split(',').map(|s| s.trim()).collect();
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
        TipeOperand::Register(raw.to_string())
    }
}