use crate::disasm::instruction::{InstructionNormalized, JenisOperandDisasm};
use crate::ir::types::{StatementIr, TipeOperand, OperasiIr};
use std::sync::Arc;

pub mod arithmetic;
pub mod flow;
pub mod simd;
pub mod crypto;
pub mod system;
pub mod semantic; 
pub mod bitwise;

#[derive(Clone)]
pub struct IrLifter {
    pub pointer_size: i64,
    pub semantic_engine: Arc<semantic::SemanticEngine>,
}

impl IrLifter {
    pub fn new() -> Self {
        Self { 
            pointer_size: 8,
            semantic_engine: Arc::new(semantic::SemanticEngine::new()),
        }
    }
    pub fn konversi_instruksi_ke_microcode(&self, instr: &InstructionNormalized) -> Vec<StatementIr> {
        let mut micro_ops = Vec::new();
        if self.semantic_engine.proses_lifting_otomatis(self, instr, &mut micro_ops) {
            return micro_ops;
        }
        let mnemonic = instr.mnemonic.to_lowercase();
        let mnem_str = mnemonic.as_str();
        if simd::cek_is_simd_instruction(mnem_str) {
            simd::proses_simd_to_intrinsic(self, instr, mnem_str, &mut micro_ops);
            return micro_ops;
        }
        match mnem_str {
            "ret" | "retn" => flow::proses_ret(self, instr, &mut micro_ops),
            "call" | "bl" => flow::proses_call(self, instr, &mut micro_ops),
            "jmp" | "b" => flow::proses_unconditional_jump(self, instr, &mut micro_ops),
            "je" | "jz" | "jne" | "jnz" | "jg" | "ja" | "jge" | "jae" | 
            "jl" | "jb" | "jle" | "jbe" | "js" | "jns" | "cbz" | "cbnz" | "b.eq" | "b.ne" => {
                flow::proses_conditional_branch(self, instr, mnem_str, &mut micro_ops);
            },
            "push" => arithmetic::proses_push(self, instr, &mut micro_ops),
            "pop" => arithmetic::proses_pop(self, instr, &mut micro_ops),
            "mov" | "movabs" | "movzx" | "movsx" => arithmetic::proses_data_movement(self, instr, &mut micro_ops),
            "lea" | "adr" | "adrp" => arithmetic::proses_lea(self, instr, &mut micro_ops),
            "add" | "inc" => arithmetic::proses_arithmetic_explicit(self, instr, OperasiIr::Add, &mut micro_ops),
            "sub" | "dec" => arithmetic::proses_arithmetic_explicit(self, instr, OperasiIr::Sub, &mut micro_ops),
            "imul" | "mul" => arithmetic::proses_arithmetic_explicit(self, instr, OperasiIr::Imul, &mut micro_ops),
            "idiv" | "div" => arithmetic::proses_arithmetic_explicit(self, instr, OperasiIr::Div, &mut micro_ops),
            "and" | "tst" => if mnem_str == "tst" { 
                arithmetic::proses_comparison_explicit(self, instr, OperasiIr::And, &mut micro_ops) 
            } else { 
                arithmetic::proses_arithmetic_explicit(self, instr, OperasiIr::And, &mut micro_ops) 
            },
            "or" | "orr" => arithmetic::proses_arithmetic_explicit(self, instr, OperasiIr::Or, &mut micro_ops),
            "xor" | "eor" => arithmetic::proses_arithmetic_explicit(self, instr, OperasiIr::Xor, &mut micro_ops),
            "shl" | "sal" | "shr" | "sar" | "rol" | "ror" => {
                bitwise::proses_shift_rotate(self, instr, mnem_str, &mut micro_ops);
            },
            "cmp" | "cmn" => arithmetic::proses_comparison_explicit(self, instr, if mnem_str == "cmn" { OperasiIr::Add } else { OperasiIr::Sub }, &mut micro_ops),
            "syscall" | "cpuid" | "rdtsc" | "andn" | "popcnt" => system::proses_system_instruction(self, instr, mnem_str, &mut micro_ops),
            "nop" => {},
            _ => arithmetic::proses_generic_unknown(self, instr, &mut micro_ops),
        }
        micro_ops
    }
    pub fn ambil_operand(&self, instr: &InstructionNormalized, index: usize) -> TipeOperand {
        if let Some(o) = instr.operands_detail.get(index) {
            self.konversi_operand(o)
        } else {
            TipeOperand::None
        }
    }
    pub fn konversi_operand(&self, op_detail: &JenisOperandDisasm) -> TipeOperand {
        match op_detail {
            JenisOperandDisasm::Register(reg) => TipeOperand::Register(reg.to_lowercase()),
            JenisOperandDisasm::Immediate(val) => TipeOperand::Immediate(*val),
            JenisOperandDisasm::Memory { base, index, scale, disp } => {
                if base.is_none() && index.is_none() { return TipeOperand::Memory(*disp as u64); }
                let mut expr = if let Some(b) = base { TipeOperand::Register(b.to_lowercase()) } else { TipeOperand::Immediate(0) };
                if let Some(idx) = index {
                    let idx_node = TipeOperand::Register(idx.to_lowercase());
                    let scaled = if *scale != 1 { TipeOperand::Expression { operasi: OperasiIr::Imul, operand_kiri: Box::new(idx_node), operand_kanan: Box::new(TipeOperand::Immediate(*scale as i64)) } } else { idx_node };
                    expr = TipeOperand::Expression { operasi: OperasiIr::Add, operand_kiri: Box::new(expr), operand_kanan: Box::new(scaled) };
                }
                if *disp != 0 {
                    expr = TipeOperand::Expression { operasi: OperasiIr::Add, operand_kiri: Box::new(expr), operand_kanan: Box::new(TipeOperand::Immediate(*disp)) };
                }
                if let Some(b) = base {
                    if index.is_none() && *scale == 1 { return TipeOperand::MemoryRef { base: b.to_lowercase(), offset: *disp }; }
                }
                expr
            },
            JenisOperandDisasm::Unknown => TipeOperand::None,
        }
    }
}