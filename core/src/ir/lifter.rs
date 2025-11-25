use crate::disasm::instruction::{InstructionNormalized, JenisOperandDisasm};
use crate::ir::types::{StatementIr, TipeOperand, OperasiIr};

pub struct IrLifter {
    _optimization_level: u8,
    pointer_size: i64,
}

impl IrLifter {
    pub fn new() -> Self {
        Self { 
            _optimization_level: 1,
            pointer_size: 8,
        }
    }
    pub fn konversi_instruksi_ke_microcode(&self, instr: &InstructionNormalized) -> Vec<StatementIr> {
        let mut micro_ops = Vec::new();
        match instr.mnemonic.as_str() {
            "push" => self.expand_instruksi_push(instr, &mut micro_ops),
            "pop" => self.expand_instruksi_pop(instr, &mut micro_ops),
            "ret" | "retn" => self.expand_instruksi_ret(instr, &mut micro_ops),
            "call" => self.expand_instruksi_call(instr, &mut micro_ops),
            "mov" | "movabs" | "lea" => self.translasikan_generic_arithmetic(instr, OperasiIr::Mov, &mut micro_ops),
            "add" | "inc" => self.translasikan_generic_arithmetic(instr, OperasiIr::Add, &mut micro_ops),
            "sub" | "dec" => self.translasikan_generic_arithmetic(instr, OperasiIr::Sub, &mut micro_ops),
            "imul" | "mul" => self.translasikan_generic_arithmetic(instr, OperasiIr::Imul, &mut micro_ops),
            "idiv" | "div" => self.translasikan_generic_arithmetic(instr, OperasiIr::Div, &mut micro_ops),
            "and" => self.translasikan_generic_arithmetic(instr, OperasiIr::And, &mut micro_ops),
            "or"  => self.translasikan_generic_arithmetic(instr, OperasiIr::Or, &mut micro_ops),
            "xor" => self.translasikan_generic_arithmetic(instr, OperasiIr::Xor, &mut micro_ops),
            "shl" | "sal" => self.translasikan_generic_arithmetic(instr, OperasiIr::Shl, &mut micro_ops),
            "shr" | "sar" => self.translasikan_generic_arithmetic(instr, OperasiIr::Shr, &mut micro_ops),
            "cmp" => self.translasikan_generic_arithmetic(instr, OperasiIr::Cmp, &mut micro_ops),
            "test" => self.translasikan_generic_arithmetic(instr, OperasiIr::Test, &mut micro_ops),
            "jmp" => self.translasikan_control_flow(instr, OperasiIr::Jmp, &mut micro_ops),
            "je" | "jz" => self.translasikan_control_flow(instr, OperasiIr::Je, &mut micro_ops),
            "jne" | "jnz" => self.translasikan_control_flow(instr, OperasiIr::Jne, &mut micro_ops),
            "jg" | "ja" => self.translasikan_control_flow(instr, OperasiIr::Jg, &mut micro_ops),
            "jge" | "jae" => self.translasikan_control_flow(instr, OperasiIr::Jge, &mut micro_ops),
            "jl" | "jb" => self.translasikan_control_flow(instr, OperasiIr::Jl, &mut micro_ops),
            "jle" | "jbe" => self.translasikan_control_flow(instr, OperasiIr::Jle, &mut micro_ops),
            _ => {
                self.translasikan_generic_arithmetic(instr, OperasiIr::Unknown, &mut micro_ops);
            }
        }
        micro_ops
    }
    fn expand_instruksi_push(&self, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
        if let Some(src_op) = instr.operands_detail.first() {
            let src = self.konversi_operand(src_op);
            ops.push(StatementIr::new(
                instr.address,
                OperasiIr::Sub,
                TipeOperand::Register("rsp".to_string()),
                TipeOperand::Immediate(self.pointer_size),
            ));
            ops.push(StatementIr::new(
                instr.address,
                OperasiIr::Mov,
                TipeOperand::MemoryRef { base: "rsp".to_string(), offset: 0 },
                src
            ));
        }
    }
    fn expand_instruksi_pop(&self, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
        if let Some(dst_op) = instr.operands_detail.first() {
            let dst = self.konversi_operand(dst_op);
            ops.push(StatementIr::new(
                instr.address,
                OperasiIr::Mov,
                dst,
                TipeOperand::MemoryRef { base: "rsp".to_string(), offset: 0 },
            ));
            ops.push(StatementIr::new(
                instr.address,
                OperasiIr::Add,
                TipeOperand::Register("rsp".to_string()),
                TipeOperand::Immediate(self.pointer_size),
            ));
        }
    }
    fn expand_instruksi_ret(&self, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
        ops.push(StatementIr::new(
            instr.address,
            OperasiIr::Add,
            TipeOperand::Register("rsp".to_string()),
            TipeOperand::Immediate(self.pointer_size),
        ));
        ops.push(StatementIr::new(
            instr.address,
            OperasiIr::Ret,
            TipeOperand::None,
            TipeOperand::None
        ));
    }
    fn expand_instruksi_call(&self, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
        ops.push(StatementIr::new(
            instr.address,
            OperasiIr::Sub,
            TipeOperand::Register("rsp".to_string()),
            TipeOperand::Immediate(self.pointer_size),
        ));
        if let Some(target_op) = instr.operands_detail.first() {
            ops.push(StatementIr::new(
                instr.address,
                OperasiIr::Call,
                self.konversi_operand(target_op),
                TipeOperand::None
            ));
        }
    }
    fn translasikan_generic_arithmetic(&self, instr: &InstructionNormalized, op_code: OperasiIr, ops: &mut Vec<StatementIr>) {
        let op1 = if let Some(o) = instr.operands_detail.get(0) {
            self.konversi_operand(o)
        } else { TipeOperand::None };
        let op2 = if let Some(o) = instr.operands_detail.get(1) {
            self.konversi_operand(o)
        } else { TipeOperand::None };
        match op_code {
            OperasiIr::Add | OperasiIr::Sub | OperasiIr::Imul | OperasiIr::Div | 
            OperasiIr::And | OperasiIr::Or | OperasiIr::Xor | OperasiIr::Shl | OperasiIr::Shr => {
                let expr = TipeOperand::Expression {
                    operasi: op_code.clone(),
                    operand_kiri: Box::new(op1.clone()),
                    operand_kanan: Box::new(op2.clone())
                };
                ops.push(StatementIr::new(
                    instr.address,
                    op_code,
                    op1,
                    expr
                ));
            },
            _ => {
                ops.push(StatementIr::new(instr.address, op_code, op1, op2));
            }
        }
    }
    fn translasikan_control_flow(&self, instr: &InstructionNormalized, op_code: OperasiIr, ops: &mut Vec<StatementIr>) {
        let target = if let Some(o) = instr.operands_detail.get(0) {
            self.konversi_operand(o)
        } else { TipeOperand::None };
        ops.push(StatementIr::new(
            instr.address,
            op_code,
            target,
            TipeOperand::None
        ));
    }
    fn konversi_operand(&self, op_detail: &JenisOperandDisasm) -> TipeOperand {
        match op_detail {
            JenisOperandDisasm::Register(reg) => TipeOperand::Register(reg.to_lowercase()),
            JenisOperandDisasm::Immediate(val) => TipeOperand::Immediate(*val),
            JenisOperandDisasm::Memory { base, index, scale, disp } => {
                if index.is_none() && *scale == 1 {
                    if let Some(b) = base {
                        return TipeOperand::MemoryRef { 
                            base: b.to_lowercase(), 
                            offset: *disp 
                        };
                    } else {
                        return TipeOperand::Memory(*disp as u64);
                    }
                }
                let mut expr = if let Some(b) = base {
                    TipeOperand::Register(b.to_lowercase())
                } else {
                    TipeOperand::Immediate(0)
                };
                if let Some(idx) = index {
                    let index_node = TipeOperand::Register(idx.to_lowercase());
                    let scaled_index = if *scale != 1 {
                        TipeOperand::Expression {
                            operasi: OperasiIr::Imul,
                            operand_kiri: Box::new(index_node),
                            operand_kanan: Box::new(TipeOperand::Immediate(*scale as i64))
                        }
                    } else {
                        index_node
                    };
                    expr = TipeOperand::Expression {
                        operasi: OperasiIr::Add,
                        operand_kiri: Box::new(expr),
                        operand_kanan: Box::new(scaled_index)
                    };
                }
                if *disp != 0 {
                    expr = TipeOperand::Expression {
                        operasi: OperasiIr::Add,
                        operand_kiri: Box::new(expr),
                        operand_kanan: Box::new(TipeOperand::Immediate(*disp))
                    };
                }
                expr
            },
            JenisOperandDisasm::Unknown => TipeOperand::None,
        }
    }
}