use crate::disasm::instruction::{InstructionNormalized, JenisOperandDisasm};
use crate::ir::types::{StatementIr, TipeOperand, OperasiIr, TipeDataIr};
use log::debug;

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
        let mnemonic = instr.mnemonic.as_str();
        if self.cek_is_simd_instruction(mnemonic) {
            self.lift_simd_instruction(instr, mnemonic, &mut micro_ops);
            return micro_ops;
        }
        match mnemonic {
            "push" => self.lift_push(instr, &mut micro_ops),
            "pop" => self.lift_pop(instr, &mut micro_ops),
            "ret" | "retn" => self.lift_ret(instr, &mut micro_ops),
            "call" | "bl" => self.lift_call(instr, &mut micro_ops),
            "jmp" | "b" => self.lift_unconditional_jump(instr, &mut micro_ops),
            "je" | "jz" | "jne" | "jnz" | 
            "jg" | "ja" | "jge" | "jae" | 
            "jl" | "jb" | "jle" | "jbe" | 
            "js" | "jns" | "jo" | "jno" => {
                self.lift_conditional_branch(instr, mnemonic, &mut micro_ops);
            },
            "mov" | "movabs" | "movzx" | "movsx" => self.lift_data_movement(instr, &mut micro_ops),
            "lea" => self.lift_lea(instr, &mut micro_ops),
            "cmovg" | "cmovl" | "cmove" | "cmovne" => self.lift_conditional_move(instr, mnemonic, &mut micro_ops),
            "add" | "inc" => self.lift_arithmetic_with_flags(instr, OperasiIr::Add, &mut micro_ops),
            "sub" | "dec" => self.lift_arithmetic_with_flags(instr, OperasiIr::Sub, &mut micro_ops),
            "imul" | "mul" => self.lift_arithmetic_with_flags(instr, OperasiIr::Imul, &mut micro_ops),
            "idiv" | "div" => self.lift_arithmetic_with_flags(instr, OperasiIr::Div, &mut micro_ops),
            "and" => self.lift_arithmetic_with_flags(instr, OperasiIr::And, &mut micro_ops),
            "or"  => self.lift_arithmetic_with_flags(instr, OperasiIr::Or, &mut micro_ops),
            "xor" => self.lift_arithmetic_with_flags(instr, OperasiIr::Xor, &mut micro_ops),
            "shl" | "sal" | "lsl" => self.lift_arithmetic_with_flags(instr, OperasiIr::Shl, &mut micro_ops),
            "shr" | "sar" | "lsr" => self.lift_arithmetic_with_flags(instr, OperasiIr::Shr, &mut micro_ops),
            "cmp" => self.lift_comparison(instr, OperasiIr::Sub, &mut micro_ops),
            "test" => self.lift_comparison(instr, OperasiIr::And, &mut micro_ops),
            "nop" => {},
            "int3" => self.lift_trap(instr, &mut micro_ops),
            _ => {
                self.lift_generic_unknown(instr, &mut micro_ops);
            }
        }
        micro_ops
    }
    fn cek_is_simd_instruction(&self, mnemonic: &str) -> bool {
        mnemonic.starts_with('v') ||
        mnemonic.ends_with("ps") || mnemonic.ends_with("pd") ||
        mnemonic.ends_with("ss") || mnemonic.ends_with("sd") ||
        mnemonic.contains("xmm") || mnemonic.contains("ymm") ||
        mnemonic == "xorps" || mnemonic == "xorpd" ||
        mnemonic == "movaps" || mnemonic == "movups" ||
        mnemonic.starts_with("padd") || mnemonic.starts_with("psub")
    }
    fn ambil_operand(&self, instr: &InstructionNormalized, index: usize) -> TipeOperand {
        if let Some(o) = instr.operands_detail.get(index) {
            self.konversi_operand(o)
        } else {
            TipeOperand::None
        }
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
    fn lift_simd_instruction(&self, instr: &InstructionNormalized, mnemonic: &str, ops: &mut Vec<StatementIr>) {
        let op_code = if mnemonic.contains("add") { OperasiIr::VecAdd }
        else if mnemonic.contains("sub") { OperasiIr::VecSub }
        else if mnemonic.contains("mul") { OperasiIr::VecMul }
        else if mnemonic.contains("div") { OperasiIr::VecDiv }
        else if mnemonic.contains("xor") { OperasiIr::VecXor }
        else if mnemonic.contains("and") { OperasiIr::VecAnd }
        else if mnemonic.contains("or") { OperasiIr::VecOr }
        else if mnemonic.contains("mov") { OperasiIr::VecMov }
        else if mnemonic.contains("cvt") { OperasiIr::IntToFloat }
        else if mnemonic.contains("ucomi") || mnemonic.contains("comi") { OperasiIr::FCmp }
        else { OperasiIr::Unknown };
        let tipe_data = if mnemonic.contains("ymm") { TipeDataIr::V256 }
        else if mnemonic.contains("xmm") { TipeDataIr::V128 }
        else if mnemonic.ends_with("sd") { TipeDataIr::F64 }
        else if mnemonic.ends_with("ss") { TipeDataIr::F32 }
        else { TipeDataIr::V128 };
        let op1 = self.ambil_operand(instr, 0);
        let op2 = self.ambil_operand(instr, 1);
        if op_code == OperasiIr::FCmp {
            self.hitung_dan_emit_flags(instr.address, OperasiIr::Sub, &op1, &op1, &op2, ops);
        } else {
            ops.push(StatementIr::new(instr.address, op_code, op1, op2).with_type(tipe_data));
        }
    }
    fn lift_arithmetic_with_flags(
        &self, 
        instr: &InstructionNormalized, 
        op_code: OperasiIr, 
        ops: &mut Vec<StatementIr>
    ) {
        let dest = self.ambil_operand(instr, 0);
        let src = self.ambil_operand(instr, 1);
        let (actual_op1, actual_op2) = if src == TipeOperand::None {
            match instr.mnemonic.as_str() {
                "inc" => (dest.clone(), TipeOperand::Immediate(1)),
                "dec" => (dest.clone(), TipeOperand::Immediate(1)),
                "neg" => (TipeOperand::Immediate(0), dest.clone()),
                "not" => (dest.clone(), TipeOperand::Immediate(-1)),
                _ => (dest.clone(), dest.clone())
            }
        } else {
            (dest.clone(), src)
        };
        let result_expr = TipeOperand::Expression {
            operasi: op_code.clone(),
            operand_kiri: Box::new(actual_op1.clone()),
            operand_kanan: Box::new(actual_op2.clone())
        };
        ops.push(StatementIr::new(
            instr.address,
            op_code.clone(),
            dest.clone(),
            result_expr.clone()
        ).with_type(TipeDataIr::I64));
        self.hitung_dan_emit_flags(instr.address, op_code, &dest, &actual_op1, &actual_op2, ops);
    }
    fn lift_comparison(&self, instr: &InstructionNormalized, op_code: OperasiIr, ops: &mut Vec<StatementIr>) {
        let op1 = self.ambil_operand(instr, 0);
        let op2 = self.ambil_operand(instr, 1);
        self.hitung_dan_emit_flags(instr.address, op_code, &op1, &op1, &op2, ops);
    }
    fn hitung_dan_emit_flags(
        &self,
        addr: u64,
        op_code: OperasiIr,
        _dest: &TipeOperand,
        op1: &TipeOperand,
        op2: &TipeOperand,
        ops: &mut Vec<StatementIr>
    ) {
        let result_expr = Box::new(TipeOperand::Expression {
            operasi: op_code.clone(),
            operand_kiri: Box::new(op1.clone()),
            operand_kanan: Box::new(op2.clone())
        });
        let zf_expr = TipeOperand::Expression {
            operasi: OperasiIr::Cmp,
            operand_kiri: result_expr.clone(),
            operand_kanan: Box::new(TipeOperand::Immediate(0))
        };
        ops.push(StatementIr::new(addr, OperasiIr::Mov, TipeOperand::Register("zf".to_string()), zf_expr));
        let sf_expr = TipeOperand::Expression {
            operasi: OperasiIr::Jl,
            operand_kiri: result_expr.clone(),
            operand_kanan: Box::new(TipeOperand::Immediate(0))
        };
        ops.push(StatementIr::new(addr, OperasiIr::Mov, TipeOperand::Register("sf".to_string()), sf_expr));
        match op_code {
            OperasiIr::Sub => {
                let cf_expr = TipeOperand::Expression {
                    operasi: OperasiIr::Jl, 
                    operand_kiri: Box::new(op1.clone()),
                    operand_kanan: Box::new(op2.clone())
                };
                ops.push(StatementIr::new(addr, OperasiIr::Mov, TipeOperand::Register("cf".to_string()), cf_expr));
                let xor_op1_op2 = Box::new(TipeOperand::Expression {
                    operasi: OperasiIr::Xor,
                    operand_kiri: Box::new(op1.clone()),
                    operand_kanan: Box::new(op2.clone())
                });
                let xor_op1_res = Box::new(TipeOperand::Expression {
                    operasi: OperasiIr::Xor,
                    operand_kiri: Box::new(op1.clone()),
                    operand_kanan: result_expr.clone()
                });
                let and_res = TipeOperand::Expression {
                    operasi: OperasiIr::And,
                    operand_kiri: xor_op1_op2,
                    operand_kanan: xor_op1_res
                };
                let of_check = TipeOperand::Expression {
                    operasi: OperasiIr::Jl,
                    operand_kiri: Box::new(and_res),
                    operand_kanan: Box::new(TipeOperand::Immediate(0))
                };
                ops.push(StatementIr::new(addr, OperasiIr::Mov, TipeOperand::Register("of".to_string()), of_check));
            },
            OperasiIr::Add => {
                let cf_expr = TipeOperand::Expression {
                    operasi: OperasiIr::Jl,
                    operand_kiri: result_expr.clone(),
                    operand_kanan: Box::new(op1.clone())
                };
                ops.push(StatementIr::new(addr, OperasiIr::Mov, TipeOperand::Register("cf".to_string()), cf_expr));
                let xor_op1_op2 = Box::new(TipeOperand::Expression {
                    operasi: OperasiIr::Xor,
                    operand_kiri: Box::new(op1.clone()),
                    operand_kanan: Box::new(op2.clone())
                });
                let not_xor = Box::new(TipeOperand::Expression {
                    operasi: OperasiIr::Xor,
                    operand_kiri: xor_op1_op2,
                    operand_kanan: Box::new(TipeOperand::Immediate(-1))
                });
                let xor_op1_res = Box::new(TipeOperand::Expression {
                    operasi: OperasiIr::Xor,
                    operand_kiri: Box::new(op1.clone()),
                    operand_kanan: result_expr.clone()
                });
                let and_res = TipeOperand::Expression {
                    operasi: OperasiIr::And,
                    operand_kiri: not_xor,
                    operand_kanan: xor_op1_res
                };
                let of_check = TipeOperand::Expression {
                    operasi: OperasiIr::Jl,
                    operand_kiri: Box::new(and_res),
                    operand_kanan: Box::new(TipeOperand::Immediate(0))
                };
                ops.push(StatementIr::new(addr, OperasiIr::Mov, TipeOperand::Register("of".to_string()), of_check));
            },
            OperasiIr::And | OperasiIr::Or | OperasiIr::Xor | OperasiIr::Test => {
                ops.push(StatementIr::new(addr, OperasiIr::Mov, TipeOperand::Register("cf".to_string()), TipeOperand::Immediate(0)));
                ops.push(StatementIr::new(addr, OperasiIr::Mov, TipeOperand::Register("of".to_string()), TipeOperand::Immediate(0)));
            },
            _ => {}
        }
    }
    fn lift_conditional_branch(&self, instr: &InstructionNormalized, mnemonic: &str, ops: &mut Vec<StatementIr>) {
        let target = self.ambil_operand(instr, 0);
        let condition_expr = match mnemonic {
            "je" | "jz" => TipeOperand::Register("zf".to_string()),
            "jne" | "jnz" => TipeOperand::Expression { 
                operasi: OperasiIr::Cmp,
                operand_kiri: Box::new(TipeOperand::Register("zf".to_string())),
                operand_kanan: Box::new(TipeOperand::Immediate(0))
            },
            "js" => TipeOperand::Register("sf".to_string()),
            "jns" => TipeOperand::Expression {
                operasi: OperasiIr::Cmp,
                operand_kiri: Box::new(TipeOperand::Register("sf".to_string())),
                operand_kanan: Box::new(TipeOperand::Immediate(0))
            },
            "jo" => TipeOperand::Register("of".to_string()),
            "jno" => TipeOperand::Expression {
                operasi: OperasiIr::Cmp,
                operand_kiri: Box::new(TipeOperand::Register("of".to_string())),
                operand_kanan: Box::new(TipeOperand::Immediate(0))
            },
            "jb" | "jc" | "jnae" => TipeOperand::Register("cf".to_string()),
            "jae" | "jnb" | "jnc" => TipeOperand::Expression {
                operasi: OperasiIr::Cmp,
                operand_kiri: Box::new(TipeOperand::Register("cf".to_string())),
                operand_kanan: Box::new(TipeOperand::Immediate(0))
            },
            "jl" | "jnge" => {
                let sf = Box::new(TipeOperand::Register("sf".to_string()));
                let of = Box::new(TipeOperand::Register("of".to_string()));
                TipeOperand::Expression {
                    operasi: OperasiIr::Jne,
                    operand_kiri: sf,
                    operand_kanan: of
                }
            },
            "jge" | "jnl" => {
                let sf = Box::new(TipeOperand::Register("sf".to_string()));
                let of = Box::new(TipeOperand::Register("of".to_string()));
                TipeOperand::Expression {
                    operasi: OperasiIr::Je,
                    operand_kiri: sf,
                    operand_kanan: of
                }
            },
            "jg" | "jnle" => {
                let zf_check = Box::new(TipeOperand::Expression {
                    operasi: OperasiIr::Cmp,
                    operand_kiri: Box::new(TipeOperand::Register("zf".to_string())),
                    operand_kanan: Box::new(TipeOperand::Immediate(0))
                });
                let sf = Box::new(TipeOperand::Register("sf".to_string()));
                let of = Box::new(TipeOperand::Register("of".to_string()));
                let sf_eq_of = Box::new(TipeOperand::Expression {
                    operasi: OperasiIr::Je,
                    operand_kiri: sf,
                    operand_kanan: of
                });
                TipeOperand::Expression {
                    operasi: OperasiIr::And,
                    operand_kiri: zf_check,
                    operand_kanan: sf_eq_of
                }
            },
            _ => TipeOperand::Register("eflags".to_string())
        };
        let op_ir = match mnemonic {
            "je" | "jz" => OperasiIr::Je,
            "jne" | "jnz" => OperasiIr::Jne,
            "jg" | "ja" => OperasiIr::Jg,
            "jge" | "jae" => OperasiIr::Jge,
            "jl" | "jb" => OperasiIr::Jl,
            "jle" | "jbe" => OperasiIr::Jle,
            _ => OperasiIr::Jmp
        };
        ops.push(StatementIr::new(
            instr.address,
            op_ir,
            target,
            condition_expr
        ));
    }
    fn lift_unconditional_jump(&self, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
        let target = self.ambil_operand(instr, 0);
        ops.push(StatementIr::new(instr.address, OperasiIr::Jmp, target, TipeOperand::None));
    }
    fn lift_ret(&self, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
        ops.push(StatementIr::new(
            instr.address,
            OperasiIr::Add,
            TipeOperand::Register("rsp".to_string()),
            TipeOperand::Immediate(self.pointer_size),
        ).with_type(TipeDataIr::I64));
        ops.push(StatementIr::new(instr.address, OperasiIr::Ret, TipeOperand::None, TipeOperand::None));
    }
    fn lift_call(&self, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
        ops.push(StatementIr::new(
            instr.address,
            OperasiIr::Sub,
            TipeOperand::Register("rsp".to_string()),
            TipeOperand::Immediate(self.pointer_size),
        ).with_type(TipeDataIr::I64));
        let target = self.ambil_operand(instr, 0);
        ops.push(StatementIr::new(instr.address, OperasiIr::Call, target, TipeOperand::None));
    }
    fn lift_data_movement(&self, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
        let dest = self.ambil_operand(instr, 0);
        let src = self.ambil_operand(instr, 1);
        ops.push(StatementIr::new(instr.address, OperasiIr::Mov, dest, src));
    }
    fn lift_conditional_move(&self, instr: &InstructionNormalized, mnemonic: &str, ops: &mut Vec<StatementIr>) {
        let dest = self.ambil_operand(instr, 0);
        let src = self.ambil_operand(instr, 1);
        debug!("Conditional Move (CMOV) di 0x{:x} ({}) dilift sebagai Mov biasa (Lossy).", instr.address, mnemonic);
        ops.push(StatementIr::new(instr.address, OperasiIr::Mov, dest, src));
    }
    fn lift_lea(&self, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
        let dest = self.ambil_operand(instr, 0);
        let src = self.ambil_operand(instr, 1);
        ops.push(StatementIr::new(instr.address, OperasiIr::Lea, dest, src));
    }
    fn lift_push(&self, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
        if let Some(src_op) = instr.operands_detail.first() {
            let src = self.konversi_operand(src_op);
            ops.push(StatementIr::new(
                instr.address,
                OperasiIr::Sub,
                TipeOperand::Register("rsp".to_string()),
                TipeOperand::Immediate(self.pointer_size),
            ).with_type(TipeDataIr::I64));
            ops.push(StatementIr::new(
                instr.address,
                OperasiIr::Mov,
                TipeOperand::MemoryRef { base: "rsp".to_string(), offset: 0 },
                src
            ).with_type(TipeDataIr::I64));
        }
    }
    fn lift_pop(&self, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
        if let Some(dst_op) = instr.operands_detail.first() {
            let dst = self.konversi_operand(dst_op);
            ops.push(StatementIr::new(
                instr.address,
                OperasiIr::Mov,
                dst,
                TipeOperand::MemoryRef { base: "rsp".to_string(), offset: 0 },
            ).with_type(TipeDataIr::I64));
            ops.push(StatementIr::new(
                instr.address,
                OperasiIr::Add,
                TipeOperand::Register("rsp".to_string()),
                TipeOperand::Immediate(self.pointer_size),
            ).with_type(TipeDataIr::I64));
        }
    }
    fn lift_trap(&self, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
        ops.push(StatementIr::new(instr.address, OperasiIr::Unknown, TipeOperand::Immediate(0xCC), TipeOperand::None));
    }
    fn lift_generic_unknown(&self, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
        let op1 = self.ambil_operand(instr, 0);
        let op2 = self.ambil_operand(instr, 1);
        debug!("Instruksi tidak dikenal dilift sebagai Unknown: {}", instr.mnemonic);
        ops.push(StatementIr::new(instr.address, OperasiIr::Unknown, op1, op2));
    }
}