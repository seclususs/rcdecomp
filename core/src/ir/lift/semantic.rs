use std::collections::HashMap;
use crate::disasm::instruction::InstructionNormalized;
use crate::ir::types::{StatementIr, TipeOperand, OperasiIr, TipeDataIr};
use super::IrLifter;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EfekFlag {
    SetZero,
    SetSign,
    SetOverflow,
    SetCarry,
    SetParity,
    Undefined,
}

#[derive(Debug, Clone)]
pub struct TemplateMicroOp {
    pub operasi: OperasiIr,
    pub tipe_hasil: TipeDataIr,
    pub pakai_dest_sebagai_src1: bool,
    pub is_vector_op: bool,
}

#[derive(Debug, Clone)]
pub struct DeskripsiInstruksi {
    pub mnemonic: String,
    pub micro_ops: Vec<TemplateMicroOp>,
    pub efek_flags: Vec<EfekFlag>,
    pub operand_implisit: Vec<TipeOperand>, 
}

pub struct SemanticEngine {
    pub tabel_definisi: HashMap<String, DeskripsiInstruksi>,
}

impl SemanticEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            tabel_definisi: HashMap::new(),
        };
        engine.inisialisasi_definisi_standar();
        engine.inisialisasi_definisi_simd();
        engine
    }
    fn registrasi_instruksi(&mut self, mnemonic: &str, ops: Vec<TemplateMicroOp>, flags: Vec<EfekFlag>) {
        self.tabel_definisi.insert(mnemonic.to_string(), DeskripsiInstruksi {
            mnemonic: mnemonic.to_string(),
            micro_ops: ops,
            efek_flags: flags,
            operand_implisit: Vec::new(),
        });
    }
    fn inisialisasi_definisi_standar(&mut self) {
        self.registrasi_instruksi("add", vec![
            TemplateMicroOp { operasi: OperasiIr::Add, tipe_hasil: TipeDataIr::Unknown, pakai_dest_sebagai_src1: true, is_vector_op: false }
        ], vec![EfekFlag::SetZero, EfekFlag::SetSign, EfekFlag::SetOverflow, EfekFlag::SetCarry, EfekFlag::SetParity]);
        
        self.registrasi_instruksi("sub", vec![
            TemplateMicroOp { operasi: OperasiIr::Sub, tipe_hasil: TipeDataIr::Unknown, pakai_dest_sebagai_src1: true, is_vector_op: false }
        ], vec![EfekFlag::SetZero, EfekFlag::SetSign, EfekFlag::SetOverflow, EfekFlag::SetCarry, EfekFlag::SetParity]);
        
        self.registrasi_instruksi("imul", vec![
            TemplateMicroOp { operasi: OperasiIr::Imul, tipe_hasil: TipeDataIr::Unknown, pakai_dest_sebagai_src1: true, is_vector_op: false }
        ], vec![EfekFlag::SetOverflow, EfekFlag::SetCarry]); // imul x86: OF=CF, sisanya undefined

        self.registrasi_instruksi("xor", vec![
            TemplateMicroOp { operasi: OperasiIr::Xor, tipe_hasil: TipeDataIr::Unknown, pakai_dest_sebagai_src1: true, is_vector_op: false }
        ], vec![EfekFlag::SetZero, EfekFlag::SetSign, EfekFlag::SetParity, EfekFlag::Undefined]); // CF/OF cleared (0), SF/ZF/PF set
    }
    fn inisialisasi_definisi_simd(&mut self) {
        self.registrasi_instruksi("addps", vec![
            TemplateMicroOp { operasi: OperasiIr::VecAdd, tipe_hasil: TipeDataIr::V128F32, pakai_dest_sebagai_src1: true, is_vector_op: true }
        ], vec![]);
    }
    pub fn proses_lifting_otomatis(
        &self,
        lifter: &IrLifter,
        instr: &InstructionNormalized,
        ops_output: &mut Vec<StatementIr>
    ) -> bool {
        let mnemonic_lower = instr.mnemonic.to_lowercase();
        if let Some(definisi) = self.tabel_definisi.get(&mnemonic_lower) {
            self.generate_ir_dari_template(lifter, instr, definisi, ops_output);
            true
        } else {
            false
        }
    }
    fn generate_ir_dari_template(
        &self,
        lifter: &IrLifter,
        instr: &InstructionNormalized,
        def: &DeskripsiInstruksi,
        ops_output: &mut Vec<StatementIr>
    ) {
        let op_dest = lifter.ambil_operand(instr, 0);
        let op_src1 = lifter.ambil_operand(instr, 1);
        let op_src2 = lifter.ambil_operand(instr, 2);
        for micro_op in &def.micro_ops {
            let (final_op1, final_op2) = if micro_op.pakai_dest_sebagai_src1 {
                (op_dest.clone(), if op_src1 != TipeOperand::None { op_src1.clone() } else { op_dest.clone() })
            } else {
                if op_src2 != TipeOperand::None {
                    (op_src1.clone(), op_src2.clone())
                } else {
                    (op_dest.clone(), op_src1.clone())
                }
            };
            let result_expr = TipeOperand::Expression {
                operasi: micro_op.operasi.clone(),
                operand_kiri: Box::new(final_op1.clone()),
                operand_kanan: Box::new(final_op2.clone()),
            };
            ops_output.push(StatementIr::new(
                instr.address,
                micro_op.operasi.clone(),
                op_dest.clone(),
                result_expr.clone()
            ).with_type(micro_op.tipe_hasil.clone()));
            if !def.efek_flags.is_empty() {
                self.generate_efek_flags(instr.address, &def.efek_flags, &op_dest, ops_output);
            }
        }
    }
    fn generate_efek_flags(
        &self,
        addr: u64,
        flags: &[EfekFlag],
        result: &TipeOperand,
        ops_output: &mut Vec<StatementIr>
    ) {
        for flag in flags {
            match flag {
                EfekFlag::SetZero => {
                    let cond = TipeOperand::Expression {
                        operasi: OperasiIr::Je,
                        operand_kiri: Box::new(result.clone()),
                        operand_kanan: Box::new(TipeOperand::Immediate(0)),
                    };
                    ops_output.push(StatementIr::new(
                        addr,
                        OperasiIr::Mov,
                        TipeOperand::Register("eflags_zf".to_string()),
                        cond
                    ).with_type(TipeDataIr::I8));
                },
                EfekFlag::SetSign => {
                     ops_output.push(StatementIr::new(addr, OperasiIr::Unknown, TipeOperand::Register("eflags_sf".to_string()), result.clone()));
                },
                EfekFlag::Undefined => {
                     ops_output.push(StatementIr::new(addr, OperasiIr::Mov, TipeOperand::Register("eflags_undef".to_string()), TipeOperand::Immediate(1)));
                },
                _ => {} 
            }
        }
    }
}