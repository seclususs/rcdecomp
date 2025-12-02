use crate::disasm::instruction::InstructionNormalized;
use crate::ir::types::{StatementIr, TipeOperand, OperasiIr, TipeDataIr};
use super::IrLifter;
use super::flow::generate_kondisi_explicit;
use log::warn;

const FLAG_ZF: &str = "eflags_zf";
const FLAG_SF: &str = "eflags_sf";
const FLAG_CF: &str = "eflags_cf";
const FLAG_OF: &str = "eflags_of";
const FLAG_PF: &str = "eflags_pf";
const FLAG_AF: &str = "eflags_af";

pub fn proses_push(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    if let Some(src_op) = instr.operands_detail.first() {
        let src = lifter.konversi_operand(src_op);
        ops.push(StatementIr::new(
            instr.address,
            OperasiIr::Sub,
            TipeOperand::Register("rsp".to_string()),
            TipeOperand::Immediate(lifter.pointer_size),
        ).with_type(TipeDataIr::I64));
        ops.push(StatementIr::new(
            instr.address,
            OperasiIr::Mov,
            TipeOperand::MemoryRef { base: "rsp".to_string(), offset: 0 },
            src
        ).with_type(TipeDataIr::I64));
    }
}

pub fn proses_pop(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    if let Some(dst_op) = instr.operands_detail.first() {
        let dst = lifter.konversi_operand(dst_op);
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
            TipeOperand::Immediate(lifter.pointer_size),
        ).with_type(TipeDataIr::I64));
    }
}

pub fn proses_data_movement(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    let dest = lifter.ambil_operand(instr, 0);
    let src = lifter.ambil_operand(instr, 1);
    ops.push(StatementIr::new(instr.address, OperasiIr::Mov, dest, src));
}

pub fn proses_lea(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    let dest = lifter.ambil_operand(instr, 0);
    let src = lifter.ambil_operand(instr, 1);
    ops.push(StatementIr::new(instr.address, OperasiIr::Lea, dest, src));
}

pub fn proses_arithmetic_extended(
    lifter: &IrLifter,
    instr: &InstructionNormalized,
    ops: &mut Vec<StatementIr>
) {
    let mnemonic = instr.mnemonic.to_lowercase();
    match mnemonic.as_str() {
        "mul" | "imul" => proses_multiplication(lifter, instr, mnemonic.as_str(), ops),
        "div" | "idiv" => proses_division(lifter, instr, mnemonic.as_str(), ops),
        "adc" => proses_add_with_carry(lifter, instr, ops),
        "sbb" => proses_sub_with_borrow(lifter, instr, ops),
        "inc" => proses_inc_dec(lifter, instr, OperasiIr::Inc, ops),
        "dec" => proses_inc_dec(lifter, instr, OperasiIr::Dec, ops),
        _ => warn!("Unhandled extended arithmetic: {}", mnemonic),
    }
}

fn proses_inc_dec(lifter: &IrLifter, instr: &InstructionNormalized, op: OperasiIr, ops: &mut Vec<StatementIr>) {
    let dest = lifter.ambil_operand(instr, 0);
    let delta = if op == OperasiIr::Inc { 1 } else { -1 };
    let res_expr = TipeOperand::Expression {
        operasi: OperasiIr::Add,
        operand_kiri: Box::new(dest.clone()),
        operand_kanan: Box::new(TipeOperand::Immediate(delta)),
    };
    ops.push(StatementIr::new(instr.address, op.clone(), dest.clone(), res_expr).with_type(TipeDataIr::I64));
    hitung_flag_zero(instr.address, &dest, ops);
    hitung_flag_sign(instr.address, &dest, ops);
    hitung_flag_parity(instr.address, &dest, ops);
    hitung_flag_overflow(instr.address, op, &dest, &TipeOperand::Immediate(1), &dest, ops);
    emit_mov_flag(instr.address, FLAG_AF, TipeOperand::Register("undefined".to_string()), ops);
}

fn proses_multiplication(lifter: &IrLifter, instr: &InstructionNormalized, mnemonic: &str, ops: &mut Vec<StatementIr>) {
    let is_signed = mnemonic == "imul";
    let op_code = if is_signed { OperasiIr::Imul } else { OperasiIr::Mul };
    if instr.operands_detail.len() == 1 {
        let src = lifter.ambil_operand(instr, 0);
        let rax = TipeOperand::Register("rax".to_string());
        let rdx = TipeOperand::Register("rdx".to_string());
        let mul_expr = TipeOperand::Expression {
            operasi: op_code.clone(),
            operand_kiri: Box::new(rax.clone()),
            operand_kanan: Box::new(src.clone()),
        };
        ops.push(StatementIr::new(instr.address, op_code.clone(), rax.clone(), mul_expr));
        let mul_hi_expr = TipeOperand::Expression {
            operasi: OperasiIr::MulHi,
            operand_kiri: Box::new(rax.clone()),
            operand_kanan: Box::new(src.clone()),
        };
        ops.push(StatementIr::new(instr.address, OperasiIr::MulHi, rdx.clone(), mul_hi_expr));
        emit_mov_flag(instr.address, FLAG_CF, TipeOperand::Register("undefined".to_string()), ops);
        emit_mov_flag(instr.address, FLAG_OF, TipeOperand::Register("undefined".to_string()), ops);

    } else if instr.operands_detail.len() >= 2 {
        let dest = lifter.ambil_operand(instr, 0);
        let (src1, src2) = if instr.operands_detail.len() == 3 {
             (lifter.ambil_operand(instr, 1), lifter.ambil_operand(instr, 2))
        } else {
             (dest.clone(), lifter.ambil_operand(instr, 1))
        };
        let expr = TipeOperand::Expression {
            operasi: op_code,
            operand_kiri: Box::new(src1),
            operand_kanan: Box::new(src2),
        };
        ops.push(StatementIr::new(instr.address, OperasiIr::Imul, dest, expr));
    }
}

fn proses_division(lifter: &IrLifter, instr: &InstructionNormalized, mnemonic: &str, ops: &mut Vec<StatementIr>) {
    let is_signed = mnemonic == "idiv";
    let op_code = if is_signed { OperasiIr::Idiv } else { OperasiIr::Div };
    let src = lifter.ambil_operand(instr, 0);
    let rax = TipeOperand::Register("rax".to_string());
    let rdx = TipeOperand::Register("rdx".to_string());
    let div_expr = TipeOperand::Expression {
        operasi: op_code.clone(),
        operand_kiri: Box::new(rax.clone()),
        operand_kanan: Box::new(src.clone()),
    };
    ops.push(StatementIr::new(instr.address, op_code.clone(), rax.clone(), div_expr));
    ops.push(StatementIr::new(instr.address, OperasiIr::Unknown, rdx, TipeOperand::None));
}

fn proses_add_with_carry(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    let dest = lifter.ambil_operand(instr, 0);
    let src = lifter.ambil_operand(instr, 1);
    let cf = TipeOperand::Register(FLAG_CF.to_string());
    let tmp = TipeOperand::Expression {
        operasi: OperasiIr::Add,
        operand_kiri: Box::new(dest.clone()),
        operand_kanan: Box::new(src.clone()),
    };
    let res = TipeOperand::Expression {
        operasi: OperasiIr::Add,
        operand_kiri: Box::new(tmp),
        operand_kanan: Box::new(cf),
    };
    ops.push(StatementIr::new(instr.address, OperasiIr::Adc, dest.clone(), res).with_type(TipeDataIr::I64));
    hitung_flags_general(instr.address, &dest, ops);
}

fn proses_sub_with_borrow(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    let dest = lifter.ambil_operand(instr, 0);
    let src = lifter.ambil_operand(instr, 1);
    let cf = TipeOperand::Register(FLAG_CF.to_string());
    let tmp = TipeOperand::Expression {
        operasi: OperasiIr::Sub,
        operand_kiri: Box::new(dest.clone()),
        operand_kanan: Box::new(src.clone()),
    };
    let res = TipeOperand::Expression {
        operasi: OperasiIr::Sub,
        operand_kiri: Box::new(tmp),
        operand_kanan: Box::new(cf),
    };
    ops.push(StatementIr::new(instr.address, OperasiIr::Sbb, dest.clone(), res).with_type(TipeDataIr::I64));
    hitung_flags_general(instr.address, &dest, ops);
}

pub fn proses_arithmetic_explicit(
    lifter: &IrLifter, 
    instr: &InstructionNormalized, 
    op_code: OperasiIr, 
    ops: &mut Vec<StatementIr>
) {
    match instr.mnemonic.to_lowercase().as_str() {
        "mul" | "imul" | "div" | "idiv" | "adc" | "sbb" | "inc" | "dec" => {
            proses_arithmetic_extended(lifter, instr, ops);
            return;
        }
        _ => {}
    }
    let dest = lifter.ambil_operand(instr, 0);
    let src = lifter.ambil_operand(instr, 1);
    let (actual_op1, actual_op2) = (dest.clone(), src);
    let result_expr = TipeOperand::Expression {
        operasi: op_code.clone(),
        operand_kiri: Box::new(actual_op1.clone()),
        operand_kanan: Box::new(actual_op2.clone())
    };
    ops.push(StatementIr::new(
        instr.address,
        op_code.clone(),
        dest.clone(),
        result_expr
    ).with_type(TipeDataIr::I64));
    match op_code {
        OperasiIr::Add => hitung_flags_add(instr.address, &dest, &actual_op1, &actual_op2, ops),
        OperasiIr::Sub => hitung_flags_sub(instr.address, &dest, &actual_op1, &actual_op2, ops),
        OperasiIr::And | OperasiIr::Or | OperasiIr::Xor => hitung_flags_logical(instr.address, &dest, ops),
        OperasiIr::Shl | OperasiIr::Shr => hitung_flags_shift(instr.address, &dest, &actual_op1, &actual_op2, ops),
        _ => {}
    }
}

pub fn proses_comparison_explicit(
    lifter: &IrLifter, 
    instr: &InstructionNormalized, 
    op_code: OperasiIr, 
    ops: &mut Vec<StatementIr>
) {
    let op1 = lifter.ambil_operand(instr, 0);
    let op2 = lifter.ambil_operand(instr, 1);
    let temp_result = TipeOperand::Register("temp_alu_flags".to_string());
    match op_code {
        OperasiIr::Sub => {
             ops.push(StatementIr::new(
                instr.address, 
                OperasiIr::Cmp, 
                temp_result.clone(), 
                TipeOperand::Expression { operasi: OperasiIr::Sub, operand_kiri: Box::new(op1.clone()), operand_kanan: Box::new(op2.clone()) }
            ));
            hitung_flags_sub(instr.address, &temp_result, &op1, &op2, ops);
        },
        OperasiIr::And => {
            ops.push(StatementIr::new(
                instr.address, 
                OperasiIr::Test, 
                temp_result.clone(), 
                TipeOperand::Expression { operasi: OperasiIr::And, operand_kiri: Box::new(op1.clone()), operand_kanan: Box::new(op2.clone()) }
            ));
            hitung_flags_logical(instr.address, &temp_result, ops);
        },
        _ => {}
    }
}

pub fn proses_generic_unknown(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    let op1 = lifter.ambil_operand(instr, 0);
    let op2 = lifter.ambil_operand(instr, 1);
    warn!("Instruksi tidak dikenal dilift sebagai Unknown: {}", instr.mnemonic);
    ops.push(StatementIr::new(instr.address, OperasiIr::Unknown, op1, op2));
}

fn hitung_flags_general(addr: u64, result: &TipeOperand, ops: &mut Vec<StatementIr>) {
    hitung_flag_zero(addr, result, ops);
    hitung_flag_sign(addr, result, ops);
    hitung_flag_parity(addr, result, ops); 
}

fn hitung_flags_logical(addr: u64, result: &TipeOperand, ops: &mut Vec<StatementIr>) {
    emit_mov_flag(addr, FLAG_CF, TipeOperand::Immediate(0), ops);
    emit_mov_flag(addr, FLAG_OF, TipeOperand::Immediate(0), ops);
    hitung_flag_zero(addr, result, ops);
    hitung_flag_sign(addr, result, ops);
    hitung_flag_parity(addr, result, ops);
    emit_mov_flag(addr, FLAG_AF, TipeOperand::Register("undefined".to_string()), ops);
}

fn hitung_flags_add(addr: u64, result: &TipeOperand, op1: &TipeOperand, op2: &TipeOperand, ops: &mut Vec<StatementIr>) {
    hitung_flag_zero(addr, result, ops);
    hitung_flag_sign(addr, result, ops);
    hitung_flag_parity(addr, result, ops);
    let check_cf = TipeOperand::Expression {
        operasi: OperasiIr::Jl,
        operand_kiri: Box::new(result.clone()),
        operand_kanan: Box::new(op1.clone()),
    };
    emit_mov_flag(addr, FLAG_CF, check_cf, ops);
    hitung_flag_overflow(addr, OperasiIr::Add, result, op1, op2, ops);
}

fn hitung_flags_sub(addr: u64, result: &TipeOperand, op1: &TipeOperand, op2: &TipeOperand, ops: &mut Vec<StatementIr>) {
    hitung_flag_zero(addr, result, ops);
    hitung_flag_sign(addr, result, ops);
    hitung_flag_parity(addr, result, ops);
    let check_cf = TipeOperand::Expression {
        operasi: OperasiIr::Jl, 
        operand_kiri: Box::new(op1.clone()),
        operand_kanan: Box::new(op2.clone()),
    };
    emit_mov_flag(addr, FLAG_CF, check_cf, ops);
    hitung_flag_overflow(addr, OperasiIr::Sub, result, op1, op2, ops);
}

fn hitung_flag_overflow(addr: u64, _op: OperasiIr, _result: &TipeOperand, _op1: &TipeOperand, _op2: &TipeOperand, ops: &mut Vec<StatementIr>) {
    emit_mov_flag(addr, FLAG_OF, TipeOperand::Register("calc_overflow_deferred".to_string()), ops);
}

fn hitung_flags_shift(addr: u64, result: &TipeOperand, _op1: &TipeOperand, _op2: &TipeOperand, ops: &mut Vec<StatementIr>) {
    hitung_flag_zero(addr, result, ops);
    hitung_flag_sign(addr, result, ops);
    hitung_flag_parity(addr, result, ops);
}

fn hitung_flag_zero(addr: u64, result: &TipeOperand, ops: &mut Vec<StatementIr>) {
    let cond = make_binary_expr(OperasiIr::Je, result.clone(), TipeOperand::Immediate(0));
    let val = TipeOperand::Conditional {
        condition: Box::new(cond),
        true_val: Box::new(TipeOperand::Immediate(1)),
        false_val: Box::new(TipeOperand::Immediate(0)),
    };
    emit_mov_flag(addr, FLAG_ZF, val, ops);
}

fn hitung_flag_sign(addr: u64, result: &TipeOperand, ops: &mut Vec<StatementIr>) {
    let shift = make_binary_expr(OperasiIr::Shr, result.clone(), TipeOperand::Immediate(63));
    let mask = make_binary_expr(OperasiIr::And, shift, TipeOperand::Immediate(1));
    emit_mov_flag(addr, FLAG_SF, mask, ops);
}

fn hitung_flag_parity(addr: u64, result: &TipeOperand, ops: &mut Vec<StatementIr>) {
    let mask_byte = make_binary_expr(OperasiIr::And, result.clone(), TipeOperand::Immediate(0xFF));
    let temp_pop = TipeOperand::Register("temp_popcnt".to_string());
    ops.push(StatementIr::new(
        addr,
        OperasiIr::Popcnt,
        temp_pop.clone(),
        mask_byte
    ).with_type(TipeDataIr::I8));
    let bit_check = make_binary_expr(OperasiIr::And, temp_pop, TipeOperand::Immediate(1));
    let is_even = make_binary_expr(OperasiIr::Je, bit_check, TipeOperand::Immediate(0));
    let pf_val = TipeOperand::Conditional {
        condition: Box::new(is_even),
        true_val: Box::new(TipeOperand::Immediate(1)),
        false_val: Box::new(TipeOperand::Immediate(0)),
    };
    emit_mov_flag(addr, FLAG_PF, pf_val, ops);
}

fn emit_mov_flag(addr: u64, flag_reg: &str, val: TipeOperand, ops: &mut Vec<StatementIr>) {
    ops.push(StatementIr::new(
        addr,
        OperasiIr::Mov,
        TipeOperand::Register(flag_reg.to_string()),
        val
    ).with_type(TipeDataIr::I8));
}

fn make_binary_expr(op: OperasiIr, left: TipeOperand, right: TipeOperand) -> TipeOperand {
    TipeOperand::Expression {
        operasi: op,
        operand_kiri: Box::new(left),
        operand_kanan: Box::new(right),
    }
}

pub fn proses_conditional_move(
    lifter: &IrLifter, 
    instr: &InstructionNormalized, 
    mnemonic: &str, 
    ops: &mut Vec<StatementIr>
) {
    let dest = lifter.ambil_operand(instr, 0);
    let src = lifter.ambil_operand(instr, 1);
    let suffix = if mnemonic.starts_with("cmov") {
        mnemonic.strip_prefix("cmov").unwrap_or("")
    } else {
        ""
    };
    let condition = generate_kondisi_explicit(suffix);
    let conditional_expr = TipeOperand::Conditional {
        condition: Box::new(condition),
        true_val: Box::new(src), 
        false_val: Box::new(dest.clone()) 
    };
    ops.push(StatementIr::new(instr.address, OperasiIr::Cmov, dest, conditional_expr));
}