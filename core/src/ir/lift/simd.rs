use crate::disasm::instruction::InstructionNormalized;
use crate::ir::types::{StatementIr, TipeOperand, OperasiIr, TipeDataIr};
use super::IrLifter;
use log::debug;

pub fn cek_is_simd_instruction(mnemonic: &str) -> bool {
    mnemonic.starts_with('v') ||
    mnemonic.starts_with('p') ||
    mnemonic.ends_with("ps") || mnemonic.ends_with("pd") ||
    mnemonic.ends_with("ss") || mnemonic.ends_with("sd") ||
    mnemonic.contains("xmm") || mnemonic.contains("ymm") || mnemonic.contains("zmm")
}

pub fn proses_simd_to_intrinsic(
    lifter: &IrLifter, 
    instr: &InstructionNormalized, 
    mnemonic: &str, 
    ops: &mut Vec<StatementIr>
) {
    let (base_mnemonic, is_avx) = if mnemonic.starts_with('v') {
        (mnemonic.strip_prefix('v').unwrap_or(mnemonic), true)
    } else {
        (mnemonic, false)
    };
    let op_str = &instr.op_str;
    let width = if op_str.contains("zmm") {
        TipeDataIr::V512
    } else if op_str.contains("ymm") {
        TipeDataIr::V256
    } else {
        TipeDataIr::V128
    };
    let mask_reg = if let Some(start) = op_str.find("{k") {
        if let Some(end) = op_str[start..].find('}') {
            Some(op_str[start+1..start+end].to_string())
        } else { None }
    } else { None };
    let dest = lifter.ambil_operand(instr, 0);
    let src1 = lifter.ambil_operand(instr, 1);
    let ir_op = match base_mnemonic {
        "addps" | "addpd" | "paddd" | "paddq" => Some(OperasiIr::VecAdd),
        "subps" | "subpd" | "psubd" | "psubq" => Some(OperasiIr::VecSub),
        "mulps" | "mulpd" => Some(OperasiIr::VecMul),
        "divps" | "divpd" => Some(OperasiIr::VecDiv),
        "andps" | "andpd" | "pand" => Some(OperasiIr::VecAnd),
        "orps" | "orpd" | "por" => Some(OperasiIr::VecOr),
        "xorps" | "xorpd" | "pxor" => Some(OperasiIr::VecXor),
        "movaps" | "movups" | "movdqa" | "movdqu" => Some(OperasiIr::VecMov),
        _ => None
    };
    if let Some(op_vec) = ir_op {
        let actual_src2 = if instr.operands_detail.len() > 2 {
            lifter.ambil_operand(instr, 2)
        } else {
            src1.clone()
        };
        let mut result_expr = if op_vec == OperasiIr::VecMov {
             src1.clone()
        } else {
             let (op_a, op_b) = if is_avx && instr.operands_detail.len() >= 3 {
                 (src1.clone(), actual_src2)
             } else {
                 (dest.clone(), src1.clone())
             };
             TipeOperand::Expression {
                operasi: op_vec.clone(),
                operand_kiri: Box::new(op_a),
                operand_kanan: Box::new(op_b),
            }
        };
        if let Some(k_reg) = mask_reg {
            result_expr = TipeOperand::Conditional {
                condition: Box::new(TipeOperand::Register(k_reg)),
                true_val: Box::new(result_expr),
                false_val: Box::new(dest.clone())
            };
        }
        ops.push(StatementIr::new(instr.address, op_vec, dest, result_expr).with_type(width));
        return;
    }
    generate_generic_intrinsic(lifter, instr, mnemonic, width, mask_reg, ops);
}

fn generate_generic_intrinsic(
    lifter: &IrLifter,
    instr: &InstructionNormalized,
    mnemonic: &str,
    width: TipeDataIr,
    mask: Option<String>,
    ops: &mut Vec<StatementIr>
) {
    let dest = lifter.ambil_operand(instr, 0);
    let intrinsic_name = format!("_mm_{}_generic", mnemonic);
    let mut args = Vec::new();
    if let Some(k) = mask {
        args.push(TipeOperand::Register(k));
    }
    for i in 1..instr.operands_detail.len() {
        args.push(lifter.ambil_operand(instr, i));
    }
    let mut call = StatementIr::new(
        instr.address, 
        OperasiIr::Intrinsic(intrinsic_name.clone()), 
        dest.clone(), 
        TipeOperand::None
    ).with_type(width);
    
    call.operand_tambahan = args;
    ops.push(call);
    debug!("Generated intrinsic SIMD: {} -> {}", mnemonic, intrinsic_name);
}