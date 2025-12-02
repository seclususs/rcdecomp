use crate::disasm::instruction::InstructionNormalized;
use crate::ir::types::{StatementIr, TipeOperand, OperasiIr, TipeDataIr};
use super::IrLifter;

const FLAG_CF: &str = "eflags_cf";
const FLAG_ZF: &str = "eflags_zf";
const FLAG_SF: &str = "eflags_sf";
const FLAG_OF: &str = "eflags_of";
const FLAG_PF: &str = "eflags_pf";

pub fn proses_shift_rotate(
    lifter: &IrLifter, 
    instr: &InstructionNormalized, 
    mnemonic: &str, 
    ops: &mut Vec<StatementIr>
) {
    let dest = lifter.ambil_operand(instr, 0);
    let count_raw = if instr.operands_detail.len() > 1 {
        lifter.ambil_operand(instr, 1)
    } else {
        TipeOperand::Immediate(1)
    };
    let op_ir = match mnemonic {
        "shl" | "sal" => OperasiIr::Shl,
        "shr" => OperasiIr::Shr,
        "sar" => OperasiIr::Sar, 
        "rol" => OperasiIr::Rol,
        "ror" => OperasiIr::Ror,
        _ => OperasiIr::Unknown,
    };
    let mask_val = TipeOperand::Immediate(0x3F);
    let count_masked = TipeOperand::Expression {
        operasi: OperasiIr::And,
        operand_kiri: Box::new(count_raw),
        operand_kanan: Box::new(mask_val),
    };
    let result_expr = TipeOperand::Expression {
        operasi: op_ir.clone(),
        operand_kiri: Box::new(dest.clone()),
        operand_kanan: Box::new(count_masked.clone()),
    };
    ops.push(StatementIr::new(
        instr.address,
        op_ir.clone(),
        dest.clone(),
        result_expr.clone()
    ).with_type(TipeDataIr::I64));
    match mnemonic {
        "shl" | "sal" | "shr" | "sar" => {
            update_flags_shift(instr.address, mnemonic, &dest, &count_masked, ops);
        },
        "rol" | "ror" => {
            update_flags_rotate(instr.address, mnemonic, &dest, &count_masked, ops);
        },
        _ => {}
    }
}

fn update_flags_shift(
    addr: u64, 
    mnemonic: &str, 
    result_op: &TipeOperand, 
    count_op: &TipeOperand, 
    ops: &mut Vec<StatementIr>
) {
    let is_count_zero = TipeOperand::Expression {
        operasi: OperasiIr::Je,
        operand_kiri: Box::new(count_op.clone()),
        operand_kanan: Box::new(TipeOperand::Immediate(0))
    };
    let apply_conditional_flag = |target_flag: &str, new_calc: TipeOperand, ops_vec: &mut Vec<StatementIr>| {
        let old_flag = TipeOperand::Register(target_flag.to_string());
        let final_val = TipeOperand::Conditional {
            condition: Box::new(is_count_zero.clone()),
            true_val: Box::new(old_flag),
            false_val: Box::new(new_calc),
        };
        ops_vec.push(StatementIr::new(addr, OperasiIr::Mov, TipeOperand::Register(target_flag.to_string()), final_val));
    };
    let sf_calc = TipeOperand::Expression {
        operasi: OperasiIr::Shr,
        operand_kiri: Box::new(result_op.clone()),
        operand_kanan: Box::new(TipeOperand::Immediate(63)),
    };
    apply_conditional_flag(FLAG_SF, sf_calc, ops);
    let zf_calc = TipeOperand::Expression {
        operasi: OperasiIr::Je,
        operand_kiri: Box::new(result_op.clone()),
        operand_kanan: Box::new(TipeOperand::Immediate(0)),
    };
    apply_conditional_flag(FLAG_ZF, zf_calc, ops);
    let pf_calc = TipeOperand::Expression {
        operasi: OperasiIr::Call,
        operand_kiri: Box::new(TipeOperand::Register("__intrinsic_parity".to_string())),
        operand_kanan: Box::new(result_op.clone())
    };
    apply_conditional_flag(FLAG_PF, pf_calc, ops);
    let is_count_one = TipeOperand::Expression {
        operasi: OperasiIr::Je,
        operand_kiri: Box::new(count_op.clone()),
        operand_kanan: Box::new(TipeOperand::Immediate(1))
    };
    let of_defined_val = if mnemonic == "shl" || mnemonic == "sal" {
         TipeOperand::Expression {
            operasi: OperasiIr::Xor,
            operand_kiri: Box::new(TipeOperand::Register(FLAG_SF.to_string())), 
            operand_kanan: Box::new(TipeOperand::Register(FLAG_CF.to_string()))
        }
    } else if mnemonic == "shr" {
        TipeOperand::Immediate(0)
    } else {
        TipeOperand::Immediate(0)
    };
    let of_calc = TipeOperand::Conditional {
        condition: Box::new(is_count_one),
        true_val: Box::new(of_defined_val),
        false_val: Box::new(TipeOperand::Register("UNDEFINED_FLAG".to_string()))
    };
    apply_conditional_flag(FLAG_OF, of_calc, ops);
}

fn update_flags_rotate(
    addr: u64,
    _mnemonic: &str,
    _result_op: &TipeOperand,
    count_op: &TipeOperand,
    ops: &mut Vec<StatementIr>
) {
    let is_count_zero = TipeOperand::Expression {
        operasi: OperasiIr::Je,
        operand_kiri: Box::new(count_op.clone()),
        operand_kanan: Box::new(TipeOperand::Immediate(0))
    };
    let set_undefined = |flag: &str, ops_vec: &mut Vec<StatementIr>| {
        let old_val = TipeOperand::Register(flag.to_string());
        let undef_val = TipeOperand::Register("UNDEFINED".to_string());
        let final_val = TipeOperand::Conditional {
            condition: Box::new(is_count_zero.clone()),
            true_val: Box::new(old_val),
            false_val: Box::new(undef_val)
        };
        ops_vec.push(StatementIr::new(addr, OperasiIr::Mov, TipeOperand::Register(flag.to_string()), final_val));
    };
    set_undefined(FLAG_ZF, ops);
    set_undefined(FLAG_SF, ops);
    set_undefined(FLAG_PF, ops);
}