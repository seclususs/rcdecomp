use crate::disasm::instruction::InstructionNormalized;
use crate::ir::types::{StatementIr, TipeOperand, OperasiIr, TipeDataIr};
use super::IrLifter;

const FLAG_ZF: &str = "eflags_zf";
const FLAG_CF: &str = "eflags_cf";
const FLAG_SF: &str = "eflags_sf";
const FLAG_OF: &str = "eflags_of";

pub fn proses_ret(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    ops.push(StatementIr::new(
        instr.address,
        OperasiIr::Add,
        TipeOperand::Register("rsp".to_string()),
        TipeOperand::Immediate(lifter.pointer_size),
    ).with_type(TipeDataIr::I64));
    ops.push(StatementIr::new(instr.address, OperasiIr::Ret, TipeOperand::None, TipeOperand::None));
}

pub fn proses_call(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    ops.push(StatementIr::new(
        instr.address,
        OperasiIr::Sub,
        TipeOperand::Register("rsp".to_string()),
        TipeOperand::Immediate(lifter.pointer_size),
    ).with_type(TipeDataIr::I64));
    let target = lifter.ambil_operand(instr, 0);
    ops.push(StatementIr::new(instr.address, OperasiIr::Call, target, TipeOperand::None));
}

pub fn proses_unconditional_jump(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    let target = lifter.ambil_operand(instr, 0);
    ops.push(StatementIr::new(instr.address, OperasiIr::Jmp, target, TipeOperand::None));
}

pub fn proses_conditional_branch(
    lifter: &IrLifter, 
    instr: &InstructionNormalized, 
    mnemonic: &str, 
    ops: &mut Vec<StatementIr>
) {
    let target = lifter.ambil_operand(instr, 0);
    let suffix = if mnemonic.starts_with('j') {
        mnemonic.strip_prefix('j').unwrap_or("")
    } else if mnemonic.starts_with("b.") {
        mnemonic.strip_prefix("b.").unwrap_or("")
    } else if mnemonic == "cbz" {
        let reg = lifter.ambil_operand(instr, 0);
        let jump_target = lifter.ambil_operand(instr, 1);
        let cond = TipeOperand::Expression {
            operasi: OperasiIr::Je,
            operand_kiri: Box::new(reg),
            operand_kanan: Box::new(TipeOperand::Immediate(0)),
        };
        ops.push(StatementIr::new(instr.address, OperasiIr::Je, jump_target, cond));
        return;
    } else if mnemonic == "cbnz" {
        let reg = lifter.ambil_operand(instr, 0);
        let jump_target = lifter.ambil_operand(instr, 1);
        let cond = TipeOperand::Expression {
            operasi: OperasiIr::Jne, 
            operand_kiri: Box::new(reg),
            operand_kanan: Box::new(TipeOperand::Immediate(0)),
        };
        ops.push(StatementIr::new(instr.address, OperasiIr::Jne, jump_target, cond));
        return;
    } else {
        ""
    };
    let condition_expr = generate_kondisi_explicit(suffix);
    let op_ir = match suffix {
        "e" | "z" | "eq" => OperasiIr::Je,
        "ne" | "nz" => OperasiIr::Jne,
        "g" | "gt" | "a" | "ja" => OperasiIr::Jg,
        "ge" | "ae" | "jge" => OperasiIr::Jge,
        "l" | "lt" | "b" | "jb" => OperasiIr::Jl,
        "le" | "be" | "jle" => OperasiIr::Jle,
        _ => OperasiIr::Jmp
    };
    ops.push(StatementIr::new(
        instr.address,
        op_ir,
        target,
        condition_expr
    ));
}

pub fn generate_kondisi_explicit(mnemonic_suffix: &str) -> TipeOperand {
    let suffix = if mnemonic_suffix.starts_with("b.") {
        mnemonic_suffix.strip_prefix("b.").unwrap_or("")
    } else {
        mnemonic_suffix
    };
    let zf = TipeOperand::Register(FLAG_ZF.to_string());
    let cf = TipeOperand::Register(FLAG_CF.to_string());
    let sf = TipeOperand::Register(FLAG_SF.to_string());
    let of = TipeOperand::Register(FLAG_OF.to_string());
    let one = TipeOperand::Immediate(1);
    let zero = TipeOperand::Immediate(0);
    match suffix {
        "e" | "z" | "eq" => {
            make_comparison(OperasiIr::Je, zf, one)
        },
        "ne" | "nz" => {
            make_comparison(OperasiIr::Je, zf, zero)
        },
        "s" | "mi" => {
            make_comparison(OperasiIr::Je, sf, one)
        },
        "ns" | "pl" => {
            make_comparison(OperasiIr::Je, sf, zero)
        },
        "b" | "c" | "nae" | "lo" => {
            make_comparison(OperasiIr::Je, cf, one)
        },
        "nb" | "ae" | "nc" => {
            make_comparison(OperasiIr::Je, cf, zero)
        },
        "l" | "lt" => {
            make_comparison(OperasiIr::Jne, sf, of)
        },
        "ge" | "nl" => {
            make_comparison(OperasiIr::Je, sf, of)
        },
        "le" => {
            let zf_set = make_comparison(OperasiIr::Je, zf, one.clone());
            let sf_neq_of = make_comparison(OperasiIr::Jne, sf, of);
            make_binary(OperasiIr::Or, zf_set, sf_neq_of)
        },
        "g" | "gt" => {
            let zf_clear = make_comparison(OperasiIr::Je, zf, zero);
            let sf_eq_of = make_comparison(OperasiIr::Je, sf, of);
            make_binary(OperasiIr::And, zf_clear, sf_eq_of)
        },
        "a" | "ja" => {
            let cf_clear = make_comparison(OperasiIr::Je, cf, zero.clone());
            let zf_clear = make_comparison(OperasiIr::Je, zf, zero);
            make_binary(OperasiIr::And, cf_clear, zf_clear)
        },
        "be" | "jna" => {
             let cf_set = make_comparison(OperasiIr::Je, cf, one.clone());
             let zf_set = make_comparison(OperasiIr::Je, zf, one);
             make_binary(OperasiIr::Or, cf_set, zf_set)
        },
        "o" | "vs" => {
            make_comparison(OperasiIr::Je, of, one)
        },
        _ => TipeOperand::Immediate(1)
    }
}

fn make_comparison(op: OperasiIr, left: TipeOperand, right: TipeOperand) -> TipeOperand {
    TipeOperand::Expression {
        operasi: op,
        operand_kiri: Box::new(left),
        operand_kanan: Box::new(right),
    }
}

fn make_binary(op: OperasiIr, left: TipeOperand, right: TipeOperand) -> TipeOperand {
    TipeOperand::Expression {
        operasi: op,
        operand_kiri: Box::new(left),
        operand_kanan: Box::new(right),
    }
}