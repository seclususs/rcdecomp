use crate::disasm::instruction::InstructionNormalized;
use crate::ir::types::{StatementIr, TipeOperand, OperasiIr, TipeDataIr};
use super::IrLifter;

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
            operasi: OperasiIr::Cmp,
            operand_kiri: Box::new(reg),
            operand_kanan: Box::new(TipeOperand::Immediate(0)),
        };
        ops.push(StatementIr::new(instr.address, OperasiIr::Je, jump_target, cond));
        return;
    } else if mnemonic == "cbnz" {
        let reg = lifter.ambil_operand(instr, 0);
        let jump_target = lifter.ambil_operand(instr, 1);
        let cond = TipeOperand::Expression {
            operasi: OperasiIr::Cmp,
            operand_kiri: Box::new(reg),
            operand_kanan: Box::new(TipeOperand::Immediate(0)),
        };
        ops.push(StatementIr::new(instr.address, OperasiIr::Jne, jump_target, cond));
        return;
    } else {
        ""
    };
    let condition_expr = dapatkan_kondisi_lazy(suffix);
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

pub fn dapatkan_kondisi_lazy(mnemonic_suffix: &str) -> TipeOperand {
    let suffix = if mnemonic_suffix.starts_with("b.") {
        mnemonic_suffix.strip_prefix("b.").unwrap_or("")
    } else {
        mnemonic_suffix
    };
    let helper_name = match suffix {
        "e" | "z" | "eq" => "check_zf",
        "ne" | "nz"      => "check_nz",
        "s" | "mi"       => "check_sf",
        "ns" | "pl"      => "check_ns",
        "o" | "vs"       => "check_of",
        "b" | "c" | "nae" | "lo" => "check_cf",
        "l" | "lt"       => "check_lt",
        "ge" | "nl"      => "check_ge",
        "le"             => "check_le",
        "gt"             => "check_gt",
        _ => "check_unknown"
    };
    TipeOperand::Register(format!("lazy_{}", helper_name))
}