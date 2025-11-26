use crate::disasm::instruction::InstructionNormalized;
use crate::ir::types::{StatementIr, TipeOperand, OperasiIr, TipeDataIr};
use super::IrLifter;
use super::flow::dapatkan_kondisi_lazy;
use log::warn;

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

pub fn proses_load_operation(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    proses_data_movement(lifter, instr, ops);
}

pub fn proses_store_operation(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    let src_reg = lifter.ambil_operand(instr, 0);
    let dest_mem = lifter.ambil_operand(instr, 1);
    ops.push(StatementIr::new(instr.address, OperasiIr::Mov, dest_mem, src_reg));
}

pub fn proses_load_pair(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    let reg1 = lifter.ambil_operand(instr, 0);
    let reg2 = lifter.ambil_operand(instr, 1);
    let mem_base = lifter.ambil_operand(instr, 2);
    ops.push(StatementIr::new(instr.address, OperasiIr::Mov, reg1, mem_base.clone()));
    if let TipeOperand::MemoryRef { base, offset } = mem_base {
        let next_mem = TipeOperand::MemoryRef { base, offset: offset + 8 };
        ops.push(StatementIr::new(instr.address, OperasiIr::Mov, reg2, next_mem));
    } else {
        ops.push(StatementIr::new(instr.address, OperasiIr::Unknown, reg2, TipeOperand::None));
    }
}

pub fn proses_store_pair(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    let reg1 = lifter.ambil_operand(instr, 0);
    let reg2 = lifter.ambil_operand(instr, 1);
    let mem_base = lifter.ambil_operand(instr, 2);
    ops.push(StatementIr::new(instr.address, OperasiIr::Mov, mem_base.clone(), reg1));
    if let TipeOperand::MemoryRef { base, offset } = mem_base {
        let next_mem = TipeOperand::MemoryRef { base, offset: offset + 8 };
        ops.push(StatementIr::new(instr.address, OperasiIr::Mov, next_mem, reg2));
    }
}

pub fn proses_lea(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    let dest = lifter.ambil_operand(instr, 0);
    let src = lifter.ambil_operand(instr, 1);
    ops.push(StatementIr::new(instr.address, OperasiIr::Lea, dest, src));
}

pub fn proses_arithmetic_lazy(
    lifter: &IrLifter, 
    instr: &InstructionNormalized, 
    op_code: OperasiIr, 
    ops: &mut Vec<StatementIr>
) {
    let dest = lifter.ambil_operand(instr, 0);
    let src = lifter.ambil_operand(instr, 1);
    let (actual_op1, actual_op2) = if src == TipeOperand::None {
        match instr.mnemonic.as_str() {
            "inc" => (dest.clone(), TipeOperand::Immediate(1)),
            "dec" => (dest.clone(), TipeOperand::Immediate(1)),
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
    hitung_dan_emit_lazy_flags(instr.address, op_code, &dest, &actual_op1, &actual_op2, ops);
}

pub fn proses_comparison_lazy(
    lifter: &IrLifter, 
    instr: &InstructionNormalized, 
    op_code: OperasiIr, 
    ops: &mut Vec<StatementIr>
) {
    let op1 = lifter.ambil_operand(instr, 0);
    let op2 = lifter.ambil_operand(instr, 1);
    hitung_dan_emit_lazy_flags(instr.address, op_code, &op1, &op1, &op2, ops);
}

pub fn hitung_dan_emit_lazy_flags(
    addr: u64, 
    op_code: OperasiIr, 
    _dest: &TipeOperand,
    op1: &TipeOperand, 
    op2: &TipeOperand, 
    ops: &mut Vec<StatementIr>
) {
    let op_id = match op_code {
        OperasiIr::Add => 1,
        OperasiIr::Sub => 2,
        OperasiIr::Imul => 3,
        OperasiIr::And => 4,
        OperasiIr::Or => 5,
        OperasiIr::Xor => 6,
        OperasiIr::Shl => 7,
        OperasiIr::Shr => 8,
        OperasiIr::Cmp => 2,
        _ => 0
    };
    ops.push(StatementIr::new(
        addr, 
        OperasiIr::Mov, 
        TipeOperand::Register("cc_op".to_string()), 
        TipeOperand::Immediate(op_id)
    ));
    ops.push(StatementIr::new(
        addr,
        OperasiIr::Mov,
        TipeOperand::Register("cc_src1".to_string()),
        op1.clone()
    ));
    ops.push(StatementIr::new(
        addr,
        OperasiIr::Mov,
        TipeOperand::Register("cc_src2".to_string()),
        op2.clone()
    ));
    let result_expr = TipeOperand::Expression {
        operasi: op_code,
        operand_kiri: Box::new(op1.clone()),
        operand_kanan: Box::new(op2.clone())
    };
    ops.push(StatementIr::new(
        addr,
        OperasiIr::Mov,
        TipeOperand::Register("cc_dst".to_string()),
        result_expr
    ));
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
    } else if mnemonic == "csel" {
        "eq" 
    } else {
        ""
    };
    let condition = dapatkan_kondisi_lazy(suffix);
    let conditional_expr = TipeOperand::Conditional {
        condition: Box::new(condition),
        true_val: Box::new(src),
        false_val: Box::new(dest.clone())
    };
    ops.push(StatementIr::new(instr.address, OperasiIr::Mov, dest, conditional_expr));
}

pub fn proses_not_operation(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    let dest = lifter.ambil_operand(instr, 0);
    let src = lifter.ambil_operand(instr, 1);
    let actual_src = if src == TipeOperand::None { dest.clone() } else { src };
    let not_expr = TipeOperand::Expression {
        operasi: OperasiIr::Xor,
        operand_kiri: Box::new(actual_src),
        operand_kanan: Box::new(TipeOperand::Immediate(-1)),
    };
    ops.push(StatementIr::new(instr.address, OperasiIr::Mov, dest, not_expr));
}

pub fn proses_neg_operation(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    let dest = lifter.ambil_operand(instr, 0);
    let src = lifter.ambil_operand(instr, 1);
    let actual_src = if src == TipeOperand::None { dest.clone() } else { src };
    let neg_expr = TipeOperand::Expression {
        operasi: OperasiIr::Sub,
        operand_kiri: Box::new(TipeOperand::Immediate(0)),
        operand_kanan: Box::new(actual_src),
    };
    ops.push(StatementIr::new(instr.address, OperasiIr::Mov, dest, neg_expr));
}

pub fn proses_bit_clear(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    let dest = lifter.ambil_operand(instr, 0);
    let src1 = lifter.ambil_operand(instr, 1);
    let src2 = lifter.ambil_operand(instr, 2);
    let not_src2 = Box::new(TipeOperand::Expression {
        operasi: OperasiIr::Xor,
        operand_kiri: Box::new(src2),
        operand_kanan: Box::new(TipeOperand::Immediate(-1)),
    });
    let and_expr = TipeOperand::Expression {
        operasi: OperasiIr::And,
        operand_kiri: Box::new(src1),
        operand_kanan: not_src2,
    };
    ops.push(StatementIr::new(instr.address, OperasiIr::Mov, dest, and_expr));
}

pub fn proses_atomic_instruction(lifter: &IrLifter, instr: &InstructionNormalized, mnemonic: &str, ops: &mut Vec<StatementIr>) {
    let op_atomic = match mnemonic {
        "xadd" | "lock" => "__atomic_fetch_add",
        "cmpxchg" | "cas" => "__atomic_compare_exchange",
        "xchg" => "__atomic_exchange",
        "ldxr" | "ldaxr" => "__atomic_load_exclusive",
        "stxr" | "stlxr" => "__atomic_store_exclusive",
        _ => "__atomic_generic"
    };
    let op1 = lifter.ambil_operand(instr, 0);
    let op2 = lifter.ambil_operand(instr, 1);
    let mut call_stmt = StatementIr::new(
        instr.address, 
        OperasiIr::Call, 
        TipeOperand::Register(op_atomic.to_string()), 
        TipeOperand::None
    );
    call_stmt.operand_tambahan = vec![op1, op2];
    ops.push(call_stmt);
}

pub fn proses_trap(instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    ops.push(StatementIr::new(instr.address, OperasiIr::Unknown, TipeOperand::Immediate(0xCC), TipeOperand::None));
}

pub fn proses_generic_unknown(lifter: &IrLifter, instr: &InstructionNormalized, ops: &mut Vec<StatementIr>) {
    let op1 = lifter.ambil_operand(instr, 0);
    let op2 = lifter.ambil_operand(instr, 1);
    warn!("Instruksi tidak dikenal dilift sebagai Unknown: {}", instr.mnemonic);
    ops.push(StatementIr::new(instr.address, OperasiIr::Unknown, op1, op2));
}