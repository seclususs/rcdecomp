use crate::disasm::instruction::InstructionNormalized;
use crate::ir::types::{StatementIr, TipeOperand, OperasiIr, TipeDataIr};
use super::IrLifter;
use log::debug;

pub fn proses_system_instruction(
    lifter: &IrLifter, 
    instr: &InstructionNormalized, 
    mnemonic: &str, 
    ops: &mut Vec<StatementIr>
) {
    let clean_mnemonic = mnemonic.replace("lock ", ""); 
    let is_lock = mnemonic.contains("lock");
    match clean_mnemonic.as_str() {
        "syscall" | "sysenter" | "svc" | "sc" => {
            let target = format!("__kernel_{}", clean_mnemonic);
            let mut call = StatementIr::new(instr.address, OperasiIr::Syscall, TipeOperand::Register(target), TipeOperand::None);
            call.operand_tambahan = vec![
                TipeOperand::Register("rax".to_string()),
                TipeOperand::Register("rdi".to_string()),
                TipeOperand::Register("rsi".to_string()),
                TipeOperand::Register("rdx".to_string()),
                TipeOperand::Register("r10".to_string()),
                TipeOperand::Register("r8".to_string()),
                TipeOperand::Register("r9".to_string()),
            ];
            ops.push(call);
            ops.push(StatementIr::new(instr.address, OperasiIr::Mov, TipeOperand::Register("rax".to_string()), TipeOperand::Register("syscall_result".to_string())));
        },
        "xchg" => {
            let op1 = lifter.ambil_operand(instr, 0);
            let op2 = lifter.ambil_operand(instr, 1);
            let is_mem = matches!(op1, TipeOperand::Memory(_) | TipeOperand::MemoryRef{..}) || 
                         matches!(op2, TipeOperand::Memory(_) | TipeOperand::MemoryRef{..});
            let op_code = if is_mem || is_lock { OperasiIr::AtomicXchg } else { OperasiIr::Mov };
            if op_code == OperasiIr::AtomicXchg {
                ops.push(StatementIr::new(instr.address, OperasiIr::AtomicXchg, op1, op2));
            } else {
                let temp = TipeOperand::Register("temp_swap".to_string());
                ops.push(StatementIr::new(instr.address, OperasiIr::Mov, temp.clone(), op1.clone()));
                ops.push(StatementIr::new(instr.address, OperasiIr::Mov, op1, op2.clone()));
                ops.push(StatementIr::new(instr.address, OperasiIr::Mov, op2, temp));
            }
        },
        "cmpxchg" => {
            let dest = lifter.ambil_operand(instr, 0);
            let src = lifter.ambil_operand(instr, 1);
            let accumulator = TipeOperand::Register("rax".to_string());
            
            let mut cas_op = StatementIr::new(
                instr.address, 
                OperasiIr::AtomicCas, 
                dest, 
                src
            );
            cas_op.operand_tambahan.push(accumulator);
            ops.push(cas_op);
            ops.push(StatementIr::new(instr.address, OperasiIr::Unknown, TipeOperand::Register("eflags".to_string()), TipeOperand::None));
        },
        "xadd" => {
             let dest = lifter.ambil_operand(instr, 0);
             let src = lifter.ambil_operand(instr, 1);
             ops.push(StatementIr::new(instr.address, OperasiIr::AtomicAdd, dest, src)); 
        },
        "lfence" | "sfence" | "mfence" => {
             ops.push(StatementIr::new(instr.address, OperasiIr::Fence, TipeOperand::None, TipeOperand::None));
        },
        "cpuid" => {
            let mut call = StatementIr::new(instr.address, OperasiIr::Intrinsic("__cpuid".to_string()), TipeOperand::None, TipeOperand::None);
            call.operand_tambahan = vec![TipeOperand::Register("eax".to_string()), TipeOperand::Register("ecx".to_string())];
            ops.push(call);
        },
        "popcnt" | "lzcnt" | "tzcnt" => {
             let dest = lifter.ambil_operand(instr, 0);
             let src = lifter.ambil_operand(instr, 1);
             let op = match clean_mnemonic.as_str() {
                 "popcnt" => OperasiIr::Popcnt,
                 "lzcnt" => OperasiIr::Lzcnt,
                 "tzcnt" => OperasiIr::Tzcnt,
                 _ => OperasiIr::Unknown
             };
             ops.push(StatementIr::new(instr.address, op, dest, src).with_type(TipeDataIr::I64));
        }
        _ => {
            debug!("System instruction generic: {}", clean_mnemonic);
            ops.push(StatementIr::new(instr.address, OperasiIr::Unknown, TipeOperand::None, TipeOperand::None));
        }
    }
}