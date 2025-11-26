use crate::disasm::instruction::InstructionNormalized;
use crate::ir::types::{StatementIr, TipeOperand, OperasiIr};
use super::IrLifter;
use log::debug;

pub fn proses_system_instruction(
    lifter: &IrLifter, 
    instr: &InstructionNormalized, 
    mnemonic: &str, 
    ops: &mut Vec<StatementIr>
) {
    debug!("Lifting System/Privileged: {} @ 0x{:x}", mnemonic, instr.address);
    match mnemonic {
        "syscall" | "sysenter" | "svc" | "sc" => {
            let target = format!("__kernel_{}", mnemonic);
            let mut call = StatementIr::new(instr.address, OperasiIr::Call, TipeOperand::Register(target), TipeOperand::None);
            call.operand_tambahan = vec![
                TipeOperand::Register("rax".to_string()),
                TipeOperand::Register("rdi".to_string()),
                TipeOperand::Register("rsi".to_string()),
                TipeOperand::Register("rdx".to_string()),
            ];
            ops.push(call);
            ops.push(StatementIr::new(instr.address, OperasiIr::Unknown, TipeOperand::Register("rax".to_string()), TipeOperand::None));
        },
        "cpuid" => {
            let mut call = StatementIr::new(instr.address, OperasiIr::Call, TipeOperand::Register("__asm_cpuid".to_string()), TipeOperand::None);
            call.operand_tambahan = vec![TipeOperand::Register("eax".to_string()), TipeOperand::Register("ecx".to_string())];
            ops.push(call);
            for r in ["eax", "ebx", "ecx", "edx"] {
                ops.push(StatementIr::new(instr.address, OperasiIr::Unknown, TipeOperand::Register(r.to_string()), TipeOperand::None));
            }
        },
        "rdtsc" | "rdtscp" => {
            ops.push(StatementIr::new(instr.address, OperasiIr::Call, TipeOperand::Register("__asm_rdtsc".to_string()), TipeOperand::None));
            ops.push(StatementIr::new(instr.address, OperasiIr::Unknown, TipeOperand::Register("eax".to_string()), TipeOperand::None));
            ops.push(StatementIr::new(instr.address, OperasiIr::Unknown, TipeOperand::Register("edx".to_string()), TipeOperand::None));
        },
        "andn" => {
            let dest = lifter.ambil_operand(instr, 0);
            let src1 = lifter.ambil_operand(instr, 1);
            let src2 = lifter.ambil_operand(instr, 2);
            let not_s1 = Box::new(TipeOperand::Expression { operasi: OperasiIr::Xor, operand_kiri: Box::new(src1), operand_kanan: Box::new(TipeOperand::Immediate(-1)) });
            ops.push(StatementIr::new(instr.address, OperasiIr::Mov, dest, TipeOperand::Expression { operasi: OperasiIr::And, operand_kiri: not_s1, operand_kanan: Box::new(src2) }));
        },
        "popcnt" | "lzcnt" | "tzcnt" => {
            let dest = lifter.ambil_operand(instr, 0);
            let src = lifter.ambil_operand(instr, 1);
            let intr = format!("__builtin_{}", mnemonic);
            let mut call = StatementIr::new(instr.address, OperasiIr::Call, TipeOperand::Register(intr), TipeOperand::None);
            call.operand_tambahan.push(src);
            ops.push(call);
            ops.push(StatementIr::new(instr.address, OperasiIr::Unknown, dest, TipeOperand::None));
        },
        _ => {
            let op1 = lifter.ambil_operand(instr, 0);
            let op2 = lifter.ambil_operand(instr, 1);
            ops.push(StatementIr::new(instr.address, OperasiIr::Unknown, op1, op2));
        }
    }
}