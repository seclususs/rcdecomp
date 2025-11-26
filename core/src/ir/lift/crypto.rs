use crate::disasm::instruction::InstructionNormalized;
use crate::ir::types::{StatementIr, TipeOperand, OperasiIr};
use super::IrLifter;

pub fn proses_crypto_instruction(
    lifter: &IrLifter, 
    instr: &InstructionNormalized, 
    mnemonic: &str, 
    ops: &mut Vec<StatementIr>
) {
    let intrinsic = match mnemonic {
        "aesenc" => "_mm_aesenc_si128",
        "aesdec" => "_mm_aesdec_si128",
        "aesenclast" => "_mm_aesenclast_si128",
        "aesdeclast" => "_mm_aesdeclast_si128",
        "sha1msg1" => "_mm_sha1msg1_epu128",
        "sha1msg2" => "_mm_sha1msg2_epu128",
        _ => mnemonic
    };
    let dest = lifter.ambil_operand(instr, 0);
    let src = lifter.ambil_operand(instr, 1);
    let mut call_stmt = StatementIr::new(
        instr.address,
        OperasiIr::Call,
        TipeOperand::Register(intrinsic.to_string()),
        TipeOperand::None
    );
    call_stmt.operand_tambahan = vec![dest.clone(), src];
    ops.push(call_stmt);
}