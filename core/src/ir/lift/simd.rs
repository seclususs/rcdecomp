use crate::disasm::instruction::InstructionNormalized;
use crate::ir::types::{StatementIr, TipeOperand, OperasiIr};
use super::IrLifter;

pub fn cek_is_simd_instruction(mnemonic: &str) -> bool {
    mnemonic.starts_with('v') ||
    mnemonic.starts_with('p') ||
    mnemonic.ends_with("ps") || mnemonic.ends_with("pd") ||
    mnemonic.ends_with("ss") || mnemonic.ends_with("sd") ||
    mnemonic.contains("xmm") || mnemonic.contains("ymm") || mnemonic.contains("zmm") ||
    mnemonic == "xorps" || mnemonic == "xorpd" ||
    mnemonic == "movaps" || mnemonic == "movups" ||
    mnemonic == "movd" || mnemonic == "movq" ||
    mnemonic.ends_with("dq") || mnemonic.ends_with("bw") || mnemonic.ends_with("vl")
}

pub fn proses_simd_to_intrinsic(
    lifter: &IrLifter, 
    instr: &InstructionNormalized, 
    mnemonic: &str, 
    ops: &mut Vec<StatementIr>
) {
    let is_avx512 = instr.op_str.contains("zmm");
    let is_avx2 = instr.op_str.contains("ymm");
    let prefix_intrinsic = if is_avx512 {
        "_mm512"
    } else if is_avx2 {
        "_mm256"
    } else {
        "_mm"
    };
    let base_name = mnemonic.strip_prefix('v').unwrap_or(mnemonic);
    let operation_suffix = match base_name {
        "addps" => "_add_ps",
        "addpd" => "_add_pd",
        "subps" => "_sub_ps",
        "mulps" => "_mul_ps",
        "divps" => "_div_ps",
        "paddb" | "addb" => "_add_epi8",
        "paddw" | "addw" => "_add_epi16",
        "paddd" | "addd" => "_add_epi32",
        "paddq" | "addq" => "_add_epi64",
        "xorps" => "_xor_ps",
        "xorpd" => "_xor_pd",
        "pxor"  | "xor" => "_xor_si512",
        "andps" => "_and_ps",
        "orps"  => "_or_ps",
        "maxps" => "_max_ps",
        "minps" => "_min_ps",
        "sqrtps"=> "_sqrt_ps",
        "movaps"=> "_store_ps",
        "movups"=> "_storeu_ps",
        "movdqa"=> "_store_si512",
        "movdqu"=> "_storeu_si512",
        "fmadd132ps" | "fmadd213ps" | "fmadd231ps" => "_fmadd_ps",
        _ => {
            "__generic"
        }
    };
    let final_name = if operation_suffix == "__generic" {
        format!("{}_{}", prefix_intrinsic, base_name)
    } else {
        format!("{}{}", prefix_intrinsic, operation_suffix)
    };
    let dest = lifter.ambil_operand(instr, 0);
    let mut args = Vec::new();
    if instr.op_str.contains("{k") {
        args.push(TipeOperand::Register("mask_k_reg".to_string()));
    }
    if dest != TipeOperand::None { args.push(dest.clone()); }
    let src1 = lifter.ambil_operand(instr, 1);
    if src1 != TipeOperand::None { args.push(src1); }
    let src2 = lifter.ambil_operand(instr, 2);
    if src2 != TipeOperand::None { args.push(src2); }
    let src3 = lifter.ambil_operand(instr, 3);
    if src3 != TipeOperand::None { args.push(src3); }
    let call_target = TipeOperand::Register(final_name);
    let mut call_stmt = StatementIr::new(instr.address, OperasiIr::Call, call_target, TipeOperand::None);
    call_stmt.operand_tambahan = args;
    if is_avx512 {

    }
    ops.push(call_stmt);
}