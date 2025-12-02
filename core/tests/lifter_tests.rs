use rcdecomp_core::ir::lift::IrLifter;
use rcdecomp_core::disasm::instruction::{InstructionNormalized, JenisOperandDisasm};
use rcdecomp_core::ir::types::{OperasiIr, TipeOperand, StatementIr};

fn create_mock_instruction(addr: u64, mnemonic: &str, operands: Vec<JenisOperandDisasm>) -> InstructionNormalized {
    let mut instr = InstructionNormalized::new(addr, mnemonic, "");
    instr.operands_detail = operands;
    instr
}

fn contains_op(stmts: &[StatementIr], op: OperasiIr) -> bool {
    stmts.iter().any(|s| s.operation_code == op)
}

fn find_stmt_by_op(stmts: &[StatementIr], op: OperasiIr) -> Option<&StatementIr> {
    stmts.iter().find(|s| s.operation_code == op)
}

#[test]
fn test_arithmetic_lifting_add() {
    let lifter = IrLifter::new();
    let operands = vec![
        JenisOperandDisasm::Register("rax".to_string()),
        JenisOperandDisasm::Register("rbx".to_string()),
    ];
    let instr = create_mock_instruction(0x1000, "add", operands);
    let ir = lifter.konversi_instruksi_ke_microcode(&instr);
    let add_stmt = find_stmt_by_op(&ir, OperasiIr::Add).expect("Harus ada operasi ADD");
    assert_eq!(add_stmt.operand_satu, TipeOperand::Register("rax".to_string()));
    if let TipeOperand::Expression { operasi, operand_kiri, operand_kanan } = &add_stmt.operand_dua {
        assert_eq!(*operasi, OperasiIr::Add);
        assert_eq!(**operand_kiri, TipeOperand::Register("rax".to_string()));
        assert_eq!(**operand_kanan, TipeOperand::Register("rbx".to_string()));
    } else {
        panic!("Operand kedua ADD harus berupa Expression");
    }
    assert!(ir.iter().any(|s| 
        s.operation_code == OperasiIr::Mov && 
        s.operand_satu == TipeOperand::Register("eflags_zf".to_string())
    ), "Harus ada update Zero Flag (ZF)");
    assert!(ir.iter().any(|s| 
        s.operation_code == OperasiIr::Mov && 
        s.operand_satu == TipeOperand::Register("eflags_cf".to_string())
    ), "Harus ada update Carry Flag (CF) untuk ADD");
}

#[test]
fn test_flow_lifting_call() {
    let lifter = IrLifter::new();
    let target_addr = 0x405000;
    let operands = vec![
        JenisOperandDisasm::Immediate(target_addr),
    ];
    let instr = create_mock_instruction(0x1000, "call", operands);
    let ir = lifter.konversi_instruksi_ke_microcode(&instr);
    let sub_rsp = find_stmt_by_op(&ir, OperasiIr::Sub).expect("Call harus decrement stack pointer");
    assert_eq!(sub_rsp.operand_satu, TipeOperand::Register("rsp".to_string()));
    if let TipeOperand::Immediate(val) = sub_rsp.operand_dua {
        assert_eq!(val, 8, "RSP harus dikurangi 8 byte (64-bit)");
    } else {
        panic!("Operand kedua SUB harus Immediate 8");
    }
    let call_stmt = find_stmt_by_op(&ir, OperasiIr::Call).expect("Harus ada instruksi CALL");
    assert_eq!(call_stmt.operand_satu, TipeOperand::Immediate(target_addr));
}

#[test]
fn test_flow_lifting_ret() {
    let lifter = IrLifter::new();
    let instr = create_mock_instruction(0x1000, "ret", vec![]);
    let ir = lifter.konversi_instruksi_ke_microcode(&instr);
    let add_rsp = find_stmt_by_op(&ir, OperasiIr::Add).expect("Ret harus increment stack pointer");
    assert_eq!(add_rsp.operand_satu, TipeOperand::Register("rsp".to_string()));
    assert_eq!(add_rsp.operand_dua, TipeOperand::Immediate(8));
    assert!(contains_op(&ir, OperasiIr::Ret));
}

#[test]
fn test_bitwise_lifting_masking() {
    let lifter = IrLifter::new();
    let operands = vec![
        JenisOperandDisasm::Register("rax".to_string()),
        JenisOperandDisasm::Register("cl".to_string()),
    ];
    let instr = create_mock_instruction(0x1000, "shl", operands);
    let ir = lifter.konversi_instruksi_ke_microcode(&instr);
    let shl_stmt = find_stmt_by_op(&ir, OperasiIr::Shl).expect("Harus ada operasi SHL");
    if let TipeOperand::Expression { operasi: _, operand_kiri: _, operand_kanan } = &shl_stmt.operand_dua {
        if let TipeOperand::Expression { operasi: inner_op, operand_kiri: inner_l, operand_kanan: inner_r } = &**operand_kanan {
             assert_eq!(*inner_op, OperasiIr::And, "Shift count harus di-AND");
             assert_eq!(**inner_l, TipeOperand::Register("cl".to_string()));
             assert_eq!(**inner_r, TipeOperand::Immediate(0x3F), "Masking harus 0x3F");
        } else {
             if let TipeOperand::Expression { operasi: shift_op, operand_kiri: _, operand_kanan: count_expr } = &shl_stmt.operand_dua {
                  assert_eq!(*shift_op, OperasiIr::Shl);
                  if let TipeOperand::Expression { operasi: mask_op, operand_kiri: _, operand_kanan: mask_val } = &**count_expr {
                      assert_eq!(*mask_op, OperasiIr::And);
                      assert_eq!(**mask_val, TipeOperand::Immediate(0x3F));
                  } else {
                      panic!("Logic masking count tidak ditemukan di operand kanan SHL");
                  }
             } else {
                 panic!("Struktur SHL tidak sesuai ekspektasi");
             }
        }
    }
}

#[test]
fn test_simd_lifting_intrinsic() {
    let lifter = IrLifter::new();
    let operands = vec![
        JenisOperandDisasm::Register("xmm0".to_string()),
        JenisOperandDisasm::Register("xmm1".to_string()),
    ];
    let instr = create_mock_instruction(0x1000, "addps", operands);
    let ir = lifter.konversi_instruksi_ke_microcode(&instr);
    let vec_add = find_stmt_by_op(&ir, OperasiIr::VecAdd).expect("addps harus dilift ke VecAdd");
    assert_eq!(vec_add.operand_satu, TipeOperand::Register("xmm0".to_string()));
    match vec_add.tipe_hasil {
        rcdecomp_core::ir::types::TipeDataIr::V128F32 | 
        rcdecomp_core::ir::types::TipeDataIr::V128 => {},
        _ => panic!("Tipe data hasil harus vektor (V128/V128F32), dapat: {:?}", vec_add.tipe_hasil)
    }
}

#[test]
fn test_system_lifting_cpuid() {
    let lifter = IrLifter::new();
    let instr = create_mock_instruction(0x1000, "cpuid", vec![]);
    let ir = lifter.konversi_instruksi_ke_microcode(&instr);
    let intrinsic_stmt = ir.iter().find(|s| match &s.operation_code {
        OperasiIr::Intrinsic(name) => name == "__cpuid",
        _ => false
    }).expect("CPUID harus dilift ke intrinsic __cpuid");
    let has_eax_arg = intrinsic_stmt.operand_tambahan.contains(&TipeOperand::Register("eax".to_string()));
    assert!(has_eax_arg, "CPUID harus mengambil eax sebagai input");
}