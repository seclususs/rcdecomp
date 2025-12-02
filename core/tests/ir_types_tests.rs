use rcdecomp_core::ir::types::{
    StatementIr, OperasiIr, TipeOperand, TipeDataIr, OrderedFloat
};
use std::f64;

#[test]
fn test_statement_builder_pattern() {
    let addr = 0x1000;
    let op1 = TipeOperand::Register("rax".to_string());
    let op2 = TipeOperand::Immediate(42);
    let stmt = StatementIr::new(addr, OperasiIr::Mov, op1.clone(), op2.clone());
    assert_eq!(stmt.address_asal, addr);
    assert_eq!(stmt.operation_code, OperasiIr::Mov);
    assert_eq!(stmt.operand_satu, op1);
    assert_eq!(stmt.operand_dua, op2);
    assert_eq!(stmt.tipe_hasil, TipeDataIr::Unknown, "Default tipe hasil harus Unknown");
    assert!(stmt.operand_tambahan.is_empty(), "Default operand tambahan harus kosong");
    let typed_stmt = stmt.with_type(TipeDataIr::I64);
    assert_eq!(typed_stmt.tipe_hasil, TipeDataIr::I64, "Method with_type harus mengubah field tipe_hasil");
}

#[test]
fn test_nested_operands_construction() {
    let reg_a = TipeOperand::Register("rax".to_string());
    let reg_b = TipeOperand::Register("rbx".to_string());
    let imm_8 = TipeOperand::Immediate(8);
    let inner_expr = TipeOperand::Expression {
        operasi: OperasiIr::Add,
        operand_kiri: Box::new(reg_a),
        operand_kanan: Box::new(reg_b),
    };
    let outer_expr = TipeOperand::Expression {
        operasi: OperasiIr::Imul,
        operand_kiri: Box::new(inner_expr.clone()),
        operand_kanan: Box::new(imm_8.clone()),
    };
    if let TipeOperand::Expression { operasi, operand_kiri, operand_kanan } = outer_expr {
        assert_eq!(operasi, OperasiIr::Imul);
        assert_eq!(*operand_kanan, imm_8);
        if let TipeOperand::Expression { operasi: inner_op, operand_kiri: inner_l, operand_kanan: inner_r } = *operand_kiri {
            assert_eq!(inner_op, OperasiIr::Add);
            assert_eq!(*inner_l, TipeOperand::Register("rax".to_string()));
            assert_eq!(*inner_r, TipeOperand::Register("rbx".to_string()));
        } else {
            panic!("Struktur operand kiri salah");
        }
    } else {
        panic!("Struktur operand luar salah");
    }
}

#[test]
fn test_ordered_float_equality() {
    let f1 = OrderedFloat(10.5);
    let f2 = OrderedFloat(10.5);
    let f3 = OrderedFloat(20.0);
    assert_eq!(f1, f2, "Float dengan nilai sama harus equal");
    assert_ne!(f1, f3, "Float beda nilai harus not equal");
    let nan1 = OrderedFloat(f64::NAN);
    let nan2 = OrderedFloat(f64::NAN);
    assert_eq!(nan1, nan2, "OrderedFloat NaN harus equal dengan sesama NaN (bitwise check)");
}

#[test]
fn test_ordered_float_ordering() {
    let val = OrderedFloat(100.0);
    let nan = OrderedFloat(f64::NAN);
    assert!(nan > val, "NaN harus dianggap lebih besar dari regular number (berdasarkan implementasi Ord)");
    let mut vec = vec![OrderedFloat(5.0), OrderedFloat(f64::NAN), OrderedFloat(1.0)];
    vec.sort();
    assert_eq!(vec[0].0, 1.0);
    assert_eq!(vec[1].0, 5.0);
    assert!(vec[2].0.is_nan());
}

#[test]
fn test_operand_equality() {
    let reg1 = TipeOperand::Register("rax".to_string());
    let reg2 = TipeOperand::Register("rax".to_string());
    let reg3 = TipeOperand::Register("rbx".to_string());
    assert_eq!(reg1, reg2);
    assert_ne!(reg1, reg3);
    let mem1 = TipeOperand::MemoryRef { base: "rsp".into(), offset: 8 };
    let mem2 = TipeOperand::MemoryRef { base: "rsp".into(), offset: 8 };
    let mem3 = TipeOperand::MemoryRef { base: "rsp".into(), offset: 16 };
    assert_eq!(mem1, mem2);
    assert_ne!(mem1, mem3);
}

#[test]
fn test_convert_string_representation() {
    let op1 = TipeOperand::Register("rax".to_string());
    let op2 = TipeOperand::Immediate(12345);
    let stmt = StatementIr::new(0x401000, OperasiIr::Add, op1, op2);
    let output = stmt.convert_ke_string();
    assert!(output.contains("Addr: 0x401000"), "Output harus memuat alamat hex");
    assert!(output.contains("Op: Add"), "Output harus memuat nama operasi");
    assert!(output.contains("Register(\"rax\")"), "Output harus memuat operand 1");
    assert!(output.contains("Immediate(12345)"), "Output harus memuat operand 2");
}

#[test]
fn test_vector_lane_operand() {
    let base_vec = TipeOperand::Register("xmm0".to_string());
    let lane = TipeOperand::VectorLane {
        operand: Box::new(base_vec.clone()),
        lane_index: 3
    };
    if let TipeOperand::VectorLane { operand, lane_index } = lane {
        assert_eq!(*operand, base_vec);
        assert_eq!(lane_index, 3);
    } else {
        panic!("Gagal match VectorLane");
    }
}