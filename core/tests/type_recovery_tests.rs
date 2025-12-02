use std::collections::HashMap;
use rcdecomp_core::ir::types::{StatementIr, OperasiIr, TipeOperand};
use rcdecomp_core::analysis::recovery::types::{
    TypeSystem, TipePrimitif, SignatureFungsi
};

fn create_stmt(addr: u64, op: OperasiIr, op1: TipeOperand, op2: TipeOperand) -> StatementIr {
    StatementIr::new(addr, op, op1, op2)
}

fn reg(name: &str) -> TipeOperand {
    TipeOperand::Register(name.to_string())
}

fn mem(base: &str, offset: i64) -> TipeOperand {
    TipeOperand::MemoryRef { base: base.to_string(), offset }
}

fn stmt_call(addr: u64, target: u64, args: Vec<TipeOperand>) -> StatementIr {
    let mut stmt = StatementIr::new(
        addr, 
        OperasiIr::Call, 
        TipeOperand::Immediate(target as i64), 
        TipeOperand::None
    );
    stmt.operand_tambahan = args;
    stmt
}

#[test]
fn test_type_unification_conflict_resolution() {
    let mut sys = TypeSystem::new();
    let addr_func_int = 0x1000;
    let addr_func_float = 0x2000;
    sys.global_signatures.insert(addr_func_int, SignatureFungsi {
        return_type: TipePrimitif::Void,
        arg_types: vec![TipePrimitif::Integer(4)],
    });
    sys.global_signatures.insert(addr_func_float, SignatureFungsi {
        return_type: TipePrimitif::Void,
        arg_types: vec![TipePrimitif::Float(4)],
    });
    let mut stmts = Vec::new();
    stmts.push(stmt_call(0x100, addr_func_int, vec![reg("var_a")]));
    stmts.push(stmt_call(0x104, addr_func_float, vec![reg("var_b")]));
    stmts.push(stmt_call(0x108, addr_func_int, vec![reg("var_c")]));
    stmts.push(stmt_call(0x10C, addr_func_float, vec![reg("var_c")]));
    let mut functions = HashMap::new();
    functions.insert(0x100, stmts);
    sys.analisis_interprosedural(&functions);
    let type_a = sys.variable_types.get("var_a").expect("var_a harus punya tipe");
    assert_eq!(*type_a, TipePrimitif::Integer(4));
    let type_b = sys.variable_types.get("var_b").expect("var_b harus punya tipe");
    assert_eq!(*type_b, TipePrimitif::Float(4));
    let type_c = sys.variable_types.get("var_c").expect("var_c harus punya tipe");
    if let TipePrimitif::Union(members) = type_c {
        assert!(members.contains(&TipePrimitif::Integer(4)), "Union harus berisi Int");
        assert!(members.contains(&TipePrimitif::Float(4)), "Union harus berisi Float");
    } else {
        panic!("var_c harus berupa Union, tapi dapat: {:?}", type_c);
    }
}

#[test]
fn test_struct_reconstruction_from_fields() {
    let mut sys = TypeSystem::new();
    let mut stmts = Vec::new();
    stmts.push(create_stmt(0x100, OperasiIr::Mov, reg("temp1"), mem("base_struct", 0)));
    stmts.push(create_stmt(0x104, OperasiIr::Mov, reg("temp2"), mem("base_struct", 8)));
    let mut functions = HashMap::new();
    functions.insert(0x100, stmts);
    sys.global_signatures.insert(0x999, SignatureFungsi {
        return_type: TipePrimitif::Void,
        arg_types: vec![TipePrimitif::Integer(4)],
    });
    functions.get_mut(&0x100).unwrap().push(stmt_call(0x108, 0x999, vec![reg("temp1")]));
    functions.get_mut(&0x100).unwrap().push(stmt_call(0x10C, 0x999, vec![reg("temp2")]));
    sys.analisis_interprosedural(&functions);
    let type_base = sys.variable_types.get("base_struct").expect("base_struct harus terdaftar");
    let struct_name = if let TipePrimitif::Pointer(inner) = type_base {
        if let TipePrimitif::Struct(name) = &**inner {
            name.clone()
        } else {
            panic!("base_struct harus pointer ke struct");
        }
    } else {
        panic!("base_struct harus pointer");
    };
    let layout = sys.struct_definitions.get(&struct_name).expect("Definisi struct harus ada");
    assert!(layout.fields.contains_key(&0), "Harus ada field di offset 0");
    assert!(layout.fields.contains_key(&8), "Harus ada field di offset 8");
    assert_eq!(*layout.fields.get(&0).unwrap(), TipePrimitif::Integer(4));
    assert_eq!(*layout.fields.get(&8).unwrap(), TipePrimitif::Integer(4));
}

#[test]
fn test_recursive_type_handling() {
    let mut sys = TypeSystem::new();
    let mut stmts = Vec::new();
    stmts.push(create_stmt(
        0x100, 
        OperasiIr::Mov, 
        mem("ptr_node", 0), 
        reg("ptr_node")
    ));
    let mut functions = HashMap::new();
    functions.insert(0x100, stmts);
    sys.analisis_interprosedural(&functions);
    let type_ptr = sys.variable_types.get("ptr_node").expect("ptr_node missing");
    let struct_name = if let TipePrimitif::Pointer(inner) = type_ptr {
        if let TipePrimitif::Struct(name) = &**inner {
            name.clone()
        } else {
            panic!("ptr_node bukan pointer struct");
        }
    } else {
        panic!("ptr_node bukan pointer");
    };
    let layout = sys.struct_definitions.get(&struct_name).expect("Struct def missing");
    assert!(layout.is_recursive, "Struct harus terdeteksi sebagai rekursif");
    let field_type = layout.fields.get(&0).expect("Field 0 missing");
    assert_eq!(field_type, type_ptr, "Field 0 harus bertipe pointer ke struct itu sendiri");
}