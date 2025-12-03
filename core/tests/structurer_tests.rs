use std::collections::HashMap;
use rcdecomp_core::analysis::graph::cfg::{ControlFlowGraph, BasicBlock};
use rcdecomp_core::analysis::recovery::ast::{ControlFlowStructurer, NodeAst};
use rcdecomp_core::ir::types::{StatementIr, OperasiIr, TipeOperand};

fn reg(n: &str) -> TipeOperand {
    TipeOperand::Register(n.to_string())
}

fn imm(v: i64) -> TipeOperand {
    TipeOperand::Immediate(v)
}

fn create_stmt(addr: u64, op: OperasiIr, op1: TipeOperand, op2: TipeOperand) -> StatementIr {
    StatementIr::new(addr, op, op1, op2)
}

fn create_branch_block(id: u64, target_true: u64, target_false: u64, op_jmp: OperasiIr) -> BasicBlock {
    let mut block = BasicBlock::new(id);
    block.instruksi_list.push(create_stmt(id, OperasiIr::Cmp, reg("eax"), reg("ebx")));
    block.instruksi_list.push(create_stmt(id + 4, op_jmp, imm(target_true as i64), TipeOperand::None));
    block.successors.push(target_true);
    block.successors.push(target_false);
    block
}

fn create_body_block(id: u64, target: Option<u64>, dest_reg: &str, val: i64) -> BasicBlock {
    let mut block = BasicBlock::new(id);
    block.instruksi_list.push(create_stmt(id, OperasiIr::Mov, reg(dest_reg), imm(val)));
    if let Some(t) = target {
        block.instruksi_list.push(create_stmt(id + 4, OperasiIr::Jmp, imm(t as i64), TipeOperand::None));
        block.successors.push(t);
    }
    block
}

fn link_predecessors(cfg: &mut ControlFlowGraph) {
    let mut preds = HashMap::new();
    for (src, block) in &cfg.blocks {
        for &dst in &block.successors {
            preds.entry(dst).or_insert(Vec::new()).push(*src);
        }
    }
    for (dst, src_list) in preds {
        if let Some(block) = cfg.blocks.get_mut(&dst) {
            block.predecessors = src_list;
        }
    }
}

fn find_node_top_level<'a, F>(ast: &'a NodeAst, matcher: F) -> Option<&'a NodeAst>
where F: Fn(&NodeAst) -> bool {
    match ast {
        NodeAst::Sequence(nodes) => nodes.iter().find(|n| matcher(n)),
        n if matcher(n) => Some(n),
        _ => None
    }
}

fn contains_node_recursive<F>(ast: &NodeAst, matcher: &F) -> bool 
where F: Fn(&NodeAst) -> bool {
    if matcher(ast) {
        return true;
    }
    match ast {
        NodeAst::Sequence(nodes) => nodes.iter().any(|n| contains_node_recursive(n, matcher)),
        NodeAst::IfElse { branch_true, branch_false, .. } => {
            contains_node_recursive(branch_true, matcher) || 
            branch_false.as_ref().map_or(false, |n| contains_node_recursive(n, matcher))
        },
        NodeAst::WhileLoop { body, .. } => contains_node_recursive(body, matcher),
        NodeAst::Switch { kasus, default, .. } => {
            kasus.iter().any(|(_, n)| contains_node_recursive(n, matcher)) ||
            default.as_ref().map_or(false, |n| contains_node_recursive(n, matcher))
        },
        NodeAst::TryCatch { block_try, handler_catch, .. } => {
            contains_node_recursive(block_try, matcher) || contains_node_recursive(handler_catch, matcher)
        },
        _ => false,
    }
}

#[test]
fn test_pattern_detection_if_else() {
    let mut cfg = ControlFlowGraph::inisialisasi_graph_kosong();
    cfg.entry_point = 1;
    cfg.blocks.insert(1, create_branch_block(1, 2, 3, OperasiIr::Jg));
    cfg.blocks.insert(2, create_body_block(2, Some(4), "ecx", 100));
    cfg.blocks.insert(3, create_body_block(3, Some(4), "edx", 200));
    cfg.blocks.insert(4, create_body_block(4, None, "eax", 0));
    link_predecessors(&mut cfg);
    let mut structurer = ControlFlowStructurer::new();
    let ast = structurer.bangun_tree_struktur(&mut cfg);
    let if_node = find_node_top_level(&ast, |n| matches!(n, NodeAst::IfElse { .. }));
    if if_node.is_none() {
        println!("DEBUG: AST Result for IfElse Test:\n{:#?}", ast);
        panic!("Gagal mendeteksi struktur IfElse dalam AST");
    }
    match if_node.unwrap() {
        NodeAst::IfElse { kondisi, branch_true, branch_false } => {
            assert_eq!(kondisi, "eax > ebx", "Kondisi harus terekonstruksi dengan benar (JG -> >)");
            let true_not_empty = !matches!(**branch_true, NodeAst::Empty);
            assert!(true_not_empty, "Branch True tidak boleh Empty");
            if branch_false.is_none() {
                 println!("DEBUG: AST Result (Missing Else):\n{:#?}", ast);
            }
            assert!(branch_false.is_some(), "Branch False harus ada (Else block) karena Block 3 berisi instruksi");
        },
        _ => unreachable!()
    }
}

#[test]
fn test_pattern_detection_loop() {
    let mut cfg = ControlFlowGraph::inisialisasi_graph_kosong();
    cfg.entry_point = 1;
    cfg.blocks.insert(1, create_body_block(1, Some(2), "ecx", 1));
    cfg.blocks.insert(2, create_branch_block(2, 3, 4, OperasiIr::Jle));
    cfg.blocks.insert(3, create_body_block(3, Some(2), "ecx", 2));
    cfg.blocks.insert(4, create_body_block(4, None, "ecx", 3));
    link_predecessors(&mut cfg);
    let mut structurer = ControlFlowStructurer::new();
    let ast = structurer.bangun_tree_struktur(&mut cfg);
    let loop_node = find_node_top_level(&ast, |n| matches!(n, NodeAst::WhileLoop { .. }));
    if loop_node.is_none() {
        println!("DEBUG: AST Result for Loop Test:\n{:#?}", ast);
    }
    assert!(loop_node.is_some(), "Harus mendeteksi WhileLoop");
    if let NodeAst::WhileLoop { kondisi, body, is_do_while } = loop_node.unwrap() {
        assert_eq!(kondisi, "eax <= ebx", "Kondisi loop harus 'eax <= ebx' (JLE)");
        assert!(!is_do_while, "Harus dideteksi sebagai While standar (bukan Do-While)");
        
        let body_has_content = !matches!(**body, NodeAst::Empty);
        assert!(body_has_content, "Body loop tidak boleh kosong");
    }
}

#[test]
fn test_complex_nesting_loop_inside_if() {
    let mut cfg = ControlFlowGraph::inisialisasi_graph_kosong();
    cfg.entry_point = 1;
    cfg.blocks.insert(1, create_branch_block(1, 2, 5, OperasiIr::Je));
    cfg.blocks.insert(2, create_body_block(2, Some(3), "ecx", 10));
    cfg.blocks.insert(3, create_branch_block(3, 4, 5, OperasiIr::Jl));
    cfg.blocks.insert(4, create_body_block(4, Some(3), "ecx", 20));
    cfg.blocks.insert(5, create_body_block(5, None, "eax", 0));
    link_predecessors(&mut cfg);
    let mut structurer = ControlFlowStructurer::new();
    let ast = structurer.bangun_tree_struktur(&mut cfg);
    let if_node = find_node_top_level(&ast, |n| matches!(n, NodeAst::IfElse { .. }));
    if if_node.is_none() {
        println!("DEBUG: AST Result for Nested Test:\n{:#?}", ast);
        panic!("Node IfElse top-level tidak ditemukan");
    }
    if let NodeAst::IfElse { branch_true, .. } = if_node.unwrap() {
        let contains_loop = contains_node_recursive(branch_true, &|n| matches!(n, NodeAst::WhileLoop { .. }));
        if !contains_loop {
            println!("DEBUG: Branch True Content does NOT contain Loop:\n{:#?}", branch_true);
        }
        assert!(contains_loop, "Branch True dari If harus mengandung WhileLoop (Nested Structure)");
    } else {
        panic!("Struktur tidak sesuai");
    }
}