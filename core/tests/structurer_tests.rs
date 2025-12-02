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

fn create_body_block(id: u64, target: Option<u64>) -> BasicBlock {
    let mut block = BasicBlock::new(id);
    block.instruksi_list.push(create_stmt(id, OperasiIr::Mov, reg("ecx"), imm(1)));
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

#[test]
fn test_pattern_detection_if_else() {
    let mut cfg = ControlFlowGraph::inisialisasi_graph_kosong();
    cfg.entry_point = 1;
    cfg.blocks.insert(1, create_branch_block(1, 2, 3, OperasiIr::Jg));
    cfg.blocks.insert(2, create_body_block(2, Some(4)));
    cfg.blocks.insert(3, create_body_block(3, Some(4)));
    cfg.blocks.insert(4, create_body_block(4, None));
    link_predecessors(&mut cfg);
    let mut structurer = ControlFlowStructurer::new();
    let ast = structurer.bangun_tree_struktur(&mut cfg);
    if let NodeAst::Sequence(nodes) = ast {
        let if_node = &nodes[0];
        match if_node {
            NodeAst::IfElse { kondisi, branch_true, branch_false } => {
                assert_eq!(kondisi, "eax > ebx", "Kondisi harus terekonstruksi dengan benar (JG -> >)");
                assert!(matches!(**branch_true, NodeAst::Sequence(_) | NodeAst::Block(_)), "Branch True harus berisi kode");
                assert!(branch_false.is_some(), "Branch False harus ada (Else block)");
            },
            _ => panic!("Expected IfElse node, got {:?}", if_node)
        }
    } else {
        panic!("Top level AST harus Sequence");
    }
}

#[test]
fn test_pattern_detection_loop() {
    let mut cfg = ControlFlowGraph::inisialisasi_graph_kosong();
    cfg.entry_point = 1;
    cfg.blocks.insert(1, create_body_block(1, Some(2)));
    cfg.blocks.insert(2, create_branch_block(2, 3, 4, OperasiIr::Jle));
    cfg.blocks.insert(3, create_body_block(3, Some(2)));
    cfg.blocks.insert(4, create_body_block(4, None));
    link_predecessors(&mut cfg);
    let mut structurer = ControlFlowStructurer::new();
    let ast = structurer.bangun_tree_struktur(&mut cfg);
    if let NodeAst::Sequence(nodes) = ast {
        let loop_node = nodes.iter().find(|n| matches!(n, NodeAst::WhileLoop { .. }));
        assert!(loop_node.is_some(), "Harus mendeteksi WhileLoop");
        if let NodeAst::WhileLoop { kondisi, body, is_do_while } = loop_node.unwrap() {
            assert_eq!(kondisi, "eax <= ebx", "Kondisi loop harus 'eax <= ebx' (JLE)");
            assert!(!is_do_while, "Harus dideteksi sebagai While standar (bukan Do-While)");
            if let NodeAst::Sequence(body_nodes) = &**body {
                assert!(!body_nodes.is_empty());
            }
        }
    } else {
        panic!("Top level AST harus Sequence");
    }
}

#[test]
fn test_complex_nesting_loop_inside_if() {
    let mut cfg = ControlFlowGraph::inisialisasi_graph_kosong();
    cfg.entry_point = 1;
    cfg.blocks.insert(1, create_branch_block(1, 2, 5, OperasiIr::Je));
    cfg.blocks.insert(2, create_body_block(2, Some(3)));
    cfg.blocks.insert(3, create_branch_block(3, 4, 5, OperasiIr::Jl));
    cfg.blocks.insert(4, create_body_block(4, Some(3)));
    cfg.blocks.insert(5, create_body_block(5, None));
    link_predecessors(&mut cfg);
    let mut structurer = ControlFlowStructurer::new();
    let ast = structurer.bangun_tree_struktur(&mut cfg);
    if let NodeAst::Sequence(nodes) = ast {
        let if_node = &nodes[0];
        if let NodeAst::IfElse { branch_true, .. } = if_node {
            let true_ast = &**branch_true;
            let contains_loop = match true_ast {
                NodeAst::Sequence(inner_nodes) => inner_nodes.iter().any(|n| matches!(n, NodeAst::WhileLoop { .. })),
                NodeAst::WhileLoop { .. } => true,
                _ => false
            };
            assert!(contains_loop, "Branch True dari If harus mengandung WhileLoop (Nested Structure)");
        } else {
            panic!("Node pertama harus IfElse");
        }
    } else {
        panic!("Top level AST harus Sequence");
    }
}