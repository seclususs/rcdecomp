use std::collections::HashMap;
use rcdecomp_core::analysis::graph::cfg::ControlFlowGraph;
use rcdecomp_core::ir::types::{StatementIr, OperasiIr, TipeOperand};

fn make_stmt(addr: u64, op: OperasiIr, op1: TipeOperand, op2: TipeOperand) -> StatementIr {
    StatementIr::new(addr, op, op1, op2)
}

fn reg(name: &str) -> TipeOperand {
    TipeOperand::Register(name.to_string())
}

fn imm(val: i64) -> TipeOperand {
    TipeOperand::Immediate(val)
}

#[test]
fn test_block_splitting_logic() {
    let mut stmts = Vec::new();
    stmts.push(make_stmt(0x100, OperasiIr::Mov, reg("rax"), imm(10)));
    stmts.push(make_stmt(0x104, OperasiIr::Cmp, reg("rax"), imm(0)));
    stmts.push(make_stmt(0x108, OperasiIr::Je, imm(0x114), TipeOperand::None));
    stmts.push(make_stmt(0x10C, OperasiIr::Mov, reg("rbx"), imm(1)));
    stmts.push(make_stmt(0x110, OperasiIr::Jmp, imm(0x118), TipeOperand::None));
    stmts.push(make_stmt(0x114, OperasiIr::Mov, reg("rbx"), imm(2)));
    stmts.push(make_stmt(0x118, OperasiIr::Ret, TipeOperand::None, TipeOperand::None));
    let jump_tables = HashMap::new();
    let cfg = ControlFlowGraph::bangun_execution_graph(stmts, &jump_tables);
    assert_eq!(cfg.blocks.len(), 4, "Harus ada 4 basic block");
    assert!(cfg.blocks.contains_key(&0x100));
    assert_eq!(cfg.blocks[&0x100].instruksi_list.len(), 3);
    assert!(cfg.blocks.contains_key(&0x10C));
    assert_eq!(cfg.blocks[&0x10C].instruksi_list.len(), 2);
    assert!(cfg.blocks.contains_key(&0x114));
    assert_eq!(cfg.blocks[&0x114].instruksi_list.len(), 1);
    assert!(cfg.blocks.contains_key(&0x118));
    assert_eq!(cfg.blocks[&0x118].instruksi_list.len(), 1);
}

#[test]
fn test_edge_connections() {
    let mut stmts = Vec::new();
    stmts.push(make_stmt(0x100, OperasiIr::Cmp, reg("rax"), imm(0)));
    stmts.push(make_stmt(0x104, OperasiIr::Jne, imm(0x300), TipeOperand::None));
    stmts.push(make_stmt(0x200, OperasiIr::Mov, reg("rax"), imm(1)));
    stmts.push(make_stmt(0x204, OperasiIr::Jmp, imm(0x300), TipeOperand::None));
    stmts.push(make_stmt(0x300, OperasiIr::Ret, TipeOperand::None, TipeOperand::None));
    let cfg = ControlFlowGraph::bangun_execution_graph(stmts, &HashMap::new());
    let block_a = &cfg.blocks[&0x100];
    assert_eq!(block_a.successors.len(), 2, "Block A harus punya 2 successor (Branch + Fallthrough)");
    assert!(block_a.successors.contains(&0x300), "Block A harus connect ke C (Branch)");
    assert!(block_a.successors.contains(&0x200), "Block A harus connect ke B (Fallthrough)");
    let block_b = &cfg.blocks[&0x200];
    assert_eq!(block_b.successors.len(), 1, "Block B harus punya 1 successor (Uncond Jump)");
    assert!(block_b.successors.contains(&0x300), "Block B harus connect ke C");
    let block_c = &cfg.blocks[&0x300];
    assert_eq!(block_c.predecessors.len(), 2, "Block C harus punya 2 predecessor");
    assert!(block_c.predecessors.contains(&0x100));
    assert!(block_c.predecessors.contains(&0x200));
}

#[test]
fn test_graph_manipulation_copy_and_redirect() {
    let mut stmts = Vec::new();
    stmts.push(make_stmt(0x100, OperasiIr::Jmp, imm(0x200), TipeOperand::None));
    stmts.push(make_stmt(0x200, OperasiIr::Jmp, imm(0x300), TipeOperand::None));
    stmts.push(make_stmt(0x300, OperasiIr::Ret, TipeOperand::None, TipeOperand::None));
    let mut cfg = ControlFlowGraph::bangun_execution_graph(stmts, &HashMap::new());
    assert!(cfg.blocks[&0x100].successors.contains(&0x200));
    assert!(cfg.blocks[&0x200].predecessors.contains(&0x100));
    let new_id = 0x999;
    cfg.buat_block_baru_dari_copy(0x200, new_id);
    assert!(cfg.blocks.contains_key(&new_id), "Block baru harus terbentuk");
    let new_block = &cfg.blocks[&new_id];
    assert_eq!(new_block.instruksi_list.len(), 1);
    assert_eq!(new_block.instruksi_list[0].operation_code, OperasiIr::Jmp);
    assert!(new_block.successors.contains(&0x300), "Block copy harus inherit successor B");
    assert!(cfg.blocks[&0x300].predecessors.contains(&new_id));
    cfg.redirect_edge(0x100, 0x200, new_id);
    let block_a = &cfg.blocks[&0x100];
    assert!(block_a.successors.contains(&new_id), "A harus point ke Block baru");
    assert!(!block_a.successors.contains(&0x200), "A tidak boleh lagi point ke B");
    let block_b = &cfg.blocks[&0x200];
    assert!(!block_b.predecessors.contains(&0x100), "B harus kehilangan predecessor A");
    let block_new = &cfg.blocks[&new_id];
    assert!(block_new.predecessors.contains(&0x100), "Block baru harus punya predecessor A");
}