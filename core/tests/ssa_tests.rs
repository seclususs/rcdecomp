use std::collections::{HashMap};
use rcdecomp_core::analysis::graph::cfg::{ControlFlowGraph, BasicBlock};
use rcdecomp_core::analysis::graph::dom::DominatorTree;
use rcdecomp_core::analysis::passes::ssa::{SsaTransformer};
use rcdecomp_core::ir::types::{StatementIr, OperasiIr, TipeOperand};

fn create_stmt(addr: u64, op: OperasiIr, op1: TipeOperand, op2: TipeOperand) -> StatementIr {
    StatementIr::new(addr, op, op1, op2)
}

fn reg(name: &str) -> TipeOperand {
    TipeOperand::Register(name.to_string())
}

fn imm(val: i64) -> TipeOperand {
    TipeOperand::Immediate(val)
}

fn setup_ssa_env(stmts_map: HashMap<u64, Vec<StatementIr>>, edges: Vec<(u64, u64)>, entry: u64) -> (ControlFlowGraph, DominatorTree, SsaTransformer) {
    let mut cfg = ControlFlowGraph::inisialisasi_graph_kosong();
    cfg.entry_point = entry;
    for (id, stmts) in stmts_map {
        let mut block = BasicBlock::new(id);
        block.instruksi_list = stmts;
        block.id_block = id;
        cfg.blocks.insert(id, block);
    }
    for (from, to) in edges {
        cfg.hubungkan_manual(from, to);
    }
    let mut dom_tree = DominatorTree::new();
    dom_tree.hitung_dominators(&cfg);
    let transformer = SsaTransformer::new();
    (cfg, dom_tree, transformer)
}

#[test]
fn test_ssa_renaming_and_phi_insertion() {
    let mut stmts = HashMap::new();
    stmts.insert(0, vec![
        create_stmt(0x00, OperasiIr::Mov, reg("rax"), imm(10)),
        create_stmt(0x04, OperasiIr::Cmp, reg("rax"), imm(10)),
        create_stmt(0x08, OperasiIr::Je, imm(2), TipeOperand::None),
    ]);
    stmts.insert(1, vec![
        create_stmt(0x10, OperasiIr::Mov, reg("rax"), imm(100)), 
        create_stmt(0x14, OperasiIr::Jmp, imm(3), TipeOperand::None),
    ]);
    stmts.insert(2, vec![
        create_stmt(0x20, OperasiIr::Mov, reg("rax"), imm(200)),
        create_stmt(0x24, OperasiIr::Jmp, imm(3), TipeOperand::None),
    ]);
    stmts.insert(3, vec![
        create_stmt(0x30, OperasiIr::Mov, reg("rbx"), reg("rax")), // Use rax
        create_stmt(0x34, OperasiIr::Ret, TipeOperand::None, TipeOperand::None),
    ]);
    let edges = vec![(0, 1), (0, 2), (1, 3), (2, 3)];
    let (mut cfg, dom_tree, mut transformer) = setup_ssa_env(stmts, edges, 0);
    transformer.lakukan_transformasi_ssa(&mut cfg, &dom_tree);
    let block3 = &cfg.blocks[&3];
    let phi_node = block3.instruksi_list.iter().find(|s| s.operation_code == OperasiIr::Phi);
    assert!(phi_node.is_some(), "Block 3 harus memiliki Phi node untuk rax");
    let phi = phi_node.unwrap();
    if let TipeOperand::SsaVariable(name, ver) = &phi.operand_satu {
        assert_eq!(name, "rax");
        assert!(*ver > 0, "Phi node harus mendefinisikan versi baru rax");
    } else {
        panic!("Operand 1 Phi node harus SsaVariable");
    }
    let use_stmt = block3.instruksi_list.iter().find(|s| s.operation_code == OperasiIr::Mov).unwrap();
    if let TipeOperand::SsaVariable(name, _) = &use_stmt.operand_dua {
        assert_eq!(name, "rax", "Penggunaan di join block harus merujuk ke rax yang sudah di-rename");
    } else {
        panic!("Operand 2 harus SsaVariable, dapat: {:?}", use_stmt.operand_dua);
    }
}

#[test]
fn test_sccp_constant_propagation() {
    let mut stmts = HashMap::new();
    stmts.insert(0, vec![
        create_stmt(0x00, OperasiIr::Mov, reg("rax"), imm(5)),
        create_stmt(0x04, OperasiIr::Mov, reg("rbx"), imm(10)),
        create_stmt(0x08, OperasiIr::Add, reg("rax"), reg("rbx")),
        create_stmt(0x0C, OperasiIr::Mov, reg("rcx"), reg("rax")),
        create_stmt(0x10, OperasiIr::Ret, TipeOperand::None, TipeOperand::None),
    ]);
    let (mut cfg, dom_tree, mut transformer) = setup_ssa_env(stmts, vec![], 0);
    transformer.lakukan_transformasi_ssa(&mut cfg, &dom_tree);
    transformer.optimasi_propagasi_konstanta(&mut cfg);
    let block = &cfg.blocks[&0];
    let final_mov = block.instruksi_list.iter()
        .find(|s| s.address_asal == 0x0C)
        .expect("Instruksi Mov rcx harus ada");
    if let TipeOperand::Immediate(val) = final_mov.operand_dua {
        assert_eq!(val, 15, "Konstanta 15 harus terpropagasi ke instruksi mov rcx");
    } else {
        panic!("Operand kedua Mov rcx harus menjadi Immediate(15), didapat: {:?}", final_mov.operand_dua);
    }
}

#[test]
fn test_sccp_branch_folding() {
    let mut stmts = HashMap::new();
    stmts.insert(0, vec![
        create_stmt(0x00, OperasiIr::Mov, reg("rax"), imm(1)),
        create_stmt(0x04, OperasiIr::Mov, reg("zf"), TipeOperand::Expression {
            operasi: OperasiIr::Je,
            operand_kiri: Box::new(reg("rax")),
            operand_kanan: Box::new(imm(1))
        }),
        create_stmt(0x08, OperasiIr::Je, imm(100), reg("zf")), 
    ]);
    stmts.insert(100, vec![
        create_stmt(0x100, OperasiIr::Ret, TipeOperand::None, TipeOperand::None),
    ]);
    stmts.insert(200, vec![
        create_stmt(0x200, OperasiIr::Ret, TipeOperand::None, TipeOperand::None),
    ]);
    let edges = vec![(0, 100), (0, 200)];
    let (mut cfg, dom_tree, mut transformer) = setup_ssa_env(stmts, edges, 0);
    transformer.lakukan_transformasi_ssa(&mut cfg, &dom_tree);
    assert!(cfg.blocks.contains_key(&200), "Block dead harus ada sebelum optimasi");
    transformer.optimasi_propagasi_konstanta(&mut cfg);
    let block_dead_exists = cfg.blocks.contains_key(&200);
    assert!(!block_dead_exists, "Block 200 (Dead Branch) harus dihapus dari CFG setelah SCCP");
    let block_entry = &cfg.blocks[&0];
    assert_eq!(block_entry.successors.len(), 1, "Block 0 harus hanya punya 1 successor setelah folding");
    assert_eq!(block_entry.successors[0], 100, "Successor harus B1 (True branch)");
}