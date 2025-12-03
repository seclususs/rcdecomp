use std::collections::{HashMap};
use rcdecomp_core::analysis::graph::cfg::{ControlFlowGraph, BasicBlock};
use rcdecomp_core::analysis::graph::dom::DominatorTree;
use rcdecomp_core::analysis::passes::ssa::{SsaTransformer};
use rcdecomp_core::ir::types::{StatementIr, OperasiIr, TipeOperand};

// --- Helper Functions ---

fn create_stmt(addr: u64, op: OperasiIr, op1: TipeOperand, op2: TipeOperand) -> StatementIr {
    StatementIr::new(addr, op, op1, op2)
}

fn reg(name: &str) -> TipeOperand {
    TipeOperand::Register(name.to_string())
}

fn imm(val: i64) -> TipeOperand {
    TipeOperand::Immediate(val)
}

fn create_binop(addr: u64, op: OperasiIr, dest: &str, src1: &str, src2: &str) -> StatementIr {
    StatementIr::new(
        addr,
        OperasiIr::Mov, // Gunakan Mov untuk assignment hasil expression
        reg(dest),
        TipeOperand::Expression {
            operasi: op,
            operand_kiri: Box::new(reg(src1)),
            operand_kanan: Box::new(reg(src2)),
        }
    )
}

// Helper untuk setup SSA environment
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

// --- Test Suite ---

#[test]
fn test_ssa_renaming_and_phi_insertion() {
    // 1. SSA Renaming & Phi Insertion
    let mut stmts = HashMap::new();
    
    // Block 0
    stmts.insert(0, vec![
        create_stmt(0x00, OperasiIr::Mov, reg("rax"), imm(10)),
        create_stmt(0x04, OperasiIr::Cmp, reg("rax"), imm(10)),
        create_stmt(0x08, OperasiIr::Je, imm(2), TipeOperand::None),
    ]); 

    // Block 1
    stmts.insert(1, vec![
        create_stmt(0x10, OperasiIr::Mov, reg("rax"), imm(100)), 
        create_stmt(0x14, OperasiIr::Jmp, imm(3), TipeOperand::None),
    ]);

    // Block 2
    stmts.insert(2, vec![
        create_stmt(0x20, OperasiIr::Mov, reg("rax"), imm(200)),
        create_stmt(0x24, OperasiIr::Jmp, imm(3), TipeOperand::None),
    ]);

    // Block 3 (Join)
    stmts.insert(3, vec![
        create_stmt(0x30, OperasiIr::Mov, reg("rbx"), reg("rax")), 
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
}

#[test]
fn test_sccp_constant_propagation() {
    // 2. SCCP: Constant Propagation
    // B0:
    //   rax = 5
    //   rbx = 10
    //   rcx = rax + rbx  (Should be 15)
    
    let mut stmts = HashMap::new();
    stmts.insert(0, vec![
        create_stmt(0x00, OperasiIr::Mov, reg("rax"), imm(5)),
        create_stmt(0x04, OperasiIr::Mov, reg("rbx"), imm(10)),
        
        // FIX: Gunakan helper create_binop untuk membuat Expression yang benar
        // rcx = rax + rbx
        create_binop(0x08, OperasiIr::Add, "rcx", "rax", "rbx"),
        
        create_stmt(0x10, OperasiIr::Ret, TipeOperand::None, TipeOperand::None),
    ]);

    let (mut cfg, dom_tree, mut transformer) = setup_ssa_env(stmts, vec![], 0);
    
    transformer.lakukan_transformasi_ssa(&mut cfg, &dom_tree);
    transformer.optimasi_propagasi_konstanta(&mut cfg);

    let block = &cfg.blocks[&0];
    
    // Cari instruksi yang mendefinisikan rcx (di 0x08)
    let rcx_def = block.instruksi_list.iter()
        .find(|s| s.address_asal == 0x08)
        .expect("Instruksi definisi rcx harus ada");

    // Pastikan operand kanannya menjadi Immediate(15)
    // Sccp mengganti operand_dua (expression) dengan konstanta hasil evaluasi
    if let TipeOperand::Immediate(val) = rcx_def.operand_dua {
        assert_eq!(val, 15, "Konstanta 15 harus terpropagasi (5 + 10)");
    } else {
        panic!("Operand kedua rcx harus menjadi Immediate(15), didapat: {:?}", rcx_def.operand_dua);
    }
}

#[test]
fn test_sccp_branch_folding() {
    // 2b. SCCP: Branch Folding
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