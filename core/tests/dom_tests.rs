use rcdecomp_core::analysis::graph::cfg::{ControlFlowGraph, BasicBlock};
use rcdecomp_core::analysis::graph::dom::DominatorTree;

fn create_simple_cfg(entry: u64, nodes: Vec<u64>, edges: Vec<(u64, u64)>) -> ControlFlowGraph {
    let mut cfg = ControlFlowGraph::inisialisasi_graph_kosong();
    cfg.entry_point = entry;
    for id in nodes {
        cfg.blocks.insert(id, BasicBlock::new(id));
    }
    for (from, to) in edges {
        cfg.hubungkan_manual(from, to);
    }
    cfg
}

#[test]
fn test_diamond_graph_structure() {
    let nodes = vec![1, 2, 3, 4];
    let edges = vec![
        (1, 2),
        (1, 3),
        (2, 4),
        (3, 4),
    ];
    let cfg = create_simple_cfg(1, nodes, edges);
    let mut dom_tree = DominatorTree::new();
    dom_tree.hitung_dominators(&cfg);
    assert_eq!(dom_tree.peta_idom.get(&1), Some(&1), "IDOM(Root) harus Root");
    assert_eq!(dom_tree.peta_idom.get(&2), Some(&1), "IDOM(B) harus A");
    assert_eq!(dom_tree.peta_idom.get(&3), Some(&1), "IDOM(C) harus A");
    assert_eq!(dom_tree.peta_idom.get(&4), Some(&1), "IDOM(D) harus A (Diamond Property)");
}

#[test]
fn test_dominance_frontier() {
    let nodes = vec![1, 2, 3, 4];
    let edges = vec![
        (1, 2), (1, 3),
        (2, 4), (3, 4)
    ];
    let cfg = create_simple_cfg(1, nodes, edges);
    let mut dom_tree = DominatorTree::new();
    dom_tree.hitung_dominators(&cfg);
    if let Some(frontier_b) = dom_tree.frontier_dominasi.get(&2) {
        assert!(frontier_b.contains(&4), "DF(B) harus berisi D");
    } else {
        panic!("Frontier untuk node 2 tidak ditemukan");
    }
    if let Some(frontier_c) = dom_tree.frontier_dominasi.get(&3) {
        assert!(frontier_c.contains(&4), "DF(C) harus berisi D");
    } else {
        panic!("Frontier untuk node 3 tidak ditemukan");
    }
    if let Some(frontier_a) = dom_tree.frontier_dominasi.get(&1) {
        assert!(frontier_a.is_empty(), "DF(A) harus kosong");
    }
}

#[test]
fn test_loop_back_edge_detection() {
    let nodes = vec![10, 20];
    let edges = vec![
        (10, 20),
        (20, 10),
    ];
    let cfg = create_simple_cfg(10, nodes, edges);
    let mut dom_tree = DominatorTree::new();
    dom_tree.hitung_dominators(&cfg);
    assert_eq!(dom_tree.peta_idom.get(&20), Some(&10));
    let found_back_edge = dom_tree.list_back_edges.contains(&(20, 10));
    assert!(found_back_edge, "Harus mendeteksi back edge 20->10");
}

#[test]
fn test_complex_dominance_chain() {
    let nodes = vec![1, 2, 3];
    let edges = vec![(1, 2), (2, 3)];
    let cfg = create_simple_cfg(1, nodes, edges);
    let mut dom_tree = DominatorTree::new();
    dom_tree.hitung_dominators(&cfg);
    assert_eq!(dom_tree.peta_idom.get(&2), Some(&1), "IDOM(B) = A");
    assert_eq!(dom_tree.peta_idom.get(&3), Some(&2), "IDOM(C) = B");
}