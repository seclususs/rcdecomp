use std::collections::{HashMap, HashSet};
use crate::analysis::graph::cfg::ControlFlowGraph;

pub struct DominatorTree {
    pub peta_idom: HashMap<u64, u64>,
    pub peta_post_idom: HashMap<u64, u64>,
    pub list_back_edges: Vec<(u64, u64)>,
    pub peta_children: HashMap<u64, Vec<u64>>,
    pub frontier_dominasi: HashMap<u64, HashSet<u64>>,
}

impl DominatorTree {
    pub fn new() -> Self {
        Self {
            peta_idom: HashMap::new(),
            peta_post_idom: HashMap::new(),
            list_back_edges: Vec::new(),
            peta_children: HashMap::new(),
            frontier_dominasi: HashMap::new(),
        }
    }
    pub fn hitung_dominators(&mut self, cfg: &ControlFlowGraph) {
        if cfg.blocks.is_empty() {
            return;
        }
        self.peta_idom = self.kalkulasi_idom_generic(cfg, cfg.entry_point, true);
        let mut exit_nodes = Vec::new();
        for (id, block) in &cfg.blocks {
            if block.successors.is_empty() {
                exit_nodes.push(*id);
            }
        }
        if let Some(&virtual_exit) = exit_nodes.last() {
             self.peta_post_idom = self.kalkulasi_idom_generic(cfg, virtual_exit, false);
        }
        self.bangun_peta_children(); 
        self.hitung_dominance_frontier(cfg); 
        self.deteksi_back_edges(cfg);
    }
    fn kalkulasi_idom_generic(&self, cfg: &ControlFlowGraph, root: u64, is_forward: bool) -> HashMap<u64, u64> {
        let all_nodes: Vec<u64> = cfg.blocks.keys().cloned().collect();
        let mut doms: HashMap<u64, u64> = HashMap::new();
        doms.insert(root, root);
        let mut changed = true;
        while changed {
            changed = false;
            for &node in &all_nodes {
                if node == root { continue; }
                let parents = if is_forward {
                    &cfg.blocks[&node].predecessors
                } else {
                    &cfg.blocks[&node].successors
                };
                if parents.is_empty() { continue; }
                let mut processed_parents = parents.iter().filter(|p| doms.contains_key(p));
                if let Some(&first_parent) = processed_parents.next() {
                    let mut new_idom = first_parent;
                    for &p in processed_parents {
                        if doms.contains_key(&p) {
                            new_idom = self.cari_intersection(&doms, p, new_idom);
                        }
                    }
                    if let Some(&curr_idom) = doms.get(&node) {
                        if curr_idom != new_idom {
                            doms.insert(node, new_idom);
                            changed = true;
                        }
                    } else {
                        doms.insert(node, new_idom);
                        changed = true;
                    }
                }
            }
        }
        doms
    }
    fn bangun_peta_children(&mut self) {
        for (&node, &parent) in &self.peta_idom {
            if node != parent {
                self.peta_children.entry(parent).or_default().push(node);
            }
        }
    }
    fn hitung_dominance_frontier(&mut self, cfg: &ControlFlowGraph) {
        for (node, block) in &cfg.blocks {
            if block.predecessors.len() >= 2 {
                for &p in &block.predecessors {
                    let mut runner = p;
                    while runner != *self.peta_idom.get(node).unwrap_or(node) {
                        self.frontier_dominasi.entry(runner).or_default().insert(*node);
                        if let Some(&next_runner) = self.peta_idom.get(&runner) {
                            if next_runner == runner { break; }
                            runner = next_runner;
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }
    fn cari_intersection(&self, doms: &HashMap<u64, u64>, mut b1: u64, mut b2: u64) -> u64 {
        let mut visited = HashSet::new();
        let mut iterations = 0; 
        while b1 != b2 && iterations < 10000 {
            visited.insert(b1);
            visited.insert(b2);
            if let Some(&parent) = doms.get(&b1) {
                if b1 != parent { b1 = parent; }
            }
            if let Some(&parent) = doms.get(&b2) {
                 if b2 != parent { b2 = parent; }
            }
            if b1 == b2 { return b1; }
            iterations += 1;
        }
        b1
    }
    fn deteksi_back_edges(&mut self, cfg: &ControlFlowGraph) {
        for (src_id, block) in &cfg.blocks {
            for &target_id in &block.successors {
                if self.cek_apakah_didominasi(*src_id, target_id) {
                    self.list_back_edges.push((*src_id, target_id));
                }
            }
        }
    }
    pub fn cek_apakah_didominasi(&self, node: u64, dominator: u64) -> bool {
        let mut curr = node;
        let mut iterations = 0;
        while let Some(&parent) = self.peta_idom.get(&curr) {
            if curr == dominator { return true; }
            if curr == parent { break; }
            curr = parent;
            iterations += 1;
            if iterations > 10000 { break; } 
        }
        false
    }
}