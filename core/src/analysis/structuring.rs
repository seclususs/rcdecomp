use std::collections::HashSet;
use crate::analysis::cfg::ControlFlowGraph;
use crate::ir::types::StatementIr;

#[derive(Debug, Clone)]
pub enum NodeAst {
    Block(Vec<StatementIr>),
    Sequence(Vec<NodeAst>),
    IfElse {
        condition: String,
        true_branch: Box<NodeAst>,
        false_branch: Option<Box<NodeAst>>,
    },
    WhileLoop {
        condition: String,
        body: Box<NodeAst>,
    },
    UnstructuredGoto(u64), 
}

pub struct ControlFlowStructurer {
    visited: HashSet<u64>,
}

impl ControlFlowStructurer {
    pub fn new() -> Self {
        Self {
            visited: HashSet::new(),
        }
    }
    pub fn bangun_tree_struktur(&mut self, cfg: &ControlFlowGraph) -> NodeAst {
        self.visited.clear();
        self.proses_node_recursif(cfg, cfg.entry_point)
    }
    fn proses_node_recursif(&mut self, cfg: &ControlFlowGraph, current_id: u64) -> NodeAst {
        if self.visited.contains(&current_id) {
            return NodeAst::UnstructuredGoto(current_id);
        }
        self.visited.insert(current_id);
        let block = match cfg.blocks.get(&current_id) {
            Some(b) => b,
            None => return NodeAst::Block(Vec::new()),
        };
        let node_block = NodeAst::Block(block.instruksi_list.clone());
        let successors = &block.successors;
        if successors.is_empty() {
            return node_block;
        } else if successors.len() == 1 {
            let next_node = self.proses_node_recursif(cfg, successors[0]);
            return NodeAst::Sequence(vec![node_block, next_node]);
        } else if successors.len() == 2 {
            let true_node = self.proses_node_recursif(cfg, successors[0]);
            let false_node = self.proses_node_recursif(cfg, successors[1]);
            let cond_str = format!("flag_check_addr_{:x}", current_id);
            return NodeAst::Sequence(vec![
                node_block,
                NodeAst::IfElse {
                    condition: cond_str,
                    true_branch: Box::new(true_node),
                    false_branch: Some(Box::new(false_node)),
                }
            ]);
        }
        node_block
    }
}