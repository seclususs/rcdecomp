use std::collections::{HashSet, HashMap};
use crate::analysis::cfg::ControlFlowGraph;
use crate::analysis::dominator::DominatorTree;
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};

#[derive(Debug, Clone)]
pub enum NodeAst {
    Block(Vec<StatementIr>),
    Sequence(Vec<NodeAst>),
    IfElse {
        condition: String,
        true_branch: Box<NodeAst>,
        false_branch: Option<Box<NodeAst>>,
    },
    Switch {
        variable: String,
        cases: Vec<(u64, NodeAst)>,
        default: Option<Box<NodeAst>>,
    },
    WhileLoop {
        condition: String,
        body: Box<NodeAst>,
        is_do_while: bool,
    },
    UnstructuredGoto(u64),
    Break,
    Continue,
    Empty,
}

pub struct ControlFlowStructurer {
    visited: HashSet<u64>,
    loop_headers: HashMap<u64, Vec<u64>>, 
}

impl ControlFlowStructurer {
    pub fn new() -> Self {
        Self {
            visited: HashSet::new(),
            loop_headers: HashMap::new(),
        }
    }
    pub fn bangun_tree_struktur(&mut self, cfg: &ControlFlowGraph) -> NodeAst {
        let mut dom_tree = DominatorTree::new();
        dom_tree.hitung_dominators(cfg);
        self.identifikasi_loops(&dom_tree);
        self.analisis_region(cfg, &dom_tree, cfg.entry_point, None)
    }
    fn identifikasi_loops(&mut self, dom_tree: &DominatorTree) {
        for &(latch, header) in &dom_tree.list_back_edges {
            self.loop_headers.entry(header).or_default().push(latch);
        }
    }
    fn analisis_region(
        &mut self, 
        cfg: &ControlFlowGraph, 
        dom: &DominatorTree, 
        current_id: u64, 
        stop_at: Option<u64>
    ) -> NodeAst {
        if Some(current_id) == stop_at {
            return NodeAst::Empty;
        }
        if self.visited.contains(&current_id) {
            return NodeAst::UnstructuredGoto(current_id);
        }
        self.visited.insert(current_id);
        let block = match cfg.blocks.get(&current_id) {
            Some(b) => b,
            None => return NodeAst::Empty,
        };
        if self.loop_headers.contains_key(&current_id) {
            return self.strukturkan_loop(cfg, dom, current_id, stop_at);
        }
        let node_block = NodeAst::Block(block.instruksi_list.clone());
        let successors = &block.successors;
        let merge_point = dom.peta_post_idom.get(&current_id).cloned();
        if successors.is_empty() {
            return node_block;
        } else if successors.len() == 1 {
            let next_node = successors[0];
            let rest_ast = self.analisis_region(cfg, dom, next_node, stop_at);
            return self.gabungkan_sequence(node_block, rest_ast);
        } else if successors.len() == 2 {
            let s_true = successors[0];
            let s_false = successors[1];
            let cond_str = self.rekonstruksi_kondisi(&block.instruksi_list);
            let true_branch_ast = self.analisis_sub_region(cfg, dom, s_true, merge_point);
            let false_branch_ast = self.analisis_sub_region(cfg, dom, s_false, merge_point);
            let if_ast = NodeAst::IfElse {
                condition: cond_str,
                true_branch: Box::new(true_branch_ast),
                false_branch: if self.is_ast_empty(&false_branch_ast) { None } else { Some(Box::new(false_branch_ast)) },
            };

            if let Some(mp) = merge_point {
                self.visited.remove(&mp); 
                let next_ast = self.analisis_region(cfg, dom, mp, stop_at);
                return self.gabungkan_sequence(self.gabungkan_sequence(node_block, if_ast), next_ast);
            } else {
                return self.gabungkan_sequence(node_block, if_ast);
            }
        } else {
            let switch_var = self.analisa_variabel_switch(&block.instruksi_list);
            let mut cases = Vec::new();
            for (idx, &succ) in successors.iter().enumerate() {
                let case_ast = self.analisis_sub_region(cfg, dom, succ, merge_point);
                cases.push((idx as u64, case_ast));
            }
            let switch_ast = NodeAst::Switch {
                variable: switch_var,
                cases,
                default: None,
            };
            if let Some(mp) = merge_point {
                self.visited.remove(&mp);
                let next_ast = self.analisis_region(cfg, dom, mp, stop_at);
                return self.gabungkan_sequence(self.gabungkan_sequence(node_block, switch_ast), next_ast);
            } else {
                return self.gabungkan_sequence(node_block, switch_ast);
            }
        }
    }
    fn analisis_sub_region(&mut self, cfg: &ControlFlowGraph, dom: &DominatorTree, start: u64, end: Option<u64>) -> NodeAst {
        self.analisis_region(cfg, dom, start, end)
    }
    fn strukturkan_loop(
        &mut self, 
        cfg: &ControlFlowGraph, 
        dom: &DominatorTree, 
        header_id: u64, 
        stop_at: Option<u64>
    ) -> NodeAst {
        let block = cfg.blocks.get(&header_id).unwrap();
        let node_block = NodeAst::Block(block.instruksi_list.clone());
        let loop_merge = self.cari_loop_exit(cfg, dom, header_id);
        let mut body_ast = NodeAst::Empty;
        let mut loop_succs = Vec::new();
        for &succ in &block.successors {
            if dom.cek_apakah_didominasi(succ, header_id) && succ != loop_merge.unwrap_or(0) {
                 loop_succs.push(succ);
            }
        }
        if !loop_succs.is_empty() {
            body_ast = self.analisis_region(cfg, dom, loop_succs[0], Some(header_id));
        }
        let cond_str = self.rekonstruksi_kondisi(&block.instruksi_list);
        let loop_ast = NodeAst::WhileLoop {
            condition: cond_str, 
            body: Box::new(body_ast),
            is_do_while: false, 
        };
        if let Some(mp) = loop_merge {
            if Some(mp) != stop_at {
                self.visited.remove(&mp);
                let next_ast = self.analisis_region(cfg, dom, mp, stop_at);
                return self.gabungkan_sequence(self.gabungkan_sequence(node_block, loop_ast), next_ast);
            }
        }
        self.gabungkan_sequence(node_block, loop_ast)
    }
    fn cari_loop_exit(&self, cfg: &ControlFlowGraph, dom: &DominatorTree, header: u64) -> Option<u64> {
        if let Some(block) = cfg.blocks.get(&header) {
            for &succ in &block.successors {
                if !dom.cek_apakah_didominasi(succ, header) {
                    return Some(succ);
                }
            }
        }
        dom.peta_post_idom.get(&header).cloned()
    }
    fn gabungkan_sequence(&self, first: NodeAst, second: NodeAst) -> NodeAst {
        match (first, second) {
            (NodeAst::Empty, b) => b,
            (a, NodeAst::Empty) => a,
            (NodeAst::Sequence(mut a_vec), NodeAst::Sequence(b_vec)) => {
                a_vec.extend(b_vec);
                NodeAst::Sequence(a_vec)
            },
            (NodeAst::Sequence(mut a_vec), b) => {
                a_vec.push(b);
                NodeAst::Sequence(a_vec)
            },
            (a, NodeAst::Sequence(mut b_vec)) => {
                b_vec.insert(0, a);
                NodeAst::Sequence(b_vec)
            },
            (a, b) => NodeAst::Sequence(vec![a, b]),
        }
    }
    fn is_ast_empty(&self, ast: &NodeAst) -> bool {
        matches!(ast, NodeAst::Empty)
    }
    fn rekonstruksi_kondisi(&self, stmts: &[StatementIr]) -> String {
        if stmts.is_empty() { return "true".to_string(); }
        let last_stmt = stmts.last().unwrap();
        let mut cmp_stmt_opt = None;
        for i in (0..stmts.len()-1).rev() {
            match stmts[i].operation_code {
                OperasiIr::Cmp | OperasiIr::Test => {
                    cmp_stmt_opt = Some(&stmts[i]);
                    break;
                },
                _ => {}
            }
        }
        if let Some(cmp_stmt) = cmp_stmt_opt {
            let op1 = self.format_operand_simpel(&cmp_stmt.operand_satu);
            let op2 = self.format_operand_simpel(&cmp_stmt.operand_dua);
            match last_stmt.operation_code {
                OperasiIr::Je => format!("{} == {}", op1, op2),
                OperasiIr::Jne => format!("{} != {}", op1, op2),
                OperasiIr::Jg => format!("{} > {}", op1, op2),
                OperasiIr::Jge => format!("{} >= {}", op1, op2),
                OperasiIr::Jl => format!("{} < {}", op1, op2),
                OperasiIr::Jle => format!("{} <= {}", op1, op2),
                _ => "true".to_string() 
            }
        } else {
             match last_stmt.operation_code {
                OperasiIr::Jmp => "true".to_string(), 
                _ => "cond_flag".to_string()
             }
        }
    }
    fn analisa_variabel_switch(&self, stmts: &[StatementIr]) -> String {
        if let Some(last) = stmts.last() {
            if last.operation_code == OperasiIr::Jmp {
                if let TipeOperand::MemoryRef { .. } = &last.operand_satu {
                    return "switch_table_idx".to_string();
                }
            }
        }
        "switch_var".to_string()
    }
    fn format_operand_simpel(&self, op: &TipeOperand) -> String {
        match op {
            TipeOperand::Register(r) => r.clone(),
            TipeOperand::SsaVariable(name, ver) => format!("{}_{}", name, ver),
            TipeOperand::Immediate(val) => format!("0x{:x}", val),
            TipeOperand::MemoryRef { base, offset } => format!("*({} + {})", base, offset),
            _ => "?".to_string(),
        }
    }
}