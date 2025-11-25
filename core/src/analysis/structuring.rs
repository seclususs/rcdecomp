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
    },
    UnstructuredGoto(u64),
    Break,
    Continue,
}

pub struct ControlFlowStructurer {
    visited: HashSet<u64>,
    loop_headers: HashSet<u64>,
    loop_exits: HashMap<u64, u64>,
}

impl ControlFlowStructurer {
    pub fn new() -> Self {
        Self {
            visited: HashSet::new(),
            loop_headers: HashSet::new(),
            loop_exits: HashMap::new(),
        }
    }
    pub fn bangun_tree_struktur(&mut self, cfg: &ControlFlowGraph) -> NodeAst {
        let mut dom_tree = DominatorTree::new();
        dom_tree.hitung_dominators(cfg);
        self.visited.clear();
        self.loop_headers.clear();
        self.loop_exits.clear();
        for &(_src, target) in &dom_tree.list_back_edges {
            self.loop_headers.insert(target);
        }
        self.proses_node_recursif(cfg, cfg.entry_point, None)
    }
    fn proses_node_recursif(&mut self, cfg: &ControlFlowGraph, current_id: u64, current_loop_header: Option<u64>) -> NodeAst {
        if self.visited.contains(&current_id) {
            if let Some(header) = current_loop_header {
                if current_id == header {
                    return NodeAst::Continue;
                }
            }
            return NodeAst::UnstructuredGoto(current_id);
        }
        self.visited.insert(current_id);
        let block = match cfg.blocks.get(&current_id) {
            Some(b) => b,
            None => return NodeAst::Block(Vec::new()),
        };
        let node_block = NodeAst::Block(block.instruksi_list.clone());
        let successors = &block.successors;
        if self.loop_headers.contains(&current_id) && current_loop_header != Some(current_id) {
            self.visited.remove(&current_id); 
            let body_ast = self.proses_node_recursif(cfg, current_id, Some(current_id));
            return NodeAst::WhileLoop {
                condition: "true".to_string(), 
                body: Box::new(body_ast)
            };
        }
        if successors.is_empty() {
            return node_block;
        } else if successors.len() == 1 {
            let next_node = self.proses_node_recursif(cfg, successors[0], current_loop_header);
            return NodeAst::Sequence(vec![node_block, next_node]);
        } else if successors.len() == 2 {
            let s_true = successors[0];
            let s_false = successors[1];
            if let Some(block_b) = cfg.blocks.get(&s_true) {
                if block_b.successors.len() == 2 {
                    let b_true = block_b.successors[0];
                    let b_false = block_b.successors[1];
                    if b_false == s_false && !self.visited.contains(&s_true) {
                        let cond_a = self.rekonstruksi_kondisi(&block.instruksi_list);
                        let cond_b = self.rekonstruksi_kondisi(&block_b.instruksi_list);
                        self.visited.insert(s_true);
                        let true_node = self.proses_node_recursif(cfg, b_true, current_loop_header);
                        let false_node = self.proses_node_recursif(cfg, s_false, current_loop_header);
                        return NodeAst::Sequence(vec![
                            node_block,
                            NodeAst::IfElse {
                                condition: format!("({}) && ({})", cond_a, cond_b),
                                true_branch: Box::new(true_node),
                                false_branch: Some(Box::new(false_node)),
                            }
                        ]);
                    }
                }
            }
            if let Some(block_b) = cfg.blocks.get(&s_false) {
                if block_b.successors.len() == 2 {
                    let b_true = block_b.successors[0];
                    let b_false = block_b.successors[1];
                    if b_true == s_true && !self.visited.contains(&s_false) {
                        let cond_a = self.rekonstruksi_kondisi(&block.instruksi_list);
                        let cond_b = self.rekonstruksi_kondisi(&block_b.instruksi_list);
                        self.visited.insert(s_false);
                        let true_node = self.proses_node_recursif(cfg, s_true, current_loop_header);
                        let false_node = self.proses_node_recursif(cfg, b_false, current_loop_header);
                        return NodeAst::Sequence(vec![
                            node_block,
                            NodeAst::IfElse {
                                condition: format!("({}) || ({})", cond_a, cond_b),
                                true_branch: Box::new(true_node),
                                false_branch: Some(Box::new(false_node)),
                            }
                        ]);
                    }
                }
            }
            let true_node = self.proses_node_recursif(cfg, s_true, current_loop_header);
            let false_node = self.proses_node_recursif(cfg, s_false, current_loop_header);
            let cond_str = self.rekonstruksi_kondisi(&block.instruksi_list);
            return NodeAst::Sequence(vec![
                node_block,
                NodeAst::IfElse {
                    condition: cond_str,
                    true_branch: Box::new(true_node),
                    false_branch: Some(Box::new(false_node)),
                }
            ]);
        } else {
            let switch_var = self.analisa_variabel_switch(&block.instruksi_list);
            let mut cases = Vec::new();
            for (idx, &succ_id) in successors.iter().enumerate() {
                let case_body = self.proses_node_recursif(cfg, succ_id, current_loop_header);
                cases.push((idx as u64, case_body));
            }
            return NodeAst::Sequence(vec![
                node_block,
                NodeAst::Switch {
                    variable: switch_var,
                    cases: cases,
                    default: None,
                }
            ]);
        }
    }
    fn analisa_variabel_switch(&self, stmts: &[StatementIr]) -> String {
        if let Some(last) = stmts.last() {
            if last.operation_code == OperasiIr::Jmp {
                if let TipeOperand::MemoryRef { base: _, offset: _ } = &last.operand_satu {
                    return "switch_idx".to_string();
                }
                if let TipeOperand::Expression { operasi: _, operand_kiri, operand_kanan: _ } = &last.operand_satu {
                    return self.format_operand_simpel(operand_kiri);
                }
                return self.format_operand_simpel(&last.operand_satu);
            }
        }
        "unknown_switch_var".to_string()
    }
    fn rekonstruksi_kondisi(&self, stmts: &[StatementIr]) -> String {
        if stmts.is_empty() {
            return "unknown_cond".to_string();
        }
        let last_stmt = stmts.last().unwrap();
        let mut cmp_stmt_opt = None;
        for i in (0..stmts.len()-1).rev() {
            match stmts[i].operation_code {
                OperasiIr::Cmp | OperasiIr::Test => {
                    cmp_stmt_opt = Some(&stmts[i]);
                    break;
                },
                OperasiIr::Add | OperasiIr::Sub => {
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
                _ => format!("flag_check_addr_{:x}", last_stmt.address_asal)
            }
        } else {
            format!("flag_check_addr_{:x}", last_stmt.address_asal)
        }
    }
    fn format_operand_simpel(&self, op: &TipeOperand) -> String {
        match op {
            TipeOperand::Register(r) => r.clone(),
            TipeOperand::SsaVariable(name, ver) => format!("{}_{}", name, ver),
            TipeOperand::Immediate(val) => format!("0x{:x}", val),
            TipeOperand::MemoryRef { base, offset } => {
                if *offset < 0 {
                    format!("var_{}", offset.abs())
                } else {
                    format!("*(long*)({} + {})", base, offset)
                }
            },
            TipeOperand::Memory(addr) => format!("*(long*)0x{:x}", addr),
            TipeOperand::Expression { operasi: _, operand_kiri, operand_kanan: _ } => {
                 self.format_operand_simpel(operand_kiri)
            },
            TipeOperand::None => "0".to_string(),
        }
    }
}