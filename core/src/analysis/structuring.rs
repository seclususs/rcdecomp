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
    TernaryOp {
        target_var: String,
        condition: String,
        true_val: String,
        false_val: String,
    },
    Switch {
        variable: String,
        cases: Vec<(Vec<u64>, NodeAst)>,
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

#[derive(Debug, Clone)]
struct LoopContext {
    header_id: u64,
    merge_point: Option<u64>,
}

pub struct ControlFlowStructurer {
    visited: HashSet<u64>,
    loop_headers: HashMap<u64, Vec<u64>>, 
    split_count: usize,
    loop_stack: Vec<LoopContext>,
}

impl ControlFlowStructurer {
    pub fn new() -> Self {
        Self {
            visited: HashSet::new(),
            loop_headers: HashMap::new(),
            split_count: 0,
            loop_stack: Vec::new(),
        }
    }
    pub fn bangun_tree_struktur(&mut self, cfg: &mut ControlFlowGraph) -> NodeAst {
        self.normalisasi_irreducible_loops(cfg);
        let mut dom_tree = DominatorTree::new();
        dom_tree.hitung_dominators(cfg);
        self.identifikasi_loops(&dom_tree);
        self.analisis_region(cfg, &dom_tree, cfg.entry_point, None)
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
            return self.resolve_jump_target(current_id);
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
        let immediate_post_dom = dom.peta_post_idom.get(&current_id).cloned();
        let merge_point = if let Some(ipd) = immediate_post_dom {
            if let Some(stop) = stop_at {
                if dom.cek_apakah_didominasi(stop, ipd) { Some(ipd) } else { Some(stop) }
            } else {
                Some(ipd)
            }
        } else {
            stop_at
        };
        if successors.is_empty() {
            return node_block;
        } else if successors.len() == 1 {
            let next_node = successors[0];
            let rest_ast = self.analisis_region(cfg, dom, next_node, stop_at);
            return self.gabungkan_sequence(node_block, rest_ast);
        } else if successors.len() == 2 {
            let s_true = successors[0];
            let s_false = successors[1];
            if let Some(ternary_ast) = self.cek_pola_ternary(cfg, block, s_true, s_false, merge_point) {
                if let Some(mp) = merge_point {
                    self.visited.remove(&mp); 
                    let next_ast = self.analisis_region(cfg, dom, mp, stop_at);
                    return self.gabungkan_sequence(ternary_ast, next_ast);
                }
                return ternary_ast;
            }
            if let Some((combined_cond, final_true, final_false)) = self.cek_pola_short_circuit(cfg, block, s_true, s_false) {
                 let true_branch_ast = self.analisis_region(cfg, dom, final_true, merge_point);
                 let false_branch_ast = self.analisis_region(cfg, dom, final_false, merge_point);
                 let if_ast = NodeAst::IfElse {
                     condition: combined_cond,
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
            }
            let cond_str = self.rekonstruksi_kondisi(&block.instruksi_list);
            let true_branch_ast = self.analisis_region(cfg, dom, s_true, merge_point);
            let false_branch_ast = self.analisis_region(cfg, dom, s_false, merge_point);
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
            return self.strukturkan_switch(cfg, dom, block, successors, stop_at, node_block);
        }
    }
    fn cek_pola_ternary(
        &self, 
        cfg: &ControlFlowGraph,
        header_block: &crate::analysis::cfg::BasicBlock, 
        true_node: u64, 
        false_node: u64,
        merge_point: Option<u64>
    ) -> Option<NodeAst> {
        let mp = merge_point?;
        let block_true = cfg.blocks.get(&true_node)?;
        let block_false = cfg.blocks.get(&false_node)?;
        if block_true.successors.len() != 1 || block_true.successors[0] != mp { return None; }
        if block_false.successors.len() != 1 || block_false.successors[0] != mp { return None; }
        let (var_true, val_true) = self.ambil_assignment_terakhir(&block_true.instruksi_list)?;
        let (var_false, val_false) = self.ambil_assignment_terakhir(&block_false.instruksi_list)?;
        if var_true != var_false { return None; }
        let cond_str = self.rekonstruksi_kondisi(&header_block.instruksi_list);
        let mut header_stmts = header_block.instruksi_list.clone();
        if !header_stmts.is_empty() { header_stmts.pop(); }
        let ternary = NodeAst::TernaryOp {
            target_var: var_true,
            condition: cond_str,
            true_val: val_true,
            false_val: val_false
        };
        Some(self.gabungkan_sequence(NodeAst::Block(header_stmts), ternary))
    }
    fn ambil_assignment_terakhir(&self, stmts: &[StatementIr]) -> Option<(String, String)> {
        for stmt in stmts.iter().rev() {
            if let OperasiIr::Mov = stmt.operation_code {
                let dest = self.format_operand_simpel(&stmt.operand_satu);
                let src = self.format_operand_simpel(&stmt.operand_dua);
                return Some((dest, src));
            }
        }
        None
    }
    fn cek_pola_short_circuit(
        &self,
        cfg: &ControlFlowGraph,
        header_block: &crate::analysis::cfg::BasicBlock,
        s_true: u64,
        s_false: u64
    ) -> Option<(String, u64, u64)> {
        if let Some(block_b) = cfg.blocks.get(&s_true) {
            if block_b.successors.len() == 2 {
                let b_true = block_b.successors[0];
                let b_false = block_b.successors[1];
                if b_false == s_false {
                    let cond_a = self.rekonstruksi_kondisi(&header_block.instruksi_list);
                    let cond_b = self.rekonstruksi_kondisi(&block_b.instruksi_list);
                    let combined = format!("({}) && ({})", cond_a, cond_b);
                    return Some((combined, b_true, s_false));
                }
            }
        }
        if let Some(block_b) = cfg.blocks.get(&s_false) {
            if block_b.successors.len() == 2 {
                let b_true = block_b.successors[0];
                let b_false = block_b.successors[1];
                if b_true == s_true {
                    let cond_a = self.rekonstruksi_kondisi(&header_block.instruksi_list);
                    let cond_b = self.rekonstruksi_kondisi(&block_b.instruksi_list);
                    let combined = format!("({}) || ({})", cond_a, cond_b);
                    return Some((combined, s_true, b_false));
                }
            }
        }
        None
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
        let loop_exit = self.cari_loop_exit(cfg, dom, header_id);
        self.loop_stack.push(LoopContext { 
            header_id, 
            merge_point: loop_exit 
        });
        let mut body_ast = NodeAst::Empty;
        let mut loop_succs = Vec::new();
        for &succ in &block.successors {
            if dom.cek_apakah_didominasi(succ, header_id) && Some(succ) != loop_exit {
                 loop_succs.push(succ);
            }
        }
        if !loop_succs.is_empty() {
            body_ast = self.analisis_region(cfg, dom, loop_succs[0], Some(header_id));
        }
        self.loop_stack.pop();
        let cond_str = self.rekonstruksi_kondisi(&block.instruksi_list);
        let loop_ast = NodeAst::WhileLoop {
            condition: cond_str, 
            body: Box::new(body_ast),
            is_do_while: false, 
        };
        if let Some(exit_node) = loop_exit {
            if Some(exit_node) != stop_at {
                self.visited.remove(&exit_node); 
                let next_ast = self.analisis_region(cfg, dom, exit_node, stop_at);
                return self.gabungkan_sequence(self.gabungkan_sequence(node_block, loop_ast), next_ast);
            }
        }
        self.gabungkan_sequence(node_block, loop_ast)
    }
    fn resolve_jump_target(&self, target_id: u64) -> NodeAst {
        for ctx in self.loop_stack.iter().rev() {
            if target_id == ctx.header_id {
                return NodeAst::Continue;
            }
            if let Some(exit) = ctx.merge_point {
                if target_id == exit {
                    return NodeAst::Break;
                }
            }
        }
        NodeAst::UnstructuredGoto(target_id)
    }
    fn strukturkan_switch(
        &mut self,
        cfg: &ControlFlowGraph,
        dom: &DominatorTree,
        block: &crate::analysis::cfg::BasicBlock,
        successors: &[u64],
        stop_at: Option<u64>,
        node_block: NodeAst
    ) -> NodeAst {
        let switch_var = self.analisa_variabel_switch(&block.instruksi_list);
        let mut target_map: HashMap<u64, Vec<u64>> = HashMap::new();
        for (idx, &succ) in successors.iter().enumerate() {
            target_map.entry(succ).or_default().push(idx as u64);
        }
        let mut cases_ast = Vec::new();
        let merge_point = dom.peta_post_idom.get(&block.id_block).cloned().or(stop_at);
        for (target, case_indices) in target_map {
            let case_body = self.analisis_region(cfg, dom, target, merge_point);
            cases_ast.push((case_indices, case_body));
        }
        cases_ast.sort_by(|a, b| a.0[0].cmp(&b.0[0]));
        let switch_ast = NodeAst::Switch {
            variable: switch_var,
            cases: cases_ast,
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
    fn normalisasi_irreducible_loops(&mut self, cfg: &mut ControlFlowGraph) {
        let max_splits = 50;
        let mut changed = true;
        while changed && self.split_count < max_splits {
            changed = false;
            let mut dom_temp = DominatorTree::new();
            dom_temp.hitung_dominators(cfg);
            if let Some((source, target)) = self.cari_kandidat_irreducible(cfg, &dom_temp) {
                self.lakukan_node_splitting(cfg, source, target);
                self.split_count += 1;
                changed = true;
            }
        }
    }
    fn cari_kandidat_irreducible(&self, cfg: &ControlFlowGraph, dom: &DominatorTree) -> Option<(u64, u64)> {
        let mut visited = HashSet::new();
        let mut stack = Vec::new();
        stack.push(cfg.entry_point);
        while let Some(node) = stack.pop() {
            if !visited.insert(node) { continue; }
            if let Some(block) = cfg.blocks.get(&node) {
                for &succ in &block.successors {
                    if visited.contains(&succ) {
                        if !dom.cek_apakah_didominasi(node, succ) {
                            return Some((node, succ));
                        }
                    } else {
                        stack.push(succ);
                    }
                }
            }
        }
        None
    }
    fn lakukan_node_splitting(&self, cfg: &mut ControlFlowGraph, source: u64, target: u64) {
        let new_id = cfg.generate_id_baru();
        cfg.buat_block_baru_dari_copy(target, new_id);
        cfg.redirect_edge(source, target, new_id);
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
    fn identifikasi_loops(&mut self, dom_tree: &DominatorTree) {
        self.loop_headers.clear();
        for &(latch, header) in &dom_tree.list_back_edges {
            self.loop_headers.entry(header).or_default().push(latch);
        }
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
                OperasiIr::Cmp | OperasiIr::Test | OperasiIr::FCmp => {
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
                _ => "cond".to_string() 
            }
        } else {
             match last_stmt.operation_code {
                OperasiIr::Jmp | OperasiIr::Ret => "true".to_string(), 
                _ => "flag_check".to_string()
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
            TipeOperand::FloatImmediate(val) => format!("{:.2}", val),
            TipeOperand::MemoryRef { base, offset } => format!("*({} + {})", base, offset),
            _ => "?".to_string(),
        }
    }
}