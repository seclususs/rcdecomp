use std::collections::{HashSet, HashMap};
use crate::analysis::graph::cfg::ControlFlowGraph;
use crate::analysis::graph::dom::DominatorTree;
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
    latch_id: Option<u64>, 
    merge_point: Option<u64>,
    is_do_while: bool,
}

pub struct ControlFlowStructurer {
    visited_nodes: HashSet<u64>,
    loop_headers: HashMap<u64, Vec<u64>>, 
    split_counter: usize,
    loop_stack_context: Vec<LoopContext>,
}

impl ControlFlowStructurer {
    pub fn new() -> Self {
        Self {
            visited_nodes: HashSet::new(),
            loop_headers: HashMap::new(),
            split_counter: 0,
            loop_stack_context: Vec::new(),
        }
    }
    pub fn bangun_tree_struktur(&mut self, cfg: &mut ControlFlowGraph) -> NodeAst {
        self.normalisasi_irreducible_loops(cfg);
        let mut dom_tree = DominatorTree::new();
        dom_tree.hitung_dominators(cfg);
        self.identifikasi_natural_loops(&dom_tree);
        self.analisis_region_refined(cfg, &dom_tree, cfg.entry_point, None)
    }
    fn analisis_region_refined(
        &mut self, 
        cfg: &ControlFlowGraph, 
        dom: &DominatorTree, 
        current_id: u64, 
        stop_at: Option<u64>
    ) -> NodeAst {
        if Some(current_id) == stop_at {
            return NodeAst::Empty;
        }
        if let Some(control_stmt) = self.cek_jump_target_loop(current_id) {
            return control_stmt;
        }
        if self.visited_nodes.contains(&current_id) {
            return NodeAst::UnstructuredGoto(current_id);
        }
        self.visited_nodes.insert(current_id);
        let block_data = match cfg.blocks.get(&current_id) {
            Some(b) => b,
            None => return NodeAst::Empty,
        };
        if self.loop_headers.contains_key(&current_id) {
            return self.strukturkan_loop_complex(cfg, dom, current_id, stop_at);
        }
        let node_basic_block = NodeAst::Block(block_data.instruksi_list.clone());
        let successors = &block_data.successors;
        let ipd = dom.peta_post_idom.get(&current_id).cloned();
        let region_merge_point = self.hitung_region_merge_point(dom, ipd, stop_at);
        match successors.len() {
            0 => node_basic_block,
            1 => {
                let next_node = successors[0];
                let rest_ast = self.analisis_region_refined(cfg, dom, next_node, stop_at);
                self.gabungkan_sequence_nodes(node_basic_block, rest_ast)
            },
            2 => {
                self.handle_two_way_branch(cfg, dom, block_data, region_merge_point, stop_at, node_basic_block)
            },
            _ => {
                self.strukturkan_switch_case(cfg, dom, block_data, successors, stop_at, node_basic_block)
            }
        }
    }
    fn hitung_region_merge_point(
        &self, 
        dom: &DominatorTree, 
        ipd: Option<u64>, 
        parent_stop: Option<u64>
    ) -> Option<u64> {
        match (ipd, parent_stop) {
            (Some(local), Some(parent)) => {
                if dom.cek_apakah_didominasi(parent, local) {
                    Some(local)
                } else {
                    Some(parent)
                }
            },
            (Some(local), None) => Some(local),
            (None, Some(parent)) => Some(parent),
            (None, None) => None
        }
    }
    fn handle_two_way_branch(
        &mut self,
        cfg: &ControlFlowGraph,
        dom: &DominatorTree,
        block: &crate::analysis::graph::cfg::BasicBlock,
        merge_point: Option<u64>,
        global_stop: Option<u64>,
        prefix_node: NodeAst
    ) -> NodeAst {
        let s_true = block.successors[0];
        let s_false = block.successors[1];
        if let Some(ternary) = self.deteksi_pola_ternary(cfg, block, s_true, s_false, merge_point) {
            let next_ast = if let Some(mp) = merge_point {
                self.visited_nodes.remove(&mp); 
                self.analisis_region_refined(cfg, dom, mp, global_stop)
            } else {
                NodeAst::Empty
            };
            return self.gabungkan_sequence_nodes(ternary, next_ast);
        }
        if let Some((cond_complex, entry_true, entry_false)) = self.deteksi_short_circuit(cfg, block, s_true, s_false) {
            let true_ast = self.analisis_region_refined(cfg, dom, entry_true, merge_point);
            let false_ast = self.analisis_region_refined(cfg, dom, entry_false, merge_point);
            let if_stmt = NodeAst::IfElse {
                condition: cond_complex,
                true_branch: Box::new(true_ast),
                false_branch: if self.is_ast_kosong(&false_ast) { None } else { Some(Box::new(false_ast)) }
            };
            let next_ast = if let Some(mp) = merge_point {
                self.visited_nodes.remove(&mp);
                self.analisis_region_refined(cfg, dom, mp, global_stop)
            } else {
                NodeAst::Empty
            };
            return self.gabungkan_sequence_nodes(self.gabungkan_sequence_nodes(prefix_node, if_stmt), next_ast);
        }
        let cond_str = self.rekonstruksi_kondisi_branch(&block.instruksi_list);
        let true_ast = self.analisis_region_refined(cfg, dom, s_true, merge_point);
        let false_ast = self.analisis_region_refined(cfg, dom, s_false, merge_point);
        let if_stmt = NodeAst::IfElse {
            condition: cond_str,
            true_branch: Box::new(true_ast),
            false_branch: if self.is_ast_kosong(&false_ast) { None } else { Some(Box::new(false_ast)) }
        };
        let next_ast = if let Some(mp) = merge_point {
            self.visited_nodes.remove(&mp);
            self.analisis_region_refined(cfg, dom, mp, global_stop)
        } else {
            NodeAst::Empty
        };
        self.gabungkan_sequence_nodes(self.gabungkan_sequence_nodes(prefix_node, if_stmt), next_ast)
    }
    fn strukturkan_loop_complex(
        &mut self, 
        cfg: &ControlFlowGraph, 
        dom: &DominatorTree, 
        header_id: u64, 
        stop_at: Option<u64>
    ) -> NodeAst {
        let block = cfg.blocks.get(&header_id).unwrap();
        let prefix_node = NodeAst::Block(block.instruksi_list.clone());
        let loop_exit_node = self.cari_loop_exit_node(cfg, dom, header_id);
        let is_do_while = self.analisa_tipe_do_while(cfg, header_id);
        let latch_opt = self.ambil_latch_utama(header_id);
        self.loop_stack_context.push(LoopContext { 
            header_id, 
            latch_id: latch_opt,
            merge_point: loop_exit_node,
            is_do_while 
        });
        let mut body_nodes = Vec::new();
        let mut loop_entries = Vec::new();
        for &succ in &block.successors {
            if Some(succ) != loop_exit_node {
                 loop_entries.push(succ);
            }
        }
        if !loop_entries.is_empty() {
            let body_ast = self.analisis_region_refined(cfg, dom, loop_entries[0], Some(header_id));
            body_nodes.push(body_ast);
        }
        self.loop_stack_context.pop();
        let cond_str = if is_do_while {
            if let Some(latch_id) = latch_opt {
                 if let Some(latch_block) = cfg.blocks.get(&latch_id) {
                     self.rekonstruksi_kondisi_branch(&latch_block.instruksi_list)
                 } else {
                     "true".to_string()
                 }
            } else {
                "true".to_string()
            }
        } else {
            self.rekonstruksi_kondisi_branch(&block.instruksi_list)
        };
        let combined_body = if body_nodes.is_empty() { NodeAst::Empty } else { NodeAst::Sequence(body_nodes) };
        let loop_ast = NodeAst::WhileLoop {
            condition: cond_str, 
            body: Box::new(combined_body),
            is_do_while, 
        };
        if let Some(exit_node) = loop_exit_node {
            if Some(exit_node) != stop_at {
                self.visited_nodes.remove(&exit_node); 
                let next_ast = self.analisis_region_refined(cfg, dom, exit_node, stop_at);
                return self.gabungkan_sequence_nodes(self.gabungkan_sequence_nodes(prefix_node, loop_ast), next_ast);
            }
        }
        self.gabungkan_sequence_nodes(prefix_node, loop_ast)
    }
    fn analisa_tipe_do_while(&self, cfg: &ControlFlowGraph, header_id: u64) -> bool {
        if let Some(latches) = self.loop_headers.get(&header_id) {
            for &latch in latches {
                if let Some(latch_block) = cfg.blocks.get(&latch) {
                    if latch_block.successors.len() == 2 {
                        if latch_block.successors.contains(&header_id) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
    fn ambil_latch_utama(&self, header_id: u64) -> Option<u64> {
        self.loop_headers.get(&header_id).and_then(|v| v.first()).cloned()
    }
    fn strukturkan_switch_case(
        &mut self,
        cfg: &ControlFlowGraph,
        dom: &DominatorTree,
        block: &crate::analysis::graph::cfg::BasicBlock,
        successors: &[u64],
        stop_at: Option<u64>,
        prefix_node: NodeAst
    ) -> NodeAst {
        let switch_var = self.analisa_variabel_switch(&block.instruksi_list);
        let mut target_map: HashMap<u64, Vec<u64>> = HashMap::new();
        for (idx, &succ) in successors.iter().enumerate() {
            target_map.entry(succ).or_default().push(idx as u64);
        }
        let mut cases_ast = Vec::new();
        let merge_point = dom.peta_post_idom.get(&block.id_block).cloned().or(stop_at);
        for (target, case_indices) in target_map {
            let case_body = self.analisis_region_refined(cfg, dom, target, merge_point);
            cases_ast.push((case_indices, case_body));
        }
        cases_ast.sort_by(|a, b| a.0.first().unwrap_or(&0).cmp(b.0.first().unwrap_or(&0)));
        let switch_ast = NodeAst::Switch {
            variable: switch_var,
            cases: cases_ast,
            default: None, 
        };
        if let Some(mp) = merge_point {
            self.visited_nodes.remove(&mp);
            let next_ast = self.analisis_region_refined(cfg, dom, mp, stop_at);
            self.gabungkan_sequence_nodes(self.gabungkan_sequence_nodes(prefix_node, switch_ast), next_ast)
        } else {
            self.gabungkan_sequence_nodes(prefix_node, switch_ast)
        }
    }
    fn cek_jump_target_loop(&self, target_id: u64) -> Option<NodeAst> {
        for ctx in self.loop_stack_context.iter().rev() {
            if target_id == ctx.header_id {
                if !ctx.is_do_while {
                    return Some(NodeAst::Continue);
                }
            }
            if let Some(latch) = ctx.latch_id {
                if target_id == latch {
                    if ctx.is_do_while {
                        return Some(NodeAst::Continue);
                    }
                }
            }
            if let Some(exit) = ctx.merge_point {
                if target_id == exit {
                    return Some(NodeAst::Break);
                }
            }
        }
        None
    }
    fn deteksi_pola_ternary(
        &self, 
        cfg: &ControlFlowGraph,
        header_block: &crate::analysis::graph::cfg::BasicBlock, 
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
        let cond_str = self.rekonstruksi_kondisi_branch(&header_block.instruksi_list);
        let mut header_stmts = header_block.instruksi_list.clone();
        if !header_stmts.is_empty() { header_stmts.pop(); }
        let ternary = NodeAst::TernaryOp {
            target_var: var_true,
            condition: cond_str,
            true_val: val_true,
            false_val: val_false
        };
        Some(self.gabungkan_sequence_nodes(NodeAst::Block(header_stmts), ternary))
    }
    fn deteksi_short_circuit(
        &self,
        cfg: &ControlFlowGraph,
        header_block: &crate::analysis::graph::cfg::BasicBlock,
        s_true: u64,
        s_false: u64
    ) -> Option<(String, u64, u64)> {
        if let Some(block_b) = cfg.blocks.get(&s_true) {
            if block_b.successors.len() == 2 {
                let b_true = block_b.successors[0];
                let b_false = block_b.successors[1];
                if b_false == s_false {
                    let cond_a = self.rekonstruksi_kondisi_branch(&header_block.instruksi_list);
                    let cond_b = self.rekonstruksi_kondisi_branch(&block_b.instruksi_list);
                    return Some((format!("({}) && ({})", cond_a, cond_b), b_true, s_false));
                }
            }
        }
        if let Some(block_b) = cfg.blocks.get(&s_false) {
            if block_b.successors.len() == 2 {
                let b_true = block_b.successors[0];
                let b_false = block_b.successors[1];
                if b_true == s_true {
                    let cond_a = self.rekonstruksi_kondisi_branch(&header_block.instruksi_list);
                    let cond_b = self.rekonstruksi_kondisi_branch(&block_b.instruksi_list);
                    return Some((format!("({}) || ({})", cond_a, cond_b), s_true, b_false));
                }
            }
        }
        None
    }
    fn normalisasi_irreducible_loops(&mut self, cfg: &mut ControlFlowGraph) {
        let max_splits = 100; 
        let mut changed = true;
        while changed && self.split_counter < max_splits {
            changed = false;
            let mut dom_temp = DominatorTree::new();
            dom_temp.hitung_dominators(cfg);
            if let Some((source, target)) = self.cari_kandidat_irreducible(cfg, &dom_temp) {
                self.lakukan_node_splitting(cfg, source, target);
                self.split_counter += 1;
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
                            if let Some(succ_block) = cfg.blocks.get(&succ) {
                                if succ_block.predecessors.len() > 1 {
                                    return Some((node, succ));
                                }
                            }
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
    fn identifikasi_natural_loops(&mut self, dom_tree: &DominatorTree) {
        self.loop_headers.clear();
        for &(latch, header) in &dom_tree.list_back_edges {
            self.loop_headers.entry(header).or_default().push(latch);
        }
    }
    fn cari_loop_exit_node(&self, cfg: &ControlFlowGraph, dom: &DominatorTree, header: u64) -> Option<u64> {
        if let Some(block) = cfg.blocks.get(&header) {
            for &succ in &block.successors {
                if !dom.cek_apakah_didominasi(succ, header) {
                    return Some(succ);
                }
            }
        }
        dom.peta_post_idom.get(&header).cloned()
    }
    fn gabungkan_sequence_nodes(&self, first: NodeAst, second: NodeAst) -> NodeAst {
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
    fn is_ast_kosong(&self, ast: &NodeAst) -> bool {
        matches!(ast, NodeAst::Empty)
    }
    fn rekonstruksi_kondisi_branch(&self, stmts: &[StatementIr]) -> String {
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
            let op1 = self.format_operand_readable(&cmp_stmt.operand_satu);
            let op2 = self.format_operand_readable(&cmp_stmt.operand_dua);
            match last_stmt.operation_code {
                OperasiIr::Je => format!("{} == {}", op1, op2),
                OperasiIr::Jne => format!("{} != {}", op1, op2),
                OperasiIr::Jg => format!("{} > {}", op1, op2),
                OperasiIr::Jge => format!("{} >= {}", op1, op2),
                OperasiIr::Jl => format!("{} < {}", op1, op2),
                OperasiIr::Jle => format!("{} <= {}", op1, op2),
                _ => "cond_unknown".to_string() 
            }
        } else {
             match last_stmt.operation_code {
                OperasiIr::Jmp | OperasiIr::Ret => "true".to_string(), 
                _ => "flag_status".to_string()
             }
        }
    }
    fn ambil_assignment_terakhir(&self, stmts: &[StatementIr]) -> Option<(String, String)> {
        for stmt in stmts.iter().rev() {
            if let OperasiIr::Mov = stmt.operation_code {
                let dest = self.format_operand_readable(&stmt.operand_satu);
                let src = self.format_operand_readable(&stmt.operand_dua);
                return Some((dest, src));
            }
        }
        None
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
    fn format_operand_readable(&self, op: &TipeOperand) -> String {
        match op {
            TipeOperand::Register(r) => r.clone(),
            TipeOperand::SsaVariable(name, ver) => format!("{}_{}", name, ver),
            TipeOperand::Immediate(val) => format!("0x{:x}", val),
            TipeOperand::FloatImmediate(val) => format!("{:.2}", val),
            TipeOperand::MemoryRef { base, offset } => format!("*({} + 0x{:x})", base, offset),
            _ => "?".to_string(),
        }
    }
}