use std::collections::{HashSet, HashMap};
use crate::analysis::graph::cfg::ControlFlowGraph;
use crate::analysis::graph::dom::DominatorTree;
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};

#[derive(Debug, Clone)]
pub enum NodeAst {
    Block(Vec<StatementIr>),
    Sequence(Vec<NodeAst>),
    IfElse {
        kondisi: String,
        branch_true: Box<NodeAst>,
        branch_false: Option<Box<NodeAst>>,
    },
    TernaryOp {
        target_var: String,
        kondisi: String,
        nilai_true: String,
        nilai_false: String,
    },
    Switch {
        variabel: String,
        kasus: Vec<(Vec<u64>, NodeAst)>,
        default: Option<Box<NodeAst>>,
    },
    WhileLoop {
        kondisi: String,
        body: Box<NodeAst>,
        is_do_while: bool,
    },
    TryCatch {
        block_try: Box<NodeAst>,
        handler_catch: Box<NodeAst>,
        tipe_exception: String,
    },
    UnstructuredGoto(u64),
    Break,
    Continue,
    Empty,
}

#[derive(Debug, Clone)]
struct ContextLoop {
    id_header: u64,
    id_latch: Option<u64>, 
    titik_merge: Option<u64>,
    is_do_while: bool,
}

pub struct ControlFlowStructurer {
    node_terkunjungi: HashSet<u64>,
    peta_header_loop: HashMap<u64, Vec<u64>>, 
    counter_splitting: usize,
    stack_konteks_loop: Vec<ContextLoop>,
}

impl ControlFlowStructurer {
    pub fn new() -> Self {
        Self {
            node_terkunjungi: HashSet::new(),
            peta_header_loop: HashMap::new(),
            counter_splitting: 0,
            stack_konteks_loop: Vec::new(),
        }
    }
    pub fn bangun_tree_struktur(&mut self, cfg: &mut ControlFlowGraph) -> NodeAst {
        self.normalisasi_flow_irreducible(cfg);
        let mut dom_tree = DominatorTree::new();
        dom_tree.hitung_dominators(cfg);
        self.identifikasi_loop_alami(&dom_tree);
        self.analisis_region_canggih(cfg, &dom_tree, cfg.entry_point, None)
    }
    fn analisis_region_canggih(
        &mut self, 
        cfg: &ControlFlowGraph, 
        dom: &DominatorTree, 
        id_sekarang: u64, 
        stop_at: Option<u64>
    ) -> NodeAst {
        if Some(id_sekarang) == stop_at {
            return NodeAst::Empty;
        }
        if let Some(stmt_kontrol) = self.cek_target_jump_loop(id_sekarang) {
            return stmt_kontrol;
        }
        if self.node_terkunjungi.contains(&id_sekarang) {
            return NodeAst::UnstructuredGoto(id_sekarang);
        }
        self.node_terkunjungi.insert(id_sekarang);
        let data_block = match cfg.blocks.get(&id_sekarang) {
            Some(b) => b,
            None => return NodeAst::Empty,
        };
        if let Some(ast_try_catch) = self.coba_strukturkan_try_catch(cfg, dom, id_sekarang, stop_at) {
            return ast_try_catch;
        }
        if self.peta_header_loop.contains_key(&id_sekarang) {
            return self.strukturkan_loop_kompleks(cfg, dom, id_sekarang, stop_at);
        }
        let node_basic = NodeAst::Block(data_block.instruksi_list.clone());
        let list_suksesor = &data_block.successors;
        let ipd = dom.peta_post_idom.get(&id_sekarang).cloned();
        let titik_merge_region = self.kalkulasi_titik_merge(dom, ipd, stop_at);
        match list_suksesor.len() {
            0 => node_basic,
            1 => {
                let next_node = list_suksesor[0];
                let ast_sisa = self.analisis_region_canggih(cfg, dom, next_node, stop_at);
                self.gabungkan_node_sequence(node_basic, ast_sisa)
            },
            2 => {
                self.tangani_percabangan_dua_arah(cfg, dom, data_block, titik_merge_region, stop_at, node_basic)
            },
            _ => {
                self.strukturkan_switch_case(cfg, dom, data_block, list_suksesor, stop_at, node_basic)
            }
        }
    }
    fn kalkulasi_titik_merge(
        &self, 
        dom: &DominatorTree, 
        ipd_lokal: Option<u64>, 
        stop_parent: Option<u64>
    ) -> Option<u64> {
        match (ipd_lokal, stop_parent) {
            (Some(lokal), Some(parent)) => {
                if dom.cek_apakah_didominasi(parent, lokal) {
                    Some(lokal)
                } else {
                    Some(parent)
                }
            },
            (Some(lokal), None) => Some(lokal),
            (None, Some(parent)) => Some(parent),
            (None, None) => None
        }
    }
    fn coba_strukturkan_try_catch(
        &mut self,
        cfg: &ControlFlowGraph,
        dom: &DominatorTree,
        id_sekarang: u64,
        stop_at: Option<u64>
    ) -> Option<NodeAst> {
        let block = cfg.blocks.get(&id_sekarang)?;
        let mut is_potential_throw = false;
        for stmt in &block.instruksi_list {
            if let OperasiIr::Call = stmt.operation_code {
                if let TipeOperand::Register(nama) = &stmt.operand_satu {
                    if nama.contains("throw") || nama.contains("raise") {
                        is_potential_throw = true;
                    }
                }
            }
        }
        if is_potential_throw && block.successors.len() > 1 {
            let id_handler = block.successors[1]; 
            let id_normal = block.successors[0];
            let ast_try = self.analisis_region_canggih(cfg, dom, id_normal, Some(id_handler));
            self.node_terkunjungi.remove(&id_handler);
            let ast_catch = self.analisis_region_canggih(cfg, dom, id_handler, stop_at);
            return Some(NodeAst::TryCatch {
                block_try: Box::new(ast_try),
                handler_catch: Box::new(ast_catch),
                tipe_exception: "GenericException".to_string(),
            });
        }
        None
    }
    fn tangani_percabangan_dua_arah(
        &mut self,
        cfg: &ControlFlowGraph,
        dom: &DominatorTree,
        block: &crate::analysis::graph::cfg::BasicBlock,
        titik_merge: Option<u64>,
        stop_global: Option<u64>,
        node_prefix: NodeAst
    ) -> NodeAst {
        let s_true = block.successors[0];
        let s_false = block.successors[1];
        if let Some(ternary) = self.deteksi_pola_ternary(cfg, block, s_true, s_false, titik_merge) {
            let next_ast = if let Some(mp) = titik_merge {
                self.node_terkunjungi.remove(&mp); 
                self.analisis_region_canggih(cfg, dom, mp, stop_global)
            } else {
                NodeAst::Empty
            };
            return self.gabungkan_node_sequence(ternary, next_ast);
        }
        if let Some((kondisi_kompleks, entry_true, entry_false)) = self.deteksi_short_circuit(cfg, block, s_true, s_false) {
            let ast_true = self.analisis_region_canggih(cfg, dom, entry_true, titik_merge);
            let ast_false = self.analisis_region_canggih(cfg, dom, entry_false, titik_merge);
            let stmt_if = NodeAst::IfElse {
                kondisi: kondisi_kompleks,
                branch_true: Box::new(ast_true),
                branch_false: if self.cek_apakah_ast_kosong(&ast_false) { None } else { Some(Box::new(ast_false)) }
            };
            let next_ast = if let Some(mp) = titik_merge {
                self.node_terkunjungi.remove(&mp);
                self.analisis_region_canggih(cfg, dom, mp, stop_global)
            } else {
                NodeAst::Empty
            };
            return self.gabungkan_node_sequence(self.gabungkan_node_sequence(node_prefix, stmt_if), next_ast);
        }
        let str_kondisi = self.rekonstruksi_kondisi_branch(&block.instruksi_list);
        let ast_true = self.analisis_region_canggih(cfg, dom, s_true, titik_merge);
        let ast_false = self.analisis_region_canggih(cfg, dom, s_false, titik_merge);
        let stmt_if = NodeAst::IfElse {
            kondisi: str_kondisi,
            branch_true: Box::new(ast_true),
            branch_false: if self.cek_apakah_ast_kosong(&ast_false) { None } else { Some(Box::new(ast_false)) }
        };
        let next_ast = if let Some(mp) = titik_merge {
            self.node_terkunjungi.remove(&mp);
            self.analisis_region_canggih(cfg, dom, mp, stop_global)
        } else {
            NodeAst::Empty
        };
        self.gabungkan_node_sequence(self.gabungkan_node_sequence(node_prefix, stmt_if), next_ast)
    }

    fn strukturkan_loop_kompleks(
        &mut self, 
        cfg: &ControlFlowGraph, 
        dom: &DominatorTree, 
        id_header: u64, 
        stop_at: Option<u64>
    ) -> NodeAst {
        let block = cfg.blocks.get(&id_header).unwrap();
        let node_prefix = NodeAst::Block(block.instruksi_list.clone());
        let node_exit_loop = self.cari_node_exit_loop(cfg, dom, id_header);
        let is_do_while = self.analisa_tipe_do_while(cfg, id_header);
        let latch_opt = self.ambil_latch_utama(id_header);
        self.stack_konteks_loop.push(ContextLoop { 
            id_header, 
            id_latch: latch_opt,
            titik_merge: node_exit_loop,
            is_do_while 
        });
        let mut nodes_body = Vec::new();
        let mut loop_entries = Vec::new();
        for &succ in &block.successors {
            if Some(succ) != node_exit_loop {
                 loop_entries.push(succ);
            }
        }
        if !loop_entries.is_empty() {
            let body_ast = self.analisis_region_canggih(cfg, dom, loop_entries[0], Some(id_header));
            nodes_body.push(body_ast);
        }
        self.stack_konteks_loop.pop();
        let str_kondisi = if is_do_while {
            if let Some(latch_id) = latch_opt {
                 if let Some(block_latch) = cfg.blocks.get(&latch_id) {
                     self.rekonstruksi_kondisi_branch(&block_latch.instruksi_list)
                 } else {
                     "true".to_string()
                 }
            } else {
                "true".to_string()
            }
        } else {
            self.rekonstruksi_kondisi_branch(&block.instruksi_list)
        };
        let combined_body = if nodes_body.is_empty() { NodeAst::Empty } else { NodeAst::Sequence(nodes_body) };
        let ast_loop = NodeAst::WhileLoop {
            kondisi: str_kondisi, 
            body: Box::new(combined_body),
            is_do_while, 
        };
        if let Some(exit_node) = node_exit_loop {
            if Some(exit_node) != stop_at {
                self.node_terkunjungi.remove(&exit_node); 
                let next_ast = self.analisis_region_canggih(cfg, dom, exit_node, stop_at);
                return self.gabungkan_node_sequence(self.gabungkan_node_sequence(node_prefix, ast_loop), next_ast);
            }
        }
        self.gabungkan_node_sequence(node_prefix, ast_loop)
    }
    fn analisa_tipe_do_while(&self, cfg: &ControlFlowGraph, id_header: u64) -> bool {
        if let Some(latches) = self.peta_header_loop.get(&id_header) {
            for &latch in latches {
                if let Some(block_latch) = cfg.blocks.get(&latch) {
                    if block_latch.successors.len() == 2 {
                        if block_latch.successors.contains(&id_header) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
    fn ambil_latch_utama(&self, id_header: u64) -> Option<u64> {
        self.peta_header_loop.get(&id_header).and_then(|v| v.first()).cloned()
    }
    fn strukturkan_switch_case(
        &mut self,
        cfg: &ControlFlowGraph,
        dom: &DominatorTree,
        block: &crate::analysis::graph::cfg::BasicBlock,
        suksesor: &[u64],
        stop_at: Option<u64>,
        node_prefix: NodeAst
    ) -> NodeAst {
        let var_switch = self.analisa_variabel_switch(&block.instruksi_list);
        let mut peta_target: HashMap<u64, Vec<u64>> = HashMap::new();
        for (idx, &succ) in suksesor.iter().enumerate() {
            peta_target.entry(succ).or_default().push(idx as u64);
        }
        let mut list_kasus_ast = Vec::new();
        let titik_merge = dom.peta_post_idom.get(&block.id_block).cloned().or(stop_at);
        for (target, index_kasus) in peta_target {
            let body_kasus = self.analisis_region_canggih(cfg, dom, target, titik_merge);
            list_kasus_ast.push((index_kasus, body_kasus));
        }
        list_kasus_ast.sort_by(|a, b| a.0.first().unwrap_or(&0).cmp(b.0.first().unwrap_or(&0)));
        let ast_switch = NodeAst::Switch {
            variabel: var_switch,
            kasus: list_kasus_ast,
            default: None, 
        };
        if let Some(mp) = titik_merge {
            self.node_terkunjungi.remove(&mp);
            let next_ast = self.analisis_region_canggih(cfg, dom, mp, stop_at);
            self.gabungkan_node_sequence(self.gabungkan_node_sequence(node_prefix, ast_switch), next_ast)
        } else {
            self.gabungkan_node_sequence(node_prefix, ast_switch)
        }
    }
    fn cek_target_jump_loop(&self, target_id: u64) -> Option<NodeAst> {
        for ctx in self.stack_konteks_loop.iter().rev() {
            if target_id == ctx.id_header {
                if !ctx.is_do_while {
                    return Some(NodeAst::Continue);
                }
            }
            if let Some(latch) = ctx.id_latch {
                if target_id == latch {
                    if ctx.is_do_while {
                        return Some(NodeAst::Continue);
                    }
                }
            }
            if let Some(exit) = ctx.titik_merge {
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
        block_header: &crate::analysis::graph::cfg::BasicBlock, 
        node_true: u64, 
        node_false: u64,
        titik_merge: Option<u64>
    ) -> Option<NodeAst> {
        let mp = titik_merge?;
        let block_true = cfg.blocks.get(&node_true)?;
        let block_false = cfg.blocks.get(&node_false)?;
        if block_true.successors.len() != 1 || block_true.successors[0] != mp { return None; }
        if block_false.successors.len() != 1 || block_false.successors[0] != mp { return None; }
        let (var_true, val_true) = self.ambil_assignment_terakhir(&block_true.instruksi_list)?;
        let (var_false, val_false) = self.ambil_assignment_terakhir(&block_false.instruksi_list)?;
        if var_true != var_false { return None; }
        let str_kondisi = self.rekonstruksi_kondisi_branch(&block_header.instruksi_list);
        let mut stmts_header = block_header.instruksi_list.clone();
        if !stmts_header.is_empty() { stmts_header.pop(); }
        let ternary = NodeAst::TernaryOp {
            target_var: var_true,
            kondisi: str_kondisi,
            nilai_true: val_true,
            nilai_false: val_false
        };
        Some(self.gabungkan_node_sequence(NodeAst::Block(stmts_header), ternary))
    }
    fn deteksi_short_circuit(
        &self,
        cfg: &ControlFlowGraph,
        block_header: &crate::analysis::graph::cfg::BasicBlock,
        s_true: u64,
        s_false: u64
    ) -> Option<(String, u64, u64)> {
        if let Some(block_b) = cfg.blocks.get(&s_true) {
            if block_b.successors.len() == 2 {
                let b_true = block_b.successors[0];
                let b_false = block_b.successors[1];
                if b_false == s_false {
                    let cond_a = self.rekonstruksi_kondisi_branch(&block_header.instruksi_list);
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
                    let cond_a = self.rekonstruksi_kondisi_branch(&block_header.instruksi_list);
                    let cond_b = self.rekonstruksi_kondisi_branch(&block_b.instruksi_list);
                    return Some((format!("({}) || ({})", cond_a, cond_b), s_true, b_false));
                }
            }
        }
        None
    }
    fn normalisasi_flow_irreducible(&mut self, cfg: &mut ControlFlowGraph) {
        let batas_maksimal_split = 100; 
        let mut ada_perubahan = true;
        while ada_perubahan && self.counter_splitting < batas_maksimal_split {
            ada_perubahan = false;
            let mut dom_sementara = DominatorTree::new();
            dom_sementara.hitung_dominators(cfg);
            if let Some((sumber, target)) = self.temukan_kandidat_irreducible(cfg, &dom_sementara) {
                self.lakukan_splitting_node(cfg, sumber, target);
                self.counter_splitting += 1;
                ada_perubahan = true;
            }
        }
    }
    fn temukan_kandidat_irreducible(&self, cfg: &ControlFlowGraph, dom: &DominatorTree) -> Option<(u64, u64)> {
        let mut visited = HashSet::new();
        let mut stack = Vec::new();
        stack.push(cfg.entry_point);
        while let Some(node) = stack.pop() {
            if !visited.insert(node) { continue; }
            if let Some(block) = cfg.blocks.get(&node) {
                for &succ in &block.successors {
                    if visited.contains(&succ) {
                        if !dom.cek_apakah_didominasi(node, succ) {
                            if let Some(block_succ) = cfg.blocks.get(&succ) {
                                if block_succ.predecessors.len() > 1 {
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
    fn lakukan_splitting_node(&self, cfg: &mut ControlFlowGraph, sumber: u64, target: u64) {
        let id_baru = cfg.generate_id_baru();
        cfg.buat_block_baru_dari_copy(target, id_baru);
        cfg.redirect_edge(sumber, target, id_baru);
    }
    fn identifikasi_loop_alami(&mut self, dom_tree: &DominatorTree) {
        self.peta_header_loop.clear();
        for &(latch, header) in &dom_tree.list_back_edges {
            self.peta_header_loop.entry(header).or_default().push(latch);
        }
    }
    fn cari_node_exit_loop(&self, cfg: &ControlFlowGraph, dom: &DominatorTree, header: u64) -> Option<u64> {
        if let Some(block) = cfg.blocks.get(&header) {
            for &succ in &block.successors {
                if !dom.cek_apakah_didominasi(succ, header) {
                    return Some(succ);
                }
            }
        }
        dom.peta_post_idom.get(&header).cloned()
    }
    fn gabungkan_node_sequence(&self, first: NodeAst, second: NodeAst) -> NodeAst {
        match (first, second) {
            (NodeAst::Empty, b) => b,
            (a, NodeAst::Empty) => a,
            (NodeAst::Sequence(mut vec_a), NodeAst::Sequence(vec_b)) => {
                vec_a.extend(vec_b);
                NodeAst::Sequence(vec_a)
            },
            (NodeAst::Sequence(mut vec_a), b) => {
                vec_a.push(b);
                NodeAst::Sequence(vec_a)
            },
            (a, NodeAst::Sequence(mut vec_b)) => {
                vec_b.insert(0, a);
                NodeAst::Sequence(vec_b)
            },
            (a, b) => NodeAst::Sequence(vec![a, b]),
        }
    }
    fn cek_apakah_ast_kosong(&self, ast: &NodeAst) -> bool {
        matches!(ast, NodeAst::Empty)
    }
    fn rekonstruksi_kondisi_branch(&self, stmts: &[StatementIr]) -> String {
        if stmts.is_empty() { return "true".to_string(); }
        let last_stmt = stmts.last().unwrap();
        let mut stmt_cmp_opt = None;
        for i in (0..stmts.len()-1).rev() {
            match stmts[i].operation_code {
                OperasiIr::Cmp | OperasiIr::Test | OperasiIr::FCmp => {
                    stmt_cmp_opt = Some(&stmts[i]);
                    break;
                },
                _ => {}
            }
        }
        if let Some(stmt_cmp) = stmt_cmp_opt {
            let op1 = self.format_operand_readable(&stmt_cmp.operand_satu);
            let op2 = self.format_operand_readable(&stmt_cmp.operand_dua);
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