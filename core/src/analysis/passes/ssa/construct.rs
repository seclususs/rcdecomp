use std::collections::{HashMap, HashSet, VecDeque};
use crate::analysis::graph::cfg::ControlFlowGraph;
use crate::analysis::graph::dom::DominatorTree;
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};
use crate::analysis::passes::alias::{AliasAnalyzer, MemoryRegion};
use super::opt_sccp::SccpSolver;
use super::opt_adce::AdceSolver;
use log::info;

pub struct SsaTransformer {
    stack_versi: HashMap<String, Vec<usize>>,
    counter_versi: HashMap<String, usize>,
    peta_alias_register: HashMap<String, String>,
    alias_analyzer: AliasAnalyzer,
}

impl SsaTransformer {
    pub fn new() -> Self {
        Self {
            stack_versi: HashMap::new(),
            counter_versi: HashMap::new(),
            peta_alias_register: Self::inisialisasi_alias_map(),
            alias_analyzer: AliasAnalyzer::new(),
        }
    }
    fn inisialisasi_alias_map() -> HashMap<String, String> {
        let mut m = HashMap::new();
        let gprs = vec![
            ("rax", vec!["eax", "ax", "al", "ah"]),
            ("rbx", vec!["ebx", "bx", "bl", "bh"]),
            ("rcx", vec!["ecx", "cx", "cl", "ch"]),
            ("rdx", vec!["edx", "dx", "dl", "dh"]),
            ("rsi", vec!["esi", "si", "sil"]),
            ("rdi", vec!["edi", "di", "dil"]),
            ("rbp", vec!["ebp", "bp", "bpl"]),
            ("rsp", vec!["esp", "sp", "spl"]),
            ("r8", vec!["r8d", "r8w", "r8b"]),
            ("r9", vec!["r9d", "r9w", "r9b"]),
            ("r10", vec!["r10d", "r10w", "r10b"]),
            ("r11", vec!["r11d", "r11w", "r11b"]),
            ("r12", vec!["r12d", "r12w", "r12b"]),
            ("r13", vec!["r13d", "r13w", "r13b"]),
            ("r14", vec!["r14d", "r14w", "r14b"]),
            ("r15", vec!["r15d", "r15w", "r15b"]),
        ];
        for (parent, children) in gprs {
            for child in children {
                m.insert(child.to_string(), parent.to_string());
            }
        }
        m
    }
    fn dapatkan_nama_kanonik(&self, reg: &str) -> String {
        self.peta_alias_register.get(reg).cloned().unwrap_or_else(|| reg.to_string())
    }
    pub fn lakukan_transformasi_ssa(&mut self, cfg: &mut ControlFlowGraph, dom_tree: &DominatorTree) {
        let mut all_stmts = Vec::new();
        for block in cfg.blocks.values() {
            all_stmts.extend(block.instruksi_list.clone());
        }
        self.alias_analyzer.analisis_pointer_lanjutan(&all_stmts, "rbp");
        self.sisipkan_phi_nodes(cfg, dom_tree);
        self.inisialisasi_stack_variabel(cfg);
        self.rename_variabel(cfg, dom_tree, cfg.entry_point);
    }
    pub fn optimasi_propagasi_konstanta(&self, cfg: &mut ControlFlowGraph) {
        info!("Menjalankan SCCP (Sparse Conditional Constant Propagation)...");
        let mut solver = SccpSolver::new();
        solver.jalankan_sccp(cfg);
        solver.terapkan_hasil(cfg);
    }
    pub fn optimasi_dead_code(&self, cfg: &mut ControlFlowGraph) {
        info!("Menjalankan ADCE (Aggressive Dead Code Elimination)...");
        let mut solver = AdceSolver::new();
        solver.jalankan_adce(cfg);
    }
    fn sisipkan_phi_nodes(&self, cfg: &mut ControlFlowGraph, dom_tree: &DominatorTree) {
        let mut global_vars = HashSet::new();
        let mut blocks_defining_var: HashMap<String, HashSet<u64>> = HashMap::new();
        for (block_id, block) in &cfg.blocks {
            let mut var_kill = HashSet::new();
            for stmt in &block.instruksi_list {
                if let TipeOperand::Register(r) = &stmt.operand_satu {
                    let canon = self.dapatkan_nama_kanonik(r);
                    var_kill.insert(canon.clone());
                    blocks_defining_var.entry(canon).or_default().insert(*block_id);
                }
                if let TipeOperand::MemoryRef { .. } = &stmt.operand_satu {
                    if let Some(mem_key) = self.generate_memory_key(&stmt.operand_satu) {
                        var_kill.insert(mem_key.clone());
                        blocks_defining_var.entry(mem_key).or_default().insert(*block_id);
                    }
                }
            }
            for stmt in &block.instruksi_list {
                 if let TipeOperand::Register(r) = &stmt.operand_dua {
                     let canon = self.dapatkan_nama_kanonik(r);
                     if !var_kill.contains(&canon) { global_vars.insert(canon); }
                 }
                 if let TipeOperand::MemoryRef { .. } = &stmt.operand_dua {
                     if let Some(mem_key) = self.generate_memory_key(&stmt.operand_dua) {
                         if !var_kill.contains(&mem_key) { global_vars.insert(mem_key); }
                     }
                 }
            }
        }
        for var in global_vars {
            let mut work_list: VecDeque<u64> = blocks_defining_var.get(&var).unwrap_or(&HashSet::new()).iter().cloned().collect();
            let mut has_phi = HashSet::new();
            while let Some(block_idx) = work_list.pop_front() {
                if let Some(frontier) = dom_tree.frontier_dominasi.get(&block_idx) {
                    for &frontier_node in frontier {
                        if !has_phi.contains(&frontier_node) {
                            if let Some(block) = cfg.blocks.get_mut(&frontier_node) {
                                let pred_count = block.predecessors.len();
                                let mut phi_operands = Vec::with_capacity(pred_count);
                                for _ in 0..pred_count { phi_operands.push(TipeOperand::None); }
                                let mut phi_stmt = StatementIr::new(
                                    0,
                                    OperasiIr::Phi, 
                                    TipeOperand::Register(var.clone()), 
                                    TipeOperand::None
                                );
                                phi_stmt.operand_tambahan = phi_operands;
                                block.instruksi_list.insert(0, phi_stmt);
                            }
                            has_phi.insert(frontier_node);
                            if !blocks_defining_var.get(&var).map_or(false, |s| s.contains(&frontier_node)) {
                                work_list.push_back(frontier_node);
                            }
                        }
                    }
                }
            }
        }
    }
    fn inisialisasi_stack_variabel(&mut self, cfg: &ControlFlowGraph) {
        let mut vars = HashSet::new();
        for block in cfg.blocks.values() {
            for stmt in &block.instruksi_list {
                if let TipeOperand::Register(r) = &stmt.operand_satu {
                    vars.insert(self.dapatkan_nama_kanonik(r));
                }
                if let Some(key) = self.generate_memory_key(&stmt.operand_satu) {
                    vars.insert(key);
                }
            }
        }
        for var in vars {
            if !self.stack_versi.contains_key(&var) {
                self.stack_versi.insert(var.clone(), vec![0]);
                self.counter_versi.insert(var, 1);
            }
        }
    }
    fn rename_variabel(&mut self, cfg: &mut ControlFlowGraph, dom_tree: &DominatorTree, current_block: u64) {
        let mut push_count: HashMap<String, usize> = HashMap::new();
        if let Some(block) = cfg.blocks.get_mut(&current_block) {
            for stmt in &mut block.instruksi_list {
                if stmt.operation_code != OperasiIr::Phi {
                    self.proses_operand_use(&mut stmt.operand_dua);
                    let mut read_src = false;
                    match stmt.operation_code {
                         OperasiIr::Add | OperasiIr::Sub | OperasiIr::FAdd | OperasiIr::VecAdd | 
                         OperasiIr::And | OperasiIr::Or | OperasiIr::Xor | OperasiIr::Imul => {
                             if matches!(stmt.operand_satu, TipeOperand::Register(_)) { read_src = true; }
                        }
                        _ => {}
                    }
                    if read_src { self.proses_operand_use(&mut stmt.operand_satu); }
                    if stmt.operation_code == OperasiIr::Call {
                         for arg in &mut stmt.operand_tambahan {
                             self.proses_operand_use(arg);
                        }
                    }
                }
                if let Some(mem_key) = self.generate_memory_key(&stmt.operand_satu) {
                    let new_ver = self.update_variable_version(&mem_key);
                    *push_count.entry(mem_key.clone()).or_insert(0) += 1;
                    stmt.operand_satu = TipeOperand::SsaVariable(mem_key, new_ver);
                }
                if stmt.operation_code == OperasiIr::Call {
                     let clobber_candidates: Vec<String> = self.stack_versi.keys()
                        .filter(|k| (k.starts_with("mem_heap") || k.starts_with("mem_sym")) && self.alias_analyzer.is_escaped(k))
                        .cloned()
                        .collect();
                     for mem_key in clobber_candidates {
                         let _new_ver = self.update_variable_version(&mem_key);
                         *push_count.entry(mem_key).or_insert(0) += 1;
                     }
                }
                let mut def_name = None;
                match stmt.operation_code {
                    OperasiIr::Mov | OperasiIr::Add | OperasiIr::Sub | OperasiIr::Imul | 
                    OperasiIr::Phi | OperasiIr::VecMov | OperasiIr::FAdd | OperasiIr::VecAdd | 
                    OperasiIr::VecXor | OperasiIr::Lea | OperasiIr::And | OperasiIr::Or | OperasiIr::Xor | 
                    OperasiIr::Shl | OperasiIr::Shr | OperasiIr::Div | OperasiIr::Call => {
                        if let TipeOperand::Register(name) = &stmt.operand_satu {
                            def_name = Some(self.dapatkan_nama_kanonik(name));
                        } 
                    },
                    _ => {}
                }
                if let Some(canon) = def_name {
                    let new_ver = self.update_variable_version(&canon);
                    stmt.operand_satu = TipeOperand::SsaVariable(canon.clone(), new_ver);
                    *push_count.entry(canon).or_insert(0) += 1;
                }
            }
        }
        let successors = cfg.blocks.get(&current_block).map(|b| b.successors.clone()).unwrap_or_default();
        for succ_id in successors {
            let pred_idx = if let Some(succ_block) = cfg.blocks.get(&succ_id) {
                succ_block.predecessors.iter().position(|&p| p == current_block)
            } else { None };
            if let Some(idx) = pred_idx {
                if let Some(succ_block) = cfg.blocks.get_mut(&succ_id) {
                    for stmt in &mut succ_block.instruksi_list {
                        if stmt.operation_code == OperasiIr::Phi {
                            let var_name = match &stmt.operand_satu {
                                TipeOperand::Register(n) => n.clone(),
                                TipeOperand::SsaVariable(n, _) => n.clone(),
                                _ => continue
                            };
                            let current_ver = self.ambil_versi_terkini(&var_name);
                            if idx < stmt.operand_tambahan.len() {
                                stmt.operand_tambahan[idx] = TipeOperand::SsaVariable(var_name, current_ver);
                            }
                        }
                    }
                }
            }
        }
        if let Some(children) = dom_tree.peta_children.get(&current_block) {
            for &child in children {
                self.rename_variabel(cfg, dom_tree, child);
            }
        }
        for (name, count) in push_count {
            if let Some(stack) = self.stack_versi.get_mut(&name) {
                for _ in 0..count {
                    stack.pop();
                }
            }
        }
    }
    fn proses_operand_use(&self, op: &mut TipeOperand) {
        match op {
            TipeOperand::Register(name) => {
                let canon = self.dapatkan_nama_kanonik(name);
                let ver = self.ambil_versi_terkini(&canon);
                *op = TipeOperand::SsaVariable(canon, ver);
            },
            TipeOperand::MemoryRef { .. } | TipeOperand::Memory(_) => {
                if let Some(mem_key) = self.generate_memory_key(op) {
                    let ver = self.ambil_versi_terkini(&mem_key);
                    *op = TipeOperand::SsaVariable(mem_key, ver);
                }
            },
            TipeOperand::Expression { operand_kiri, operand_kanan, .. } => {
                self.proses_operand_use(operand_kiri);
                self.proses_operand_use(operand_kanan);
            },
            TipeOperand::Conditional { condition, true_val, false_val } => {
                self.proses_operand_use(condition);
                self.proses_operand_use(true_val);
                self.proses_operand_use(false_val);
            },
            _ => {}
        }
    }
    fn update_variable_version(&mut self, name: &str) -> usize {
        let counter = self.counter_versi.entry(name.to_string()).or_insert(0);
        let ver = *counter;
        *counter += 1;
        self.stack_versi.entry(name.to_string()).or_default().push(ver);
        ver
    }
    fn ambil_versi_terkini(&self, name: &str) -> usize {
        self.stack_versi.get(name).and_then(|s| s.last()).cloned().unwrap_or(0)
    }
    fn generate_memory_key(&self, op: &TipeOperand) -> Option<String> {
        let state = self.alias_analyzer.infer_region_state(op, "rbp")?;
        match state.base_region {
            MemoryRegion::Stack(offset) => Some(format!("mem_stack_{}", offset)),
            MemoryRegion::Global(addr) => Some(format!("mem_global_{:x}", addr)),
            MemoryRegion::Heap(alloc_site) => Some(format!("mem_heap_{:x}", alloc_site)),
            MemoryRegion::Symbolic(base_reg) => {
                Some(format!("mem_sym_{}_{}", base_reg, state.offset))
            },
            MemoryRegion::Unknown => None, 
        }
    }
}