use std::collections::{HashMap, HashSet, VecDeque};
use crate::analysis::cfg::ControlFlowGraph;
use crate::analysis::dominator::DominatorTree;
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};

pub struct SsaTransformer {
    stack_versi: HashMap<String, Vec<usize>>,
    counter_versi: HashMap<String, usize>,
}

impl SsaTransformer {
    pub fn new() -> Self {
        Self {
            stack_versi: HashMap::new(),
            counter_versi: HashMap::new(),
        }
    }
    pub fn lakukan_transformasi_ssa(&mut self, cfg: &mut ControlFlowGraph, dom_tree: &DominatorTree) {
        self.sisipkan_phi_nodes(cfg, dom_tree);
        self.inisialisasi_stack_variabel(cfg);
        self.rename_variabel(cfg, dom_tree, cfg.entry_point);
    }
    pub fn optimasi_propagasi_konstanta(&self, cfg: &mut ControlFlowGraph) {
        let mut konstanta_map: HashMap<String, i64> = HashMap::new();
        let mut ada_perubahan = true;
        while ada_perubahan {
            ada_perubahan = false;
            for block in cfg.blocks.values_mut() {
                for stmt in &mut block.instruksi_list {
                    if stmt.operation_code == OperasiIr::Mov {
                        if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_satu {
                            let key = format!("{}_{}", name, ver);
                            if let TipeOperand::Immediate(val) = stmt.operand_dua {
                                if !konstanta_map.contains_key(&key) {
                                    konstanta_map.insert(key, val);
                                    ada_perubahan = true;
                                }
                            }
                        }
                    }
                    if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_dua {
                        let key = format!("{}_{}", name, ver);
                        if let Some(&val) = konstanta_map.get(&key) {
                            stmt.operand_dua = TipeOperand::Immediate(val);
                            ada_perubahan = true;
                        }
                    }
                    match stmt.operation_code {
                        OperasiIr::Cmp | OperasiIr::Test => {
                            if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_satu {
                                let key = format!("{}_{}", name, ver);
                                if let Some(&val) = konstanta_map.get(&key) {
                                    stmt.operand_satu = TipeOperand::Immediate(val);
                                    ada_perubahan = true;
                                }
                            }
                        },
                        _ => {}
                    }
                }
            }
        }
    }
    pub fn optimasi_dead_code(&self, cfg: &mut ControlFlowGraph) {
        let mut variabel_terpakai: HashSet<String> = HashSet::new();
        for block in cfg.blocks.values() {
            for stmt in &block.instruksi_list {
                if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_dua {
                    variabel_terpakai.insert(format!("{}_{}", name, ver));
                }
                match stmt.operation_code {
                    OperasiIr::Cmp | OperasiIr::Test => {
                        if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_satu {
                            variabel_terpakai.insert(format!("{}_{}", name, ver));
                        }
                    },
                    _ => {}
                }
            }
        }
        for block in cfg.blocks.values_mut() {
            block.instruksi_list.retain(|stmt| {
                match stmt.operation_code {
                    OperasiIr::Call | OperasiIr::Ret | OperasiIr::Jmp | 
                    OperasiIr::Je | OperasiIr::Jne | OperasiIr::Cmp | OperasiIr::Test => true,
                    _ => {
                        if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_satu {
                            let key = format!("{}_{}", name, ver);
                            variabel_terpakai.contains(&key)
                        } else {
                            true
                        }
                    }
                }
            });
        }
    }
    fn sisipkan_phi_nodes(&self, cfg: &mut ControlFlowGraph, dom_tree: &DominatorTree) {
        let mut global_vars = HashSet::new();
        let mut blocks_defining_var: HashMap<String, HashSet<u64>> = HashMap::new();
        for (block_id, block) in &cfg.blocks {
            let mut var_kill = HashSet::new();
            for stmt in &block.instruksi_list {
                if let TipeOperand::Register(r) = &stmt.operand_dua {
                    if !var_kill.contains(r) { global_vars.insert(r.clone()); }
                }
                match stmt.operation_code {
                    OperasiIr::Mov | OperasiIr::Add | OperasiIr::Sub | OperasiIr::Imul => {
                        if let TipeOperand::Register(r) = &stmt.operand_satu {
                            var_kill.insert(r.clone());
                            blocks_defining_var.entry(r.clone()).or_default().insert(*block_id);
                        }
                    },
                    _ => {}
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
                                let phi_stmt = StatementIr {
                                    address_asal: 0,
                                    operation_code: OperasiIr::Phi,
                                    operand_satu: TipeOperand::Register(var.clone()),
                                    operand_dua: TipeOperand::None,
                                    operand_tambahan: Vec::new(),
                                };
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
        for block in cfg.blocks.values() {
            for stmt in &block.instruksi_list {
                if let TipeOperand::Register(r) = &stmt.operand_satu {
                    self.stack_versi.insert(r.clone(), vec![0]);
                    self.counter_versi.insert(r.clone(), 1);
                }
            }
        }
    }
    fn rename_variabel(&mut self, cfg: &mut ControlFlowGraph, dom_tree: &DominatorTree, current_block: u64) {
        let mut push_count: HashMap<String, usize> = HashMap::new();
        if let Some(block) = cfg.blocks.get_mut(&current_block) {
            for stmt in &mut block.instruksi_list {
                if stmt.operation_code != OperasiIr::Phi {
                    if let TipeOperand::Register(name) = &stmt.operand_dua {
                        let ver = self.ambil_versi_terkini(name);
                        stmt.operand_dua = TipeOperand::SsaVariable(name.clone(), ver);
                    }
                    let mut read_src = None;
                    match stmt.operation_code {
                        OperasiIr::Cmp | OperasiIr::Test => {
                            if let TipeOperand::Register(name) = &stmt.operand_satu {
                                read_src = Some(name.clone());
                            }
                        },
                        _ => {}
                    }
                    if let Some(name) = read_src {
                        let ver = self.ambil_versi_terkini(&name);
                        stmt.operand_satu = TipeOperand::SsaVariable(name, ver);
                    }
                }
                let mut def_name = None;
                match stmt.operation_code {
                    OperasiIr::Mov | OperasiIr::Add | OperasiIr::Sub | OperasiIr::Imul | OperasiIr::Phi => {
                        if let TipeOperand::Register(name) = &stmt.operand_satu {
                            def_name = Some(name.clone());
                        }
                    },
                    _ => {}
                }
                if let Some(name) = def_name {
                    let new_ver = self.buat_versi_baru(&name);
                    stmt.operand_satu = TipeOperand::SsaVariable(name.clone(), new_ver);
                    *push_count.entry(name).or_insert(0) += 1;
                }
            }
        }
        let successors = cfg.blocks.get(&current_block).map(|b| b.successors.clone()).unwrap_or_default();
        for succ_id in successors {
            if let Some(succ_block) = cfg.blocks.get_mut(&succ_id) {
                for stmt in &mut succ_block.instruksi_list {
                    if stmt.operation_code == OperasiIr::Phi {
                        if let TipeOperand::SsaVariable(name, _) = &stmt.operand_satu {
                            let current_ver = self.ambil_versi_terkini(name);
                            stmt.operand_tambahan.push(TipeOperand::SsaVariable(name.clone(), current_ver));
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
    fn ambil_versi_terkini(&self, name: &str) -> usize {
        self.stack_versi.get(name).and_then(|s| s.last()).cloned().unwrap_or(0)
    }
    fn buat_versi_baru(&mut self, name: &str) -> usize {
        let counter = self.counter_versi.entry(name.to_string()).or_insert(0);
        let ver = *counter;
        *counter += 1;
        self.stack_versi.entry(name.to_string()).or_default().push(ver);
        ver
    }
}