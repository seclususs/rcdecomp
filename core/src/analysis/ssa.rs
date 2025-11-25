use std::collections::{HashMap, HashSet, VecDeque};
use crate::analysis::cfg::ControlFlowGraph;
use crate::analysis::dominator::DominatorTree;
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};
use crate::analysis::alias_analysis::{AliasAnalyzer, MemoryRegion};

pub struct SsaTransformer {
    stack_versi: HashMap<String, Vec<usize>>,
    counter_versi: HashMap<String, usize>,
    peta_alias_register: HashMap<String, String>,
    alias_analyzer: AliasAnalyzer,
    _memory_versions: HashMap<String, usize>, 
}

impl SsaTransformer {
    pub fn new() -> Self {
        Self {
            stack_versi: HashMap::new(),
            counter_versi: HashMap::new(),
            peta_alias_register: Self::inisialisasi_alias_map(),
            alias_analyzer: AliasAnalyzer::new(),
            _memory_versions: HashMap::new(),
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
        ];
        for (parent, children) in gprs {
            for child in children {
                m.insert(child.to_string(), parent.to_string());
            }
        }
        for i in 0..16 {
            let xmm = format!("xmm{}", i);
            let ymm = format!("ymm{}", i);
            m.insert(ymm, xmm); 
        }
        for i in 0..32 {
            let canonical = format!("v{}", i); 
            for prefix in &["q", "d", "s", "h", "b"] {
                m.insert(format!("{}{}", prefix, i), canonical.clone());
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
        self.alias_analyzer.analisis_pointer(&all_stmts, "rbp");
        self.sisipkan_phi_nodes(cfg, dom_tree);
        self.inisialisasi_stack_variabel(cfg);
        self.rename_variabel(cfg, dom_tree, cfg.entry_point);
    }
    pub fn optimasi_propagasi_konstanta(&self, cfg: &mut ControlFlowGraph) {
        let mut konstanta_map: HashMap<String, TipeOperand> = HashMap::new(); 
        let mut ada_perubahan = true;
        while ada_perubahan {
            ada_perubahan = false;
            for block in cfg.blocks.values_mut() {
                for stmt in &mut block.instruksi_list {
                    match stmt.operation_code {
                        OperasiIr::Mov | OperasiIr::VecMov => {
                            if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_satu {
                                let key = format!("{}_{}", name, ver);
                                match &stmt.operand_dua {
                                    TipeOperand::Immediate(_) | TipeOperand::FloatImmediate(_) => {
                                        if !konstanta_map.contains_key(&key) {
                                            konstanta_map.insert(key, stmt.operand_dua.clone());
                                            ada_perubahan = true;
                                        }
                                    },
                                    _ => {}
                                }
                            }
                        },
                        _ => {}
                    }
                    if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_dua {
                        let key = format!("{}_{}", name, ver);
                        if let Some(val) = konstanta_map.get(&key) {
                            stmt.operand_dua = val.clone();
                            ada_perubahan = true;
                        }
                    }
                     match stmt.operation_code {
                        OperasiIr::Cmp | OperasiIr::Test | OperasiIr::FCmp => {
                            if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_satu {
                                let key = format!("{}_{}", name, ver);
                                if let Some(val) = konstanta_map.get(&key) {
                                    stmt.operand_satu = val.clone();
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
                 self.kumpulkan_usage_dari_operand(&stmt.operand_dua, &mut variabel_terpakai);
                 match stmt.operation_code {
                     OperasiIr::Cmp | OperasiIr::Test | OperasiIr::FCmp => {
                         self.kumpulkan_usage_dari_operand(&stmt.operand_satu, &mut variabel_terpakai);
                     },
                     _ => {}
                 }
                 if let TipeOperand::Expression { operand_kiri, operand_kanan, .. } = &stmt.operand_dua {
                     self.kumpulkan_usage_dari_operand(operand_kiri, &mut variabel_terpakai);
                     self.kumpulkan_usage_dari_operand(operand_kanan, &mut variabel_terpakai);
                 }
                 for op in &stmt.operand_tambahan {
                     self.kumpulkan_usage_dari_operand(op, &mut variabel_terpakai);
                 }
             }
         }
         for block in cfg.blocks.values_mut() {
            block.instruksi_list.retain(|stmt| {
                match stmt.operation_code {
                    OperasiIr::Call | OperasiIr::Ret | OperasiIr::Jmp | 
                    OperasiIr::Je | OperasiIr::Jne | OperasiIr::Jg | OperasiIr::Jge |
                    OperasiIr::Jl | OperasiIr::Jle |
                    OperasiIr::Cmp | OperasiIr::Test | OperasiIr::FCmp => true,
                    OperasiIr::Mov | OperasiIr::Lea | OperasiIr::Add | OperasiIr::Sub => {
                        if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_satu {
                            let key = format!("{}_{}", name, ver);
                            variabel_terpakai.contains(&key)
                        } else if let TipeOperand::MemoryRef { .. } = stmt.operand_satu {
                            true 
                        } else if let TipeOperand::Memory(_) = stmt.operand_satu {
                            true
                        } else {
                            true
                        }
                    },
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
    fn kumpulkan_usage_dari_operand(&self, op: &TipeOperand, set_terpakai: &mut HashSet<String>) {
        match op {
            TipeOperand::SsaVariable(name, ver) => {
                set_terpakai.insert(format!("{}_{}", name, ver));
            },
            TipeOperand::Expression { operand_kiri, operand_kanan, .. } => {
                self.kumpulkan_usage_dari_operand(operand_kiri, set_terpakai);
                self.kumpulkan_usage_dari_operand(operand_kanan, set_terpakai);
            },
            _ => {}
        }
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
                    let region = self.alias_analyzer.infer_region(&stmt.operand_satu, "rbp");
                    if let Some(mem_key) = self.konversi_region_ke_key(&region) {
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
                                let phi_stmt = StatementIr::new(
                                    0,
                                    OperasiIr::Phi,
                                    TipeOperand::Register(var.clone()), 
                                    TipeOperand::None
                                );
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
                if let TipeOperand::MemoryRef { .. } = &stmt.operand_satu {
                    let region = self.alias_analyzer.infer_region(&stmt.operand_satu, "rbp");
                    if let Some(key) = self.konversi_region_ke_key(&region) {
                        vars.insert(key);
                    }
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
                    self.update_memory_use_version(&mut stmt.operand_dua);
                    if let TipeOperand::Register(name) = &stmt.operand_dua {
                        let canon = self.dapatkan_nama_kanonik(name);
                        let ver = self.ambil_versi_terkini(&canon);
                        stmt.operand_dua = TipeOperand::SsaVariable(canon, ver); 
                    }
                    let mut read_src = None;
                    match stmt.operation_code {
                        OperasiIr::Cmp | OperasiIr::Test | OperasiIr::FCmp => {
                            if let TipeOperand::Register(name) = &stmt.operand_satu {
                                read_src = Some(self.dapatkan_nama_kanonik(name));
                            } else {
                                self.update_memory_use_version(&mut stmt.operand_satu);
                            }
                        },
                        OperasiIr::Add | OperasiIr::Sub | OperasiIr::FAdd | OperasiIr::VecAdd => {
                             if let TipeOperand::Register(name) = &stmt.operand_satu {
                                 read_src = Some(self.dapatkan_nama_kanonik(name));
                             }
                        }
                        _ => {}
                    }
                    if let Some(canon) = read_src {
                         let ver = self.ambil_versi_terkini(&canon);
                         stmt.operand_satu = TipeOperand::SsaVariable(canon, ver);
                    }
                }
                if let TipeOperand::MemoryRef { .. } = &stmt.operand_satu {
                    let region = self.alias_analyzer.infer_region(&stmt.operand_satu, "rbp");
                    if let Some(mem_key) = self.konversi_region_ke_key(&region) {
                        let new_ver = self.update_memory_def_version(&mem_key);
                        *push_count.entry(mem_key.clone()).or_insert(0) += 1;
                        stmt.operand_satu = TipeOperand::SsaVariable(mem_key, new_ver);
                    }
                }
                let mut def_name = None;
                match stmt.operation_code {
                    OperasiIr::Mov | OperasiIr::Add | OperasiIr::Sub | OperasiIr::Imul | 
                    OperasiIr::Phi | OperasiIr::VecMov | OperasiIr::FAdd | OperasiIr::VecAdd | 
                    OperasiIr::VecXor | OperasiIr::Lea => {
                        if let TipeOperand::Register(name) = &stmt.operand_satu {
                            def_name = Some(self.dapatkan_nama_kanonik(name));
                        } 
                        else if let TipeOperand::SsaVariable(name, _) = &stmt.operand_satu {
                            def_name = Some(name.clone());
                        }
                    },
                    _ => {}
                }
                if let Some(canon) = def_name {
                    let new_ver = self.buat_versi_baru(&canon);
                    stmt.operand_satu = TipeOperand::SsaVariable(canon.clone(), new_ver);
                    *push_count.entry(canon).or_insert(0) += 1;
                }
            }
        }
        let successors = cfg.blocks.get(&current_block).map(|b| b.successors.clone()).unwrap_or_default();
        for succ_id in successors {
            if let Some(succ_block) = cfg.blocks.get_mut(&succ_id) {
                for stmt in &mut succ_block.instruksi_list {
                    if stmt.operation_code == OperasiIr::Phi {
                        if let TipeOperand::Register(name) = &stmt.operand_satu {
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
    fn update_memory_use_version(&self, op: &mut TipeOperand) {
        let region = match op {
            TipeOperand::MemoryRef { .. } | TipeOperand::Memory(_) => {
                self.alias_analyzer.infer_region(op, "rbp")
            },
            _ => MemoryRegion::Unknown,
        };
        if let Some(mem_key) = self.konversi_region_ke_key(&region) {
            let ver = self.ambil_versi_terkini(&mem_key);
            *op = TipeOperand::SsaVariable(mem_key, ver);
        }
    }
    fn update_memory_def_version(&mut self, mem_key: &str) -> usize {
        self.buat_versi_baru(mem_key)
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
    fn konversi_region_ke_key(&self, region: &MemoryRegion) -> Option<String> {
        match region {
            MemoryRegion::Stack(offset) => Some(format!("mem_stack_{}", offset)),
            MemoryRegion::Global(addr) => Some(format!("mem_global_{:x}", addr)),
            MemoryRegion::Heap => Some("mem_heap_generic".to_string()), 
            MemoryRegion::Unknown => None, 
        }
    }
}