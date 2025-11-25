use std::collections::{HashMap, HashSet};
use crate::ir::types::{StatementIr, OperasiIr};

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id_block: u64,
    pub instruksi_list: Vec<StatementIr>,
    pub successors: Vec<u64>,
    pub predecessors: Vec<u64>,
}

impl BasicBlock {
    pub fn new(start_addr: u64) -> Self {
        Self {
            id_block: start_addr,
            instruksi_list: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }
}

pub struct ControlFlowGraph {
    pub blocks: HashMap<u64, BasicBlock>,
    pub entry_point: u64,
}

impl ControlFlowGraph {
    pub fn inisialisasi_graph_kosong() -> Self {
        Self {
            blocks: HashMap::new(),
            entry_point: 0,
        }
    }
    pub fn bangun_execution_graph(
        statements: Vec<StatementIr>, 
        jump_table_targets: &HashMap<u64, Vec<u64>>
    ) -> Self {
        let mut cfg = Self::inisialisasi_graph_kosong();
        if statements.is_empty() {
            return cfg;
        }
        cfg.entry_point = statements[0].address_asal;
        let leaders = cfg.identifikasi_leaders(&statements, jump_table_targets);
        let mut current_block = BasicBlock::new(statements[0].address_asal);
        for stmt in statements {
            if leaders.contains(&stmt.address_asal) && !current_block.instruksi_list.is_empty() {
                cfg.blocks.insert(current_block.id_block, current_block);
                current_block = BasicBlock::new(stmt.address_asal);
            }
            current_block.instruksi_list.push(stmt);
        }
        if !current_block.instruksi_list.is_empty() {
            cfg.blocks.insert(current_block.id_block, current_block);
        }
        cfg.hubungkan_edges(jump_table_targets);
        cfg
    }
    fn identifikasi_leaders(
        &self, 
        stmts: &[StatementIr], 
        jump_targets: &HashMap<u64, Vec<u64>>
    ) -> HashSet<u64> {
        let mut leaders = HashSet::new();
        if let Some(first) = stmts.first() {
            leaders.insert(first.address_asal);
        }
        for (i, stmt) in stmts.iter().enumerate() {
            match stmt.operation_code {
                OperasiIr::Jmp => {
                    if let crate::ir::types::TipeOperand::Immediate(target) = stmt.operand_satu {
                        leaders.insert(target as u64);
                    }
                    if let Some(targets) = jump_targets.get(&stmt.address_asal) {
                        for &t in targets {
                            leaders.insert(t);
                        }
                    }
                    if i + 1 < stmts.len() {
                        leaders.insert(stmts[i + 1].address_asal);
                    }
                },
                OperasiIr::Je | OperasiIr::Jne | OperasiIr::Call | OperasiIr::Jg | 
                OperasiIr::Jge | OperasiIr::Jl | OperasiIr::Jle | OperasiIr::Cmp | OperasiIr::Test | OperasiIr::FCmp => {
                    if let crate::ir::types::TipeOperand::Immediate(target) = stmt.operand_satu {
                        leaders.insert(target as u64);
                    }
                    if i + 1 < stmts.len() {
                        leaders.insert(stmts[i + 1].address_asal);
                    }
                }
                OperasiIr::Ret => {
                    if i + 1 < stmts.len() {
                        leaders.insert(stmts[i + 1].address_asal);
                    }
                }
                _ => {}
            }
        }
        leaders
    }
    fn hubungkan_edges(&mut self, jump_targets: &HashMap<u64, Vec<u64>>) {
        let block_ids: Vec<u64> = self.blocks.keys().cloned().collect();
        let mut connections_to_add: Vec<(u64, u64)> = Vec::new();
        for id in &block_ids {
            let last_instr = {
                let block = self.blocks.get(id).unwrap();
                block.instruksi_list.last().cloned()
            };
            if let Some(stmt) = last_instr {
                let mut targets = Vec::new();
                match stmt.operation_code {
                    OperasiIr::Jmp => {
                        if let crate::ir::types::TipeOperand::Immediate(val) = stmt.operand_satu {
                            targets.push(val as u64);
                        } else if let Some(indirect_list) = jump_targets.get(&stmt.address_asal) {
                            targets.extend(indirect_list);
                        }
                    },
                    OperasiIr::Je | OperasiIr::Jne | OperasiIr::Jg | OperasiIr::Jge | OperasiIr::Jl | OperasiIr::Jle => {
                        if let crate::ir::types::TipeOperand::Immediate(val) = stmt.operand_satu {
                            targets.push(val as u64); 
                        }
                    },
                    _ => {}
                }
                for target_id in targets {
                    if self.blocks.contains_key(&target_id) {
                         connections_to_add.push((*id, target_id));
                    }
                }
            }
        }
        for (from, to) in connections_to_add {
            self.hubungkan_manual(from, to);
        }
        let mut sorted_ids = block_ids;
        sorted_ids.sort();
        let mut fallthroughs = Vec::new();
        for i in 0..sorted_ids.len()-1 {
            let curr = sorted_ids[i];
            let next = sorted_ids[i+1];
            let is_uncond = {
                let block = self.blocks.get(&curr).unwrap();
                let last_op = block.instruksi_list.last().map(|s| &s.operation_code);
                matches!(last_op, Some(OperasiIr::Jmp) | Some(OperasiIr::Ret))
            };
            if !is_uncond {
                fallthroughs.push((curr, next));
            }
        }
        for (curr, next) in fallthroughs {
             self.hubungkan_manual(curr, next);
        }
    }
    pub fn hubungkan_manual(&mut self, from: u64, to: u64) {
        if let Some(block) = self.blocks.get_mut(&from) {
            if !block.successors.contains(&to) {
                block.successors.push(to);
            }
        }
        if let Some(block) = self.blocks.get_mut(&to) {
            if !block.predecessors.contains(&from) {
                block.predecessors.push(from);
            }
        }
    }
    pub fn generate_id_baru(&self) -> u64 {
        let max_id = self.blocks.keys().max().unwrap_or(&0);
        max_id + 0x1000 
    }
    pub fn buat_block_baru_dari_copy(&mut self, original_id: u64, new_id: u64) {
        let (instruksi, successors) = if let Some(original) = self.blocks.get(&original_id) {
            (original.instruksi_list.clone(), original.successors.clone())
        } else {
            return;
        };
        let new_block = BasicBlock {
            id_block: new_id,
            instruksi_list: instruksi,
            successors: successors.clone(),
            predecessors: Vec::new(),
        };
        self.blocks.insert(new_id, new_block);
        for succ in successors {
            if let Some(succ_block) = self.blocks.get_mut(&succ) {
                succ_block.predecessors.push(new_id);
            }
        }
    }
    pub fn redirect_edge(&mut self, source: u64, old_target: u64, new_target: u64) {
        if let Some(src_block) = self.blocks.get_mut(&source) {
            if let Some(idx) = src_block.successors.iter().position(|&x| x == old_target) {
                src_block.successors[idx] = new_target;
            }
        }
        if let Some(old_block) = self.blocks.get_mut(&old_target) {
            if let Some(idx) = old_block.predecessors.iter().position(|&x| x == source) {
                old_block.predecessors.remove(idx);
            }
        }
        if let Some(new_block) = self.blocks.get_mut(&new_target) {
            if !new_block.predecessors.contains(&source) {
                new_block.predecessors.push(source);
            }
        }
    }
}