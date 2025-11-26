use std::collections::{HashSet, VecDeque};
use crate::analysis::graph::cfg::ControlFlowGraph;
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};

pub struct AdceSolver {
    live_stmts_map: HashSet<(u64, usize)>,
    worklist: VecDeque<(u64, usize)>,
}

impl AdceSolver {
    pub fn new() -> Self {
        Self {
            live_stmts_map: HashSet::new(),
            worklist: VecDeque::new(),
        }
    }
    pub fn jalankan_adce(&mut self, cfg: &mut ControlFlowGraph) {
        for (block_id, block) in &cfg.blocks {
            for (idx, stmt) in block.instruksi_list.iter().enumerate() {
                if self.cek_apakah_critical(stmt) {
                    self.validasi_dan_tandai_live(*block_id, idx, stmt);
                }
            }
        }
        while let Some((blk, idx)) = self.worklist.pop_front() {
            if let Some(block) = cfg.blocks.get(&blk) {
                if idx < block.instruksi_list.len() {
                    let stmt = &block.instruksi_list[idx];
                    self.tandai_operands_live(stmt, cfg);
                }
            }
        }
        for (block_id, block) in cfg.blocks.iter_mut() {
            let mut new_instruksi = Vec::new();
            for (idx, stmt) in block.instruksi_list.iter().enumerate() {
                if self.live_stmts_map.contains(&(*block_id, idx)) || 
                   matches!(stmt.operation_code, OperasiIr::Jmp | OperasiIr::Je | OperasiIr::Jne | OperasiIr::Ret | OperasiIr::Call) {
                    new_instruksi.push(stmt.clone());
                }
            }
            block.instruksi_list = new_instruksi;
        }
    }
    fn cek_apakah_critical(&self, stmt: &StatementIr) -> bool {
        match stmt.operation_code {
            OperasiIr::Call | OperasiIr::Ret | 
            OperasiIr::Jmp | OperasiIr::Je | OperasiIr::Jne | 
            OperasiIr::Jg | OperasiIr::Jge | OperasiIr::Jl | OperasiIr::Jle => true,
            OperasiIr::Mov | OperasiIr::Add => {
                if let TipeOperand::Memory(_) | TipeOperand::MemoryRef { .. } = stmt.operand_satu {
                    true
                } else {
                    false
                }
            },
            _ => false
        }
    }
    fn validasi_dan_tandai_live(&mut self, block_id: u64, idx: usize, stmt: &StatementIr) {
        match stmt.operation_code {
            OperasiIr::Nop | OperasiIr::Unknown => return,
            _ => {}
        }
        if !self.live_stmts_map.contains(&(block_id, idx)) {
            self.live_stmts_map.insert((block_id, idx));
            self.worklist.push_back((block_id, idx));
        }
    }
    fn tandai_operands_live(&mut self, stmt: &StatementIr, cfg: &ControlFlowGraph) {
        let mut used_vars = Vec::new();
        self.kumpulkan_penggunaan_var(&stmt.operand_satu, &mut used_vars);
        self.kumpulkan_penggunaan_var(&stmt.operand_dua, &mut used_vars);
        for op in &stmt.operand_tambahan {
            self.kumpulkan_penggunaan_var(op, &mut used_vars);
        }
        for (var_name, var_ver) in used_vars {
            self.temukan_dan_tandai_definisi(cfg, &var_name, var_ver);
        }
    }
    fn kumpulkan_penggunaan_var(&self, op: &TipeOperand, collector: &mut Vec<(String, usize)>) {
        match op {
            TipeOperand::SsaVariable(n, v) => collector.push((n.clone(), *v)),
            TipeOperand::Expression { operand_kiri, operand_kanan, .. } => {
                self.kumpulkan_penggunaan_var(operand_kiri, collector);
                self.kumpulkan_penggunaan_var(operand_kanan, collector);
            },
            TipeOperand::Conditional { condition, true_val, false_val } => {
                self.kumpulkan_penggunaan_var(condition, collector);
                self.kumpulkan_penggunaan_var(true_val, collector);
                self.kumpulkan_penggunaan_var(false_val, collector);
            },
            _ => {}
        }
    }
    fn temukan_dan_tandai_definisi(&mut self, cfg: &ControlFlowGraph, name: &str, ver: usize) {
        for (bid, block) in &cfg.blocks {
            for (idx, stmt) in block.instruksi_list.iter().enumerate() {
                if let TipeOperand::SsaVariable(def_n, def_v) = &stmt.operand_satu {
                    if def_n == name && *def_v == ver {
                        self.validasi_dan_tandai_live(*bid, idx, stmt);
                        return;
                    }
                }
            }
        }
    }
}