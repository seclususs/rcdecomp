use std::collections::{HashMap, HashSet};
use crate::analysis::graph::cfg::ControlFlowGraph;
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};
use crate::arch::Architecture;

pub struct CallingConventionAnalyzer {
    abi_registers: Vec<String>,
}

impl CallingConventionAnalyzer {
    pub fn new(arch: &dyn Architecture) -> Self {
        Self {
            abi_registers: arch.dapatkan_register_argumen(),
        }
    }
    pub fn terapkan_analisa_call_args(&self, cfg: &mut ControlFlowGraph) {
        let mut global_reg_versions: HashMap<String, usize> = HashMap::new();
        for reg in &self.abi_registers {
            global_reg_versions.insert(reg.clone(), 0);
        }
        let mut block_ids: Vec<u64> = cfg.blocks.keys().cloned().collect();
        block_ids.sort();
        for id in block_ids {
            if let Some(block) = cfg.blocks.get_mut(&id) {
                for stmt in &mut block.instruksi_list {
                    self.update_reg_tracker(stmt, &mut global_reg_versions);
                    if stmt.operation_code == OperasiIr::Call {
                        let mut detected_args = Vec::new();
                        for abi_reg in &self.abi_registers {
                            let ver = *global_reg_versions.get(abi_reg).unwrap_or(&0);
                            detected_args.push(TipeOperand::SsaVariable(abi_reg.clone(), ver));
                        }
                        stmt.operand_tambahan = detected_args;
                    }
                }
            }
        }
    }
    fn update_reg_tracker(&self, stmt: &StatementIr, tracker: &mut HashMap<String, usize>) {
        if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_satu {
            if self.abi_registers.contains(name) {
                tracker.insert(name.clone(), *ver);
            }
        }
        if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_dua {
            if self.abi_registers.contains(name) {
                tracker.insert(name.clone(), *ver);
            }
        }
    }
    pub fn deteksi_entry_params(&self, cfg: &ControlFlowGraph) -> Vec<String> {
        let mut params = Vec::new();
        let entry_id = cfg.entry_point;
        if let Some(block) = cfg.blocks.get(&entry_id) {
            let mut written = HashSet::new();
            let mut read = HashSet::new();
            for stmt in &block.instruksi_list {
                if let TipeOperand::SsaVariable(name, _) = &stmt.operand_dua {
                   if !written.contains(name) {
                       read.insert(name.clone());
                   }
                }
                match stmt.operation_code {
                    OperasiIr::Cmp | OperasiIr::Test => {
                        if let TipeOperand::SsaVariable(name, _) = &stmt.operand_satu {
                             if !written.contains(name) {
                                read.insert(name.clone());
                            }
                        }
                    },
                    _ => {}
                }
                match stmt.operation_code {
                    OperasiIr::Mov | OperasiIr::Add | OperasiIr::Sub | OperasiIr::Imul => {
                        if let TipeOperand::SsaVariable(name, _) = &stmt.operand_satu {
                            written.insert(name.clone());
                        }
                    },
                    _ => {}
                }
            }
            for reg in &self.abi_registers {
                if read.contains(reg) {
                    params.push(format!("{}_0", reg));
                }
            }
        }
        params
    }
}