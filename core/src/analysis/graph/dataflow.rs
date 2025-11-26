use std::collections::{HashMap, HashSet};
use crate::ir::types::{TipeOperand, OperasiIr};
use super::cfg::ControlFlowGraph;
use log::debug;

pub struct DataFlowAnalysis {
    pub definitions: HashMap<u64, HashSet<String>>,
    pub usages: HashMap<u64, HashSet<String>>,
}

impl DataFlowAnalysis {
    pub fn new() -> Self {
        Self {
            definitions: HashMap::new(),
            usages: HashMap::new(),
        }
    }
    pub fn analisa_use_def(&mut self, cfg: &ControlFlowGraph) {
        for (id, block) in &cfg.blocks {
            let mut defined = HashSet::new();
            let mut used = HashSet::new();
            for stmt in &block.instruksi_list {
                if let TipeOperand::Register(reg) = &stmt.operand_dua {
                    if !defined.contains(reg) {
                        used.insert(reg.clone());
                    }
                }
                match stmt.operation_code {
                    OperasiIr::Mov | OperasiIr::Add | OperasiIr::Sub | OperasiIr::Imul => {
                        if let TipeOperand::Register(reg) = &stmt.operand_satu {
                            defined.insert(reg.clone());
                        }
                    },
                    OperasiIr::Je | OperasiIr::Jne | OperasiIr::Jmp => {
                        if let TipeOperand::Register(reg) = &stmt.operand_satu {
                            if !defined.contains(reg) {
                                used.insert(reg.clone());
                            }
                        }
                    },
                    _ => {}
                }
            }
            self.definitions.insert(*id, defined);
            self.usages.insert(*id, used);
        }
    }
    pub fn cetak_laporan_dataflow(&self) {
        debug!("--- Laporan Analisis Data Flow ---");
        for (id, defs) in &self.definitions {
            let uses = self.usages.get(id).unwrap();
            debug!("Block 0x{:x}:", id);
            debug!("  Defined: {:?}", defs);
            debug!("  Used:    {:?}", uses);
        }
    }
}