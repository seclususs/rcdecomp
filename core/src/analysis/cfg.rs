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
    pub fn bangun_execution_graph(statements: Vec<StatementIr>) -> Self {
        let mut cfg = Self::inisialisasi_graph_kosong();
        if statements.is_empty() {
            return cfg;
        }
        cfg.entry_point = statements[0].address_asal;
        let leaders = cfg.identifikasi_leaders(&statements);
        let mut current_block = BasicBlock::new(statements[0].address_asal);
        for stmt in statements {
            if leaders.contains(&stmt.address_asal) && current_block.instruksi_list.len() > 0 {
                cfg.blocks.insert(current_block.id_block, current_block);
                current_block = BasicBlock::new(stmt.address_asal);
            }
            current_block.instruksi_list.push(stmt);
        }
        if !current_block.instruksi_list.is_empty() {
            cfg.blocks.insert(current_block.id_block, current_block);
        }
        cfg.hubungkan_edges();
        cfg
    }
    fn identifikasi_leaders(&self, stmts: &[StatementIr]) -> HashSet<u64> {
        let mut leaders = HashSet::new();
        if let Some(first) = stmts.first() {
            leaders.insert(first.address_asal);
        }
        for (i, stmt) in stmts.iter().enumerate() {
            match stmt.operation_code {
                OperasiIr::Jmp | OperasiIr::Je | OperasiIr::Jne | OperasiIr::Call => {
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
    fn hubungkan_edges(&mut self) {
        let block_ids: Vec<u64> = self.blocks.keys().cloned().collect();
        for id in block_ids {
            let last_instr = {
                let block = self.blocks.get(&id).unwrap();
                block.instruksi_list.last().cloned()
            };
            if let Some(stmt) = last_instr {
                let mut targets = Vec::new();
                match stmt.operation_code {
                    OperasiIr::Jmp => {
                        if let crate::ir::types::TipeOperand::Immediate(val) = stmt.operand_satu {
                            targets.push(val as u64);
                        }
                    },
                    OperasiIr::Je | OperasiIr::Jne => {
                        if let crate::ir::types::TipeOperand::Immediate(val) = stmt.operand_satu {
                            targets.push(val as u64);
                        }
                    },
                    _ => {}
                }
                for target_id in targets {
                    if self.blocks.contains_key(&target_id) {
                        self.blocks.get_mut(&id).unwrap().successors.push(target_id);
                        self.blocks.get_mut(&target_id).unwrap().predecessors.push(id);
                    }
                }
            }
        }
    }
}