use std::collections::{HashMap, HashSet, VecDeque};
use crate::analysis::graph::cfg::ControlFlowGraph;
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum StatusLattice {
    Top,            
    Constant(i64),  
    Bottom,         
}

pub struct SccpSolver {
    lattice_values: HashMap<String, StatusLattice>,
    flow_worklist: VecDeque<(u64, u64)>, 
    ssa_worklist: VecDeque<String>,      
    executable_edges: HashSet<(u64, u64)>,
    visited_blocks: HashSet<u64>,
}

impl SccpSolver {
    pub fn new() -> Self {
        Self {
            lattice_values: HashMap::new(),
            flow_worklist: VecDeque::new(),
            ssa_worklist: VecDeque::new(),
            executable_edges: HashSet::new(),
            visited_blocks: HashSet::new(),
        }
    }
    pub fn jalankan_sccp(&mut self, cfg: &ControlFlowGraph) {
        self.flow_worklist.push_back((0, cfg.entry_point));
        while !self.flow_worklist.is_empty() || !self.ssa_worklist.is_empty() {
            if let Some((src, dst)) = self.flow_worklist.pop_front() {
                if self.executable_edges.contains(&(src, dst)) { continue; }
                self.executable_edges.insert((src, dst));
                self.proses_phi_nodes(cfg, dst);
                if !self.visited_blocks.contains(&dst) {
                    self.visited_blocks.insert(dst);
                    self.visit_instruksi_block(cfg, dst);
                } else {
                    self.visit_instruksi_block(cfg, dst); 
                }
            } else if let Some(var_name) = self.ssa_worklist.pop_front() {
                self.visit_uses(cfg, &var_name);
            }
        }
    }
    pub fn terapkan_hasil(&self, cfg: &mut ControlFlowGraph) {
        for block in cfg.blocks.values_mut() {
            for stmt in &mut block.instruksi_list {
                self.ganti_konstanta_di_operand(&mut stmt.operand_satu);
                self.ganti_konstanta_di_operand(&mut stmt.operand_dua);
                for op in &mut stmt.operand_tambahan {
                    self.ganti_konstanta_di_operand(op);
                }
            }
        }
        cfg.blocks.retain(|id, _| self.visited_blocks.contains(id) || *id == cfg.entry_point);
        for block in cfg.blocks.values_mut() {
            block.successors.retain(|succ| self.visited_blocks.contains(succ));
        }
    }
    fn proses_phi_nodes(&mut self, cfg: &ControlFlowGraph, block_id: u64) {
        let block = match cfg.blocks.get(&block_id) {
            Some(b) => b,
            None => return,
        };
        let preds = &block.predecessors;
        for stmt in &block.instruksi_list {
            if stmt.operation_code != OperasiIr::Phi { break; }
            if let TipeOperand::SsaVariable(dest, ver) = &stmt.operand_satu {
                let dest_key = format!("{}_{}", dest, ver);
                let mut merged_val = StatusLattice::Top;
                for (i, pred_id) in preds.iter().enumerate() {
                    if self.executable_edges.contains(&(*pred_id, block_id)) {
                        if i < stmt.operand_tambahan.len() {
                            let val = self.evaluasi_operand(&stmt.operand_tambahan[i]);
                            merged_val = self.meet_lattice(merged_val, val);
                        }
                    }
                }
                self.update_lattice(&dest_key, merged_val);
            }
        }
    }
    fn visit_instruksi_block(&mut self, cfg: &ControlFlowGraph, block_id: u64) {
        let block = cfg.blocks.get(&block_id).unwrap();
        for stmt in &block.instruksi_list {
            if stmt.operation_code == OperasiIr::Phi { continue; }
            self.evaluasi_instruksi(stmt, block_id, cfg);
        }
    }
    fn visit_uses(&mut self, cfg: &ControlFlowGraph, var_name: &str) {
        for (bid, block) in &cfg.blocks {
            if !self.visited_blocks.contains(bid) { continue; }
            for stmt in &block.instruksi_list {
                if self.stmt_uses_var(stmt, var_name) {
                    self.evaluasi_instruksi(stmt, *bid, cfg);
                }
            }
        }
    }
    fn stmt_uses_var(&self, stmt: &StatementIr, var: &str) -> bool {
        self.operand_uses_var(&stmt.operand_satu, var) || 
        self.operand_uses_var(&stmt.operand_dua, var) ||
        stmt.operand_tambahan.iter().any(|op| self.operand_uses_var(op, var))
    }
    fn operand_uses_var(&self, op: &TipeOperand, var: &str) -> bool {
        match op {
            TipeOperand::SsaVariable(n, v) => format!("{}_{}", n, v) == var,
            TipeOperand::Expression { operand_kiri, operand_kanan, .. } => 
                self.operand_uses_var(operand_kiri, var) || self.operand_uses_var(operand_kanan, var),
            _ => false
        }
    }
    fn evaluasi_instruksi(&mut self, stmt: &StatementIr, block_id: u64, cfg: &ControlFlowGraph) {
        if let TipeOperand::SsaVariable(dest, ver) = &stmt.operand_satu {
             let dest_key = format!("{}_{}", dest, ver);
             let result = match stmt.operation_code {
                 OperasiIr::Mov => self.evaluasi_operand(&stmt.operand_dua),
                 OperasiIr::Add | OperasiIr::Sub | OperasiIr::Imul | 
                 OperasiIr::And | OperasiIr::Or | OperasiIr::Xor | 
                 OperasiIr::Shl | OperasiIr::Shr => self.evaluasi_operand(&stmt.operand_dua),
                 _ => StatusLattice::Bottom,
             };
             self.update_lattice(&dest_key, result);
        }
        match stmt.operation_code {
            OperasiIr::Jmp => {
                if let TipeOperand::Immediate(target) = stmt.operand_satu {
                    self.flow_worklist.push_back((block_id, target as u64));
                }
            },
            OperasiIr::Je | OperasiIr::Jne | OperasiIr::Jg | OperasiIr::Jle => {
                let cond_val = self.evaluasi_operand(&stmt.operand_dua);
                let successors = &cfg.blocks.get(&block_id).unwrap().successors; 
                if successors.len() == 2 {
                    match cond_val {
                        StatusLattice::Constant(c) => {
                            let taken = self.eval_branch_condition(stmt.operation_code.clone(), c);
                            let idx = if taken { 0 } else { 1 };
                            self.flow_worklist.push_back((block_id, successors[idx]));
                        },
                        StatusLattice::Bottom => {
                            self.flow_worklist.push_back((block_id, successors[0]));
                            self.flow_worklist.push_back((block_id, successors[1]));
                        },
                        StatusLattice::Top => {}
                    }
                } else {
                    for &succ in successors {
                        self.flow_worklist.push_back((block_id, succ));
                    }
                }
            },
            _ => {
                 let block = cfg.blocks.get(&block_id).unwrap();
                 if std::ptr::eq(stmt, block.instruksi_list.last().unwrap()) {
                    for &succ in &block.successors {
                        self.flow_worklist.push_back((block_id, succ));
                    }
                }
            }
        }
    }
    fn eval_branch_condition(&self, op: OperasiIr, val: i64) -> bool {
        match op {
            OperasiIr::Je => val != 0,
            OperasiIr::Jne => val != 0, 
            _ => val != 0
        }
    }
    fn evaluasi_operand(&self, op: &TipeOperand) -> StatusLattice {
        match op {
            TipeOperand::Immediate(val) => StatusLattice::Constant(*val),
            TipeOperand::SsaVariable(n, v) => {
                self.lattice_values.get(&format!("{}_{}", n, v)).cloned().unwrap_or(StatusLattice::Top)
            },
            TipeOperand::Expression { operand_kiri, operand_kanan, operasi } => {
                let v1 = self.evaluasi_operand(operand_kiri);
                let v2 = self.evaluasi_operand(operand_kanan);
                match (v1, v2) {
                    (StatusLattice::Constant(c1), StatusLattice::Constant(c2)) => {
                        match operasi {
                            OperasiIr::Add => StatusLattice::Constant(c1.wrapping_add(c2)),
                            OperasiIr::Sub => StatusLattice::Constant(c1.wrapping_sub(c2)),
                            OperasiIr::Imul => StatusLattice::Constant(c1.wrapping_mul(c2)),
                            OperasiIr::Div => if c2 != 0 { StatusLattice::Constant(c1.wrapping_div(c2)) } else { StatusLattice::Bottom },
                            OperasiIr::And => StatusLattice::Constant(c1 & c2),
                            OperasiIr::Or => StatusLattice::Constant(c1 | c2),
                            OperasiIr::Xor => StatusLattice::Constant(c1 ^ c2),
                            OperasiIr::Shl => StatusLattice::Constant(c1 << (c2 as u32)),
                            OperasiIr::Shr => StatusLattice::Constant(c1 >> (c2 as u32)),
                            _ => StatusLattice::Bottom,
                        }
                    },
                    (StatusLattice::Bottom, _) | (_, StatusLattice::Bottom) => StatusLattice::Bottom,
                    _ => StatusLattice::Top,
                }
            },
             TipeOperand::FloatImmediate(_) => {
                StatusLattice::Bottom 
            },
            _ => StatusLattice::Bottom,
        }
    }
    fn meet_lattice(&self, l1: StatusLattice, l2: StatusLattice) -> StatusLattice {
        match (l1, l2) {
            (StatusLattice::Top, x) | (x, StatusLattice::Top) => x,
            (StatusLattice::Bottom, _) | (_, StatusLattice::Bottom) => StatusLattice::Bottom,
            (StatusLattice::Constant(c1), StatusLattice::Constant(c2)) => {
                if c1 == c2 { StatusLattice::Constant(c1) } else { StatusLattice::Bottom }
            }
        }
    }
    fn update_lattice(&mut self, key: &str, new_val: StatusLattice) {
        let old_val = self.lattice_values.get(key).cloned().unwrap_or(StatusLattice::Top);
        if old_val != new_val {
            self.lattice_values.insert(key.to_string(), new_val);
            self.ssa_worklist.push_back(key.to_string());
        }
    }
    fn ganti_konstanta_di_operand(&self, op: &mut TipeOperand) {
        match op {
            TipeOperand::SsaVariable(n, v) => {
                let key = format!("{}_{}", n, v);
                if let Some(StatusLattice::Constant(c)) = self.lattice_values.get(&key) {
                    *op = TipeOperand::Immediate(*c);
                }
            },
            TipeOperand::Expression { operand_kiri, operand_kanan, .. } => {
                self.ganti_konstanta_di_operand(operand_kiri);
                self.ganti_konstanta_di_operand(operand_kanan);
            },
            _ => {}
        }
    }
}