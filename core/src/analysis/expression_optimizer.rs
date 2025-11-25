use std::collections::{HashMap, HashSet};
use crate::ir::types::{OperasiIr, TipeOperand};
use crate::analysis::cfg::ControlFlowGraph;
use log::debug;

pub struct ExpressionOptimizer;

impl ExpressionOptimizer {
    pub fn new() -> Self {
        Self
    }
    pub fn jalankan_optimasi(&self, cfg: &mut ControlFlowGraph) {
        let mut changed = true;
        let mut iterasi = 0;
        while changed && iterasi < 10 {
            changed = false;
            let usage_counts = self.hitung_usage(cfg);
            let definitions = self.petakan_definisi(cfg);
            let folded_vars = self.terapkan_folding(cfg, &usage_counts, &definitions);
            if !folded_vars.is_empty() {
                changed = true;
                self.hapus_dead_definitions(cfg, &folded_vars);
                debug!("Iterasi {}: Melipat {} ekspresi.", iterasi + 1, folded_vars.len());
            }
            iterasi += 1;
        }
        self.sederhanakan_ekspresi(cfg);
    }
    fn hitung_usage(&self, cfg: &ControlFlowGraph) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for block in cfg.blocks.values() {
            for stmt in &block.instruksi_list {
                self.visit_operand(&stmt.operand_dua, &mut counts);
                match stmt.operation_code {
                    OperasiIr::Cmp | OperasiIr::Test | OperasiIr::Call => {
                         self.visit_operand(&stmt.operand_satu, &mut counts);
                    },
                    _ => {}
                }
                for op in &stmt.operand_tambahan {
                    self.visit_operand(op, &mut counts);
                }
            }
        }
        counts
    }
    fn visit_operand(&self, op: &TipeOperand, counts: &mut HashMap<String, usize>) {
        match op {
            TipeOperand::SsaVariable(name, ver) => {
                let key = format!("{}_{}", name, ver);
                *counts.entry(key).or_insert(0) += 1;
            },
            TipeOperand::Expression { operand_kiri, operand_kanan, .. } => {
                self.visit_operand(operand_kiri, counts);
                self.visit_operand(operand_kanan, counts);
            },
            _ => {}
        }
    }
    fn petakan_definisi(&self, cfg: &ControlFlowGraph) -> HashMap<String, (OperasiIr, TipeOperand, TipeOperand)> {
        let mut defs = HashMap::new();
        for block in cfg.blocks.values() {
            for stmt in &block.instruksi_list {
                if self.is_foldable_op(&stmt.operation_code) {
                    if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_satu {
                        let key = format!("{}_{}", name, ver);
                        defs.insert(key, (
                            stmt.operation_code.clone(),
                            stmt.operand_dua.clone(),
                            TipeOperand::None
                        ));
                    }
                }
            }
        }
        defs
    }
    fn is_foldable_op(&self, op: &OperasiIr) -> bool {
        match op {
            OperasiIr::Mov | OperasiIr::Add | OperasiIr::Sub | 
            OperasiIr::Imul | OperasiIr::Div |
            OperasiIr::And | OperasiIr::Or | OperasiIr::Xor | 
            OperasiIr::Shl | OperasiIr::Shr => true,
            _ => false
        }
    }
    fn terapkan_folding(
        &self, 
        cfg: &mut ControlFlowGraph, 
        counts: &HashMap<String, usize>,
        defs: &HashMap<String, (OperasiIr, TipeOperand, TipeOperand)>
    ) -> HashSet<String> {
        let mut folded = HashSet::new();
        for block in cfg.blocks.values_mut() {
            for stmt in &mut block.instruksi_list {
                if let Some(replaced) = self.try_fold_operand(&stmt.operand_dua, counts, defs, &mut folded) {
                    stmt.operand_dua = replaced;
                }
                match stmt.operation_code {
                    OperasiIr::Cmp | OperasiIr::Test | OperasiIr::Call => {
                        if let Some(replaced) = self.try_fold_operand(&stmt.operand_satu, counts, defs, &mut folded) {
                            stmt.operand_satu = replaced;
                        }
                    },
                    _ => {}
                }
                for i in 0..stmt.operand_tambahan.len() {
                    if let Some(replaced) = self.try_fold_operand(&stmt.operand_tambahan[i], counts, defs, &mut folded) {
                        stmt.operand_tambahan[i] = replaced;
                    }
                }
            }
        }
        folded
    }
    fn try_fold_operand(
        &self, 
        op: &TipeOperand,
        counts: &HashMap<String, usize>,
        defs: &HashMap<String, (OperasiIr, TipeOperand, TipeOperand)>,
        folded_set: &mut HashSet<String>
    ) -> Option<TipeOperand> {
        if let TipeOperand::SsaVariable(name, ver) = op {
            let key = format!("{}_{}", name, ver);
            if let Some(&count) = counts.get(&key) {
                if count == 1 {
                    if let Some((def_op, def_src, _)) = defs.get(&key) {
                        folded_set.insert(key);
                        if *def_op == OperasiIr::Mov {
                            return Some(def_src.clone());
                        } 
                         return Some(def_src.clone());
                    }
                }
            }
        }
        if let TipeOperand::Expression { operasi, operand_kiri, operand_kanan } = op {
            let new_kiri = self.try_fold_operand(operand_kiri, counts, defs, folded_set);
            let new_kanan = self.try_fold_operand(operand_kanan, counts, defs, folded_set);
            if new_kiri.is_some() || new_kanan.is_some() {
                return Some(TipeOperand::Expression {
                    operasi: operasi.clone(),
                    operand_kiri: Box::new(new_kiri.unwrap_or(*operand_kiri.clone())),
                    operand_kanan: Box::new(new_kanan.unwrap_or(*operand_kanan.clone())),
                });
            }
        }
        None
    }
    fn hapus_dead_definitions(&self, cfg: &mut ControlFlowGraph, folded_vars: &HashSet<String>) {
        for block in cfg.blocks.values_mut() {
            block.instruksi_list.retain(|stmt| {
                if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_satu {
                    let key = format!("{}_{}", name, ver);
                    if folded_vars.contains(&key) {
                        return false;
                    }
                }
                true
            });
        }
    }
    fn sederhanakan_ekspresi(&self, cfg: &mut ControlFlowGraph) {
        for block in cfg.blocks.values_mut() {
            for stmt in &mut block.instruksi_list {
                self.simplify_operand(&mut stmt.operand_dua);
                if let TipeOperand::Expression { .. } = stmt.operand_satu {
                     self.simplify_operand(&mut stmt.operand_satu);
                }
            }
        }
    }
    fn simplify_operand(&self, op: &mut TipeOperand) {
        match op {
            TipeOperand::Expression { operasi, operand_kiri, operand_kanan } => {
                self.simplify_operand(operand_kiri);
                self.simplify_operand(operand_kanan);
                if *operasi == OperasiIr::Add {
                    if let TipeOperand::Immediate(0) = **operand_kanan {
                        *op = *operand_kiri.clone();
                        return;
                    }
                }
                if *operasi == OperasiIr::Imul {
                    if let TipeOperand::Immediate(1) = **operand_kanan {
                        *op = *operand_kiri.clone();
                        return;
                    }
                }
            },
            _ => {}
        }
    }
}