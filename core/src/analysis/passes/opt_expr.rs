use std::collections::{HashMap};
use crate::ir::types::{OperasiIr, TipeOperand, OrderedFloat};
use crate::analysis::graph::cfg::ControlFlowGraph;
use log::{info};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExpressionKey {
    opcode: OperasiIr,
    op1_vn: u32,
    op2_vn: u32,
    extra: u64, 
}

pub struct ExpressionOptimizer {
    value_number_map: HashMap<TipeOperand, u32>, 
    expression_to_vn: HashMap<ExpressionKey, u32>,
    vn_to_operand: HashMap<u32, TipeOperand>,
    next_vn: u32,
}

impl ExpressionOptimizer {
    pub fn new() -> Self {
        Self {
            value_number_map: HashMap::new(),
            expression_to_vn: HashMap::new(),
            vn_to_operand: HashMap::new(),
            next_vn: 1,
        }
    }
    pub fn jalankan_optimasi(&mut self, cfg: &mut ControlFlowGraph) {
        self.jalankan_gvn(cfg);
        self.sederhanakan_ekspresi_global(cfg);
    }
    fn jalankan_gvn(&mut self, cfg: &mut ControlFlowGraph) {
        info!("Menjalankan Global Value Numbering (GVN)...");
        self.reset_state();
        let mut sorted_ids: Vec<u64> = cfg.blocks.keys().cloned().collect();
        sorted_ids.sort();
        for block_id in sorted_ids {
            if let Some(block) = cfg.blocks.get_mut(&block_id) {
                let mut instruksi_baru = Vec::new();
                for mut stmt in block.instruksi_list.drain(..) {
                    self.simplify_operand_local(&mut stmt.operand_dua);
                    if let TipeOperand::Expression { .. } = &mut stmt.operand_satu {
                         self.simplify_operand_local(&mut stmt.operand_satu);
                    }
                    match stmt.operation_code {
                        OperasiIr::Mov | OperasiIr::Add | OperasiIr::Sub | 
                        OperasiIr::Imul | OperasiIr::Div | OperasiIr::And | 
                        OperasiIr::Or | OperasiIr::Xor | OperasiIr::Shl | 
                        OperasiIr::Shr | OperasiIr::VecAdd | OperasiIr::VecSub | 
                        OperasiIr::VecMul | OperasiIr::VecDiv | OperasiIr::VecAnd | 
                        OperasiIr::VecOr | OperasiIr::VecXor => {
                            if let TipeOperand::SsaVariable(_, _) = &stmt.operand_satu {
                                let dest_op = stmt.operand_satu.clone();
                                let vn_rhs = self.hitung_vn_untuk_operand(&stmt.operand_dua);
                                if let Some(canonical_op) = self.vn_to_operand.get(&vn_rhs) {
                                    if canonical_op != &dest_op {
                                        stmt.operation_code = OperasiIr::Mov;
                                        stmt.operand_dua = canonical_op.clone();
                                        self.value_number_map.insert(dest_op, vn_rhs);
                                        instruksi_baru.push(stmt);
                                        continue;
                                    }
                                } else {
                                    self.vn_to_operand.insert(vn_rhs, stmt.operand_dua.clone());
                                }
                                self.value_number_map.insert(dest_op, vn_rhs);
                            }
                        },
                        OperasiIr::Phi => {
                            if let TipeOperand::SsaVariable(_, _) = &stmt.operand_satu {
                                let vn = self.alokasi_vn_baru();
                                self.value_number_map.insert(stmt.operand_satu.clone(), vn);
                                self.vn_to_operand.insert(vn, stmt.operand_satu.clone());
                            }
                        }
                        _ => {}
                    }
                    instruksi_baru.push(stmt);
                }
                block.instruksi_list = instruksi_baru;
            }
        }
    }
    fn reset_state(&mut self) {
        self.value_number_map.clear();
        self.expression_to_vn.clear();
        self.vn_to_operand.clear();
        self.next_vn = 1;
    }
    fn alokasi_vn_baru(&mut self) -> u32 {
        let vn = self.next_vn;
        self.next_vn += 1;
        vn
    }
    fn hitung_vn_untuk_operand(&mut self, op: &TipeOperand) -> u32 {
        if let Some(&vn) = self.value_number_map.get(op) {
            return vn;
        }
        match op {
            TipeOperand::SsaVariable(_, _) | TipeOperand::Register(_) => {
                let vn = self.alokasi_vn_baru();
                self.value_number_map.insert(op.clone(), vn);
                self.vn_to_operand.insert(vn, op.clone());
                vn
            },
            TipeOperand::Immediate(val) => {
                let key = ExpressionKey { 
                    opcode: OperasiIr::Unknown, 
                    op1_vn: 0, 
                    op2_vn: 0, 
                    extra: *val as u64 
                };
                self.dapatkan_atau_buat_vn(key, op)
            },
            TipeOperand::FloatImmediate(val) => {
                 let key = ExpressionKey { 
                    opcode: OperasiIr::Unknown, 
                    op1_vn: 0, 
                    op2_vn: 0, 
                    extra: val.0.to_bits()
                };
                self.dapatkan_atau_buat_vn(key, op)
            },
            TipeOperand::Expression { operasi, operand_kiri, operand_kanan } => {
                let vn_left = self.hitung_vn_untuk_operand(operand_kiri);
                let vn_right = self.hitung_vn_untuk_operand(operand_kanan);
                let (v1, v2) = if self.is_commutative(operasi) && vn_left > vn_right {
                    (vn_right, vn_left)
                } else {
                    (vn_left, vn_right)
                };
                let key = ExpressionKey { 
                    opcode: operasi.clone(), 
                    op1_vn: v1, 
                    op2_vn: v2, 
                    extra: 0 
                };
                self.dapatkan_atau_buat_vn(key, op)
            },
            _ => self.alokasi_vn_baru(),
        }
    }
    fn dapatkan_atau_buat_vn(&mut self, key: ExpressionKey, original_op: &TipeOperand) -> u32 {
        if let Some(&vn) = self.expression_to_vn.get(&key) {
            vn
        } else {
            let vn = self.alokasi_vn_baru();
            self.expression_to_vn.insert(key, vn);
            self.vn_to_operand.insert(vn, original_op.clone());
            vn
        }
    }
    fn is_commutative(&self, op: &OperasiIr) -> bool {
        matches!(op, 
            OperasiIr::Add | OperasiIr::Imul | 
            OperasiIr::And | OperasiIr::Or | OperasiIr::Xor | 
            OperasiIr::VecAdd | OperasiIr::VecMul | 
            OperasiIr::VecAnd | OperasiIr::VecOr | OperasiIr::VecXor |
            OperasiIr::FAdd | OperasiIr::FMul
        )
    }
    fn sederhanakan_ekspresi_global(&self, cfg: &mut ControlFlowGraph) {
        for block in cfg.blocks.values_mut() {
            for stmt in &mut block.instruksi_list {
                self.simplify_operand_local(&mut stmt.operand_dua);
                if let TipeOperand::Expression { .. } = stmt.operand_satu {
                     self.simplify_operand_local(&mut stmt.operand_satu);
                }
            }
        }
    }
    fn simplify_operand_local(&self, op: &mut TipeOperand) {
        match op {
            TipeOperand::Expression { operasi, operand_kiri, operand_kanan } => {
                self.simplify_operand_local(operand_kiri);
                self.simplify_operand_local(operand_kanan);
                match operasi {
                    OperasiIr::Add => {
                        if let TipeOperand::Immediate(0) = **operand_kanan {
                            *op = *operand_kiri.clone(); return;
                        }
                        if let TipeOperand::Immediate(0) = **operand_kiri {
                            *op = *operand_kanan.clone(); return;
                        }
                    },
                    OperasiIr::Imul => {
                        if let TipeOperand::Immediate(1) = **operand_kanan {
                            *op = *operand_kiri.clone(); return;
                        }
                        if let TipeOperand::Immediate(0) = **operand_kanan {
                            *op = TipeOperand::Immediate(0); return;
                        }
                    },
                    OperasiIr::Sub => {
                         if let TipeOperand::Immediate(0) = **operand_kanan {
                            *op = *operand_kiri.clone(); return;
                        }
                        if operand_kiri == operand_kanan {
                            *op = TipeOperand::Immediate(0); return;
                        }
                    },
                    OperasiIr::Div => {
                        if let TipeOperand::Immediate(1) = **operand_kanan {
                            *op = *operand_kiri.clone(); return;
                        }
                        if operand_kiri == operand_kanan {
                            *op = TipeOperand::Immediate(1); return;
                        }
                    }
                    _ => {}
                }
                let folded_int = if let (TipeOperand::Immediate(v1), TipeOperand::Immediate(v2)) = (&**operand_kiri, &**operand_kanan) {
                    match operasi {
                        OperasiIr::Add => Some(v1.wrapping_add(*v2)),
                        OperasiIr::Sub => Some(v1.wrapping_sub(*v2)),
                        OperasiIr::Imul => Some(v1.wrapping_mul(*v2)),
                        OperasiIr::Div => if *v2 != 0 { Some(v1.wrapping_div(*v2)) } else { None },
                        OperasiIr::And => Some(v1 & v2),
                        OperasiIr::Or => Some(v1 | v2),
                        OperasiIr::Xor => Some(v1 ^ v2),
                        OperasiIr::Shl => Some(v1 << (*v2 as u32)),
                        OperasiIr::Shr => Some(v1 >> (*v2 as u32)),
                        _ => None
                    }
                } else {
                    None
                };
                if let Some(val) = folded_int {
                    *op = TipeOperand::Immediate(val);
                    return;
                }
                let folded_float = if let (TipeOperand::FloatImmediate(v1), TipeOperand::FloatImmediate(v2)) = (&**operand_kiri, &**operand_kanan) {
                     let f1 = v1.0;
                     let f2 = v2.0;
                     match operasi {
                         OperasiIr::FAdd => Some(f1 + f2),
                         OperasiIr::FSub => Some(f1 - f2),
                         OperasiIr::FMul => Some(f1 * f2),
                         OperasiIr::FDiv => Some(f1 / f2),
                         _ => None
                     }
                } else {
                    None
                };
                if let Some(val) = folded_float {
                    *op = TipeOperand::FloatImmediate(OrderedFloat(val));
                }
            },
            TipeOperand::Conditional { condition, true_val, false_val } => {
                self.simplify_operand_local(condition);
                self.simplify_operand_local(true_val);
                self.simplify_operand_local(false_val);
                if let TipeOperand::Immediate(1) = **condition {
                    *op = *true_val.clone();
                } else if let TipeOperand::Immediate(0) = **condition {
                    *op = *false_val.clone();
                }
            }
            _ => {}
        }
    }
}