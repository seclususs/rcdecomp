use std::collections::{HashMap, HashSet};
use crate::ir::types::{TipeOperand, OperasiIr, StatementIr};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MemoryRegion {
    Global(u64),
    Stack(i64),
    Heap(u64),
    Symbolic(String),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HasilAliasing {
    MustAlias,
    MayAlias,
    NoAlias,
}

#[derive(Clone, Debug)]
pub struct StatePointer {
    pub base_region: MemoryRegion,
    pub offset: i64,
    pub index_scale: Option<(String, i64)>, 
    pub is_escaped: bool,
}

pub struct AliasAnalyzer {
    peta_state_pointer: HashMap<String, StatePointer>,
    set_variabel_escaped: HashSet<String>,
}

impl AliasAnalyzer {
    pub fn new() -> Self {
        Self {
            peta_state_pointer: HashMap::new(),
            set_variabel_escaped: HashSet::new(),
        }
    }
    pub fn analisis_pointer_lanjutan(&mut self, stmts: &[StatementIr], frame_pointer: &str) {
        self.peta_state_pointer.clear();
        self.set_variabel_escaped.clear();
        self.peta_state_pointer.insert(frame_pointer.to_string(), StatePointer {
            base_region: MemoryRegion::Stack(0),
            offset: 0,
            index_scale: None,
            is_escaped: false,
        });
        for stmt in stmts {
            match &stmt.operation_code {
                OperasiIr::Mov | OperasiIr::Lea | OperasiIr::VecMov => {
                    self.proses_propagasi_pointer(&stmt.operand_satu, &stmt.operand_dua, frame_pointer);
                },
                OperasiIr::Add | OperasiIr::Sub => {
                    self.proses_aritmatika_linear(stmt);
                },
                OperasiIr::Imul | OperasiIr::Shl => {
                    if let Some(dest) = self.extract_nama_variabel(&stmt.operand_satu) {
                        self.peta_state_pointer.remove(&dest);
                    }
                },
                OperasiIr::And => {
                    self.handle_pointer_masking(stmt);
                },
                OperasiIr::Call => {
                    self.proses_instruksi_call(stmt);
                },
                _ => {
                    if let Some(dest) = self.extract_nama_variabel(&stmt.operand_satu) {
                        self.peta_state_pointer.remove(&dest);
                    }
                }
            }
            if matches!(stmt.operation_code, OperasiIr::Mov | OperasiIr::VecMov) {
                if let TipeOperand::MemoryRef { .. } = &stmt.operand_satu {
                    self.tandai_sebagai_escaped(&stmt.operand_dua);
                } else if let TipeOperand::Memory(_) = &stmt.operand_satu {
                    self.tandai_sebagai_escaped(&stmt.operand_dua);
                }
            }
        }
    }
    fn proses_propagasi_pointer(&mut self, dest: &TipeOperand, src: &TipeOperand, fp: &str) {
        let dest_name = match self.extract_nama_variabel(dest) {
            Some(n) => n,
            None => return,
        };
        match src {
            TipeOperand::Register(r) | TipeOperand::SsaVariable(r, _) => {
                if let Some(state) = self.peta_state_pointer.get(r) {
                    self.peta_state_pointer.insert(dest_name, state.clone());
                } else if r == fp {
                    self.peta_state_pointer.insert(dest_name, StatePointer {
                        base_region: MemoryRegion::Stack(0),
                        offset: 0,
                        index_scale: None,
                        is_escaped: false,
                    });
                } else {
                    self.peta_state_pointer.insert(dest_name, StatePointer {
                        base_region: MemoryRegion::Symbolic(r.clone()),
                        offset: 0,
                        index_scale: None,
                        is_escaped: false, 
                    });
                }
            },
            TipeOperand::MemoryRef { base, offset } => {
                if let Some(base_state) = self.peta_state_pointer.get(base) {
                    let mut new_state = base_state.clone();
                    new_state.offset += offset;
                    self.peta_state_pointer.insert(dest_name, new_state);
                } else {
                    self.peta_state_pointer.remove(&dest_name);
                }
            },
            _ => {
                self.peta_state_pointer.remove(&dest_name);
            }
        }
    }
    fn proses_aritmatika_linear(&mut self, stmt: &StatementIr) {
        let dest = match self.extract_nama_variabel(&stmt.operand_satu) {
            Some(n) => n,
            None => return,
        };
        let mut base_state: Option<StatePointer> = None;
        let mut delta: i64 = 0;
        if let Some(state) = self.peta_state_pointer.get(&dest) {
            base_state = Some(state.clone());
        }
        match &stmt.operand_dua {
            TipeOperand::Immediate(val) => {
                delta = *val;
            },
            TipeOperand::Register(r) | TipeOperand::SsaVariable(r, _) => {
                 if base_state.is_none() {
                     if let Some(src_state) = self.peta_state_pointer.get(r) {
                         base_state = Some(src_state.clone());
                     }
                 } else {
                     if let Some(mut state) = base_state {
                        if state.index_scale.is_none() {
                            state.index_scale = Some((r.clone(), 1));
                            self.peta_state_pointer.insert(dest, state);
                            return;
                        } else {
                            self.peta_state_pointer.remove(&dest);
                            return;
                        }
                     }
                 }
            }
            _ => {}
        }
        if let Some(mut state) = base_state {
            if stmt.operation_code == OperasiIr::Sub {
                state.offset -= delta;
            } else {
                state.offset += delta;
            }
            self.peta_state_pointer.insert(dest, state);
        } else {
            self.peta_state_pointer.remove(&dest);
        }
    }
    fn handle_pointer_masking(&mut self, stmt: &StatementIr) {
        let dest = match self.extract_nama_variabel(&stmt.operand_satu) {
            Some(n) => n,
            None => return,
        };
        if let Some(state) = self.peta_state_pointer.get(&dest).cloned() {
            let mut new_state = state;
            new_state.offset = 0; 
            self.peta_state_pointer.insert(dest, new_state);
        }
    }
    fn proses_instruksi_call(&mut self, stmt: &StatementIr) {
        for arg in &stmt.operand_tambahan {
            self.tandai_sebagai_escaped(arg);
        }
        if let TipeOperand::Register(reg) = &stmt.operand_satu {
            self.peta_state_pointer.insert(reg.clone(), StatePointer {
                base_region: MemoryRegion::Heap(stmt.address_asal),
                offset: 0,
                index_scale: None,
                is_escaped: true,
            });
        }
    }
    fn tandai_sebagai_escaped(&mut self, op: &TipeOperand) {
        if let Some(name) = self.extract_nama_variabel(op) {
            self.set_variabel_escaped.insert(name.clone());
            if let Some(mut state) = self.peta_state_pointer.get(&name).cloned() {
                state.is_escaped = true;
                self.peta_state_pointer.insert(name, state);
            }
        }
    }
    pub fn infer_region_state(&self, op: &TipeOperand, frame_pointer: &str) -> Option<StatePointer> {
        match op {
            TipeOperand::Register(r) | TipeOperand::SsaVariable(r, _) => {
                if r == frame_pointer {
                    return Some(StatePointer {
                        base_region: MemoryRegion::Stack(0),
                        offset: 0,
                        index_scale: None,
                        is_escaped: false,
                    });
                }
                self.peta_state_pointer.get(r).cloned()
            },
            TipeOperand::MemoryRef { base, offset } => {
                if let Some(base_state) = self.infer_region_state(&TipeOperand::Register(base.clone()), frame_pointer) {
                    let mut refined = base_state;
                    refined.offset += offset;
                    Some(refined)
                } else {
                    None
                }
            },
            TipeOperand::Expression { operand_kiri, operand_kanan, operasi } => {
                 match operasi {
                     OperasiIr::Add => {
                         let left = self.infer_region_state(operand_kiri, frame_pointer);
                         if let Some(mut s) = left {
                             if let TipeOperand::Immediate(val) = **operand_kanan {
                                 s.offset += val;
                                 return Some(s);
                             }
                         }
                         None
                     },
                     _ => None
                 }
            },
            _ => None
        }
    }
    pub fn is_escaped(&self, var_name: &str) -> bool {
        if self.set_variabel_escaped.contains(var_name) { return true; }
        if let Some(state) = self.peta_state_pointer.get(var_name) {
            return state.is_escaped;
        }
        false
    }
    fn extract_nama_variabel(&self, op: &TipeOperand) -> Option<String> {
        match op {
            TipeOperand::Register(r) => Some(r.clone()),
            TipeOperand::SsaVariable(n, _) => Some(n.clone()),
            _ => None
        }
    }
}