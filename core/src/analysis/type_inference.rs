use std::collections::{HashMap, HashSet, BTreeMap};
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TipePrimitif {
    Unknown,
    Void,
    Integer(u8),
    Float,
    Pointer(Box<TipePrimitif>),
    Struct(String),
}

#[derive(Debug, Clone)]
pub struct SignatureFungsi {
    pub return_type: TipePrimitif,
    pub arg_types: Vec<TipePrimitif>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConstraintTipe {
    Equal(String, String),
    IsType(String, TipePrimitif),
    ArgPass(String, u64, usize),
    ReturnUse(String, u64),
}

pub struct TypeSystem {
    pub global_signatures: HashMap<u64, SignatureFungsi>,
    pub variable_types: HashMap<String, TipePrimitif>,
    constraints: HashSet<ConstraintTipe>,
}

impl TypeSystem {
    pub fn new() -> Self {
        Self {
            global_signatures: HashMap::new(),
            variable_types: HashMap::new(),
            constraints: HashSet::new(),
        }
    }
    pub fn analisis_interprosedural(&mut self, all_functions_stmts: &HashMap<u64, Vec<StatementIr>>) {
        for (addr, _) in all_functions_stmts {
            self.global_signatures.insert(*addr, SignatureFungsi {
                return_type: TipePrimitif::Unknown,
                arg_types: vec![TipePrimitif::Unknown; 8], 
            });
        }
        for (_, stmts) in all_functions_stmts {
            self.kumpulkan_constraints_lokal(stmts);
        }
        let mut changed = true;
        while changed {
            changed = self.selesaikan_iterasi();
        }
    }
    fn kumpulkan_constraints_lokal(&mut self, stmts: &[StatementIr]) {
        for stmt in stmts {
            match stmt.operation_code {
                OperasiIr::Mov => {
                    if let (Some(dest), Some(src)) = (self.var_name(&stmt.operand_satu), self.var_name(&stmt.operand_dua)) {
                        self.constraints.insert(ConstraintTipe::Equal(dest, src));
                    } else if let Some(dest) = self.var_name(&stmt.operand_satu) {
                        if let TipeOperand::Immediate(_) = stmt.operand_dua {
                            self.constraints.insert(ConstraintTipe::IsType(dest, TipePrimitif::Integer(8)));
                        }
                    }
                },
                OperasiIr::Add | OperasiIr::Sub | OperasiIr::Imul => {
                     if let Some(dest) = self.var_name(&stmt.operand_satu) {
                         self.constraints.insert(ConstraintTipe::IsType(dest, TipePrimitif::Integer(8)));
                     }
                },
                OperasiIr::Call => {
                    if let TipeOperand::Immediate(target_addr) = stmt.operand_satu {
                        let addr = target_addr as u64;
                        for (idx, arg_op) in stmt.operand_tambahan.iter().enumerate() {
                            if let Some(var_arg) = self.var_name(arg_op) {
                                self.constraints.insert(ConstraintTipe::ArgPass(var_arg, addr, idx));
                            }
                        }
                    }
                },
                _ => {}
            }
        }
    }
    fn selesaikan_iterasi(&mut self) -> bool {
        let mut changed = false;
        let active_constraints: Vec<ConstraintTipe> = self.constraints.iter().cloned().collect();
        for cons in active_constraints {
            match cons {
                ConstraintTipe::IsType(var, tipe) => {
                    if self.update_tipe_variabel(&var, tipe) { changed = true; }
                },
                ConstraintTipe::Equal(v1, v2) => {
                    let t1 = self.variable_types.get(&v1).cloned().unwrap_or(TipePrimitif::Unknown);
                    let t2 = self.variable_types.get(&v2).cloned().unwrap_or(TipePrimitif::Unknown);
                    if t1 != TipePrimitif::Unknown && t2 == TipePrimitif::Unknown {
                        if self.update_tipe_variabel(&v2, t1) { changed = true; }
                    } else if t2 != TipePrimitif::Unknown && t1 == TipePrimitif::Unknown {
                         if self.update_tipe_variabel(&v1, t2) { changed = true; }
                    }
                },
                ConstraintTipe::ArgPass(var, func_addr, arg_idx) => {
                    let var_type = self.variable_types.get(&var).cloned().unwrap_or(TipePrimitif::Unknown);
                    let mut target_sig_type = TipePrimitif::Unknown;
                    let mut should_update_sig = false;
                    let mut should_update_var = false;
                    if let Some(sig) = self.global_signatures.get_mut(&func_addr) {
                        if arg_idx < sig.arg_types.len() {
                             if var_type != TipePrimitif::Unknown && sig.arg_types[arg_idx] == TipePrimitif::Unknown {
                                 sig.arg_types[arg_idx] = var_type.clone();
                                 should_update_sig = true;
                             } else if sig.arg_types[arg_idx] != TipePrimitif::Unknown && var_type == TipePrimitif::Unknown {
                                 target_sig_type = sig.arg_types[arg_idx].clone();
                                 should_update_var = true;
                             }
                        }
                    }
                    if should_update_sig {
                        changed = true;
                    }
                    if should_update_var {
                        if self.update_tipe_variabel(&var, target_sig_type) { changed = true; }
                    }
                },
                ConstraintTipe::ReturnUse(_, _) => {}
            }
        }
        changed
    }
    fn update_tipe_variabel(&mut self, var: &str, tipe: TipePrimitif) -> bool {
        if let Some(existing) = self.variable_types.get(var) {
            if *existing == tipe { return false; }
            if *existing != TipePrimitif::Unknown { 
                return false; 
            }
        }
        self.variable_types.insert(var.to_string(), tipe);
        true
    }
    fn var_name(&self, op: &TipeOperand) -> Option<String> {
        match op {
            TipeOperand::Register(r) => Some(r.clone()),
            TipeOperand::SsaVariable(n, v) => Some(format!("{}_{}", n, v)),
            _ => None
        }
    }
    pub fn dapatkan_tipe_c(&self, reg_name: &str) -> String {
        match self.variable_types.get(reg_name) {
            Some(TipePrimitif::Pointer(_)) => "void*".to_string(),
            Some(TipePrimitif::Integer(_)) => "long".to_string(),
            Some(TipePrimitif::Struct(name)) => format!("{}*", name),
            _ => "long".to_string(),
        }
    }
    pub fn definisi_struct(&self) -> BTreeMap<String, BTreeMap<i64, String>> {
        BTreeMap::new()
    }
}