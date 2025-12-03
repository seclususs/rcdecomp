use std::collections::{HashMap, HashSet, BTreeMap, VecDeque};
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};
use super::sys::{TypeSystem, ConstraintTipe, TipePrimitif, StructLayout, SignatureFungsi};
use log::{info, warn, debug};

pub struct TypeSolver<'a> {
    sys: &'a mut TypeSystem,
    worklist_queue: VecDeque<u64>,
    processed_functions: HashSet<u64>,
}

impl<'a> TypeSolver<'a> {
    pub fn new(sys: &'a mut TypeSystem) -> Self {
        Self { 
            sys,
            worklist_queue: VecDeque::new(),
            processed_functions: HashSet::new(),
        }
    }
    pub fn jalankan_analisis(&mut self, all_functions_stmts: &HashMap<u64, Vec<StatementIr>>) {
        info!("Memulai Analisis Tipe Interprosedural (Enhanced Union Support)...");
        self.bangun_call_graph(all_functions_stmts);
        for (addr, _) in all_functions_stmts {
            self.sys.global_signatures.entry(*addr).or_insert(SignatureFungsi {
                return_type: TipePrimitif::Unknown,
                arg_types: vec![TipePrimitif::Unknown; 8],
            });
            self.worklist_queue.push_back(*addr);
            self.processed_functions.insert(*addr);
        }
        let mut iterasi_counter = 0;
        let max_iterasi = 15000;
        while let Some(func_addr) = self.worklist_queue.pop_front() {
            self.processed_functions.remove(&func_addr);
            let stmts = match all_functions_stmts.get(&func_addr) {
                Some(s) => s, None => continue,
            };
            let old_sig = self.sys.global_signatures.get(&func_addr).cloned();
            self.kumpulkan_constraints_lokal(stmts, func_addr);
            let local_changed = self.selesaikan_iterasi_constraints();
            let mut inter_changed = false;
            let current_sig = self.sys.global_signatures.get(&func_addr).unwrap();
            if let Some(old) = old_sig {
                if &old != current_sig {
                    inter_changed = true;
                    for &caller in self.sys.call_graph.dapatkan_callers(func_addr) {
                        if !self.processed_functions.contains(&caller) {
                            self.worklist_queue.push_back(caller);
                            self.processed_functions.insert(caller);
                        }
                    }
                }
            }
            let callees: Vec<u64> = self.sys.call_graph.dapatkan_callees(func_addr).cloned().collect();
            for callee_addr in callees {
                if self.propagasi_ke_callee(func_addr, callee_addr, stmts) {
                    if !self.processed_functions.contains(&callee_addr) {
                        self.worklist_queue.push_back(callee_addr);
                        self.processed_functions.insert(callee_addr);
                    }
                }
            }
            if local_changed || inter_changed { 
                iterasi_counter += 1; 
            }
            if iterasi_counter > max_iterasi { 
                warn!("Batas iterasi analisis tipe tercapai ({}).", max_iterasi); 
                break; 
            }
        }
        self.rekonstruksi_struktur_bersarang(); 
        self.finalisasi_tipe();
        info!("Analisis Tipe Selesai dalam {} iterasi.", iterasi_counter);
    }
    fn bangun_call_graph(&mut self, all_functions: &HashMap<u64, Vec<StatementIr>>) {
        for (caller_addr, stmts) in all_functions {
            for stmt in stmts {
                if let OperasiIr::Call = stmt.operation_code {
                    if let TipeOperand::Immediate(target) = stmt.operand_satu {
                        self.sys.call_graph.tambah_edge(*caller_addr, target as u64);
                    }
                }
            }
        }
    }
    fn kumpulkan_constraints_lokal(&mut self, stmts: &[StatementIr], current_func: u64) {
        self.sys.constraints.clear();
        for stmt in stmts {
            self.inferensi_pola_memori(&stmt.operand_satu);
            self.inferensi_pola_memori(&stmt.operand_dua);
            match &stmt.operation_code {
                OperasiIr::Mov | OperasiIr::VecMov | OperasiIr::Lea => {
                    self.analisa_data_movement(&stmt.operand_satu, &stmt.operand_dua);
                },
                OperasiIr::Add => {
                    if let (Some(dest), Some(_base)) = (self.dapatkan_nama_variabel(&stmt.operand_satu), self.dapatkan_nama_variabel(&stmt.operand_dua)) {
                         if let TipeOperand::Expression { operasi: OperasiIr::Add, operand_kiri, operand_kanan } = &stmt.operand_dua {
                             if let (Some(base_var), TipeOperand::Immediate(off)) = (self.dapatkan_nama_variabel(operand_kiri), &**operand_kanan) {
                                  self.sys.constraints.insert(ConstraintTipe::DerivedPointer(dest.clone(), base_var, *off));
                             }
                         } 
                    }
                },
                OperasiIr::Call => {
                    if let TipeOperand::Immediate(target_addr) = stmt.operand_satu {
                        let callee_addr = target_addr as u64;
                        for (idx, arg_op) in stmt.operand_tambahan.iter().enumerate() {
                            if let Some(var_arg) = self.dapatkan_nama_variabel(arg_op) {
                                self.sys.constraints.insert(ConstraintTipe::ArgPass(var_arg, callee_addr, idx));
                            } 
                        }
                        self.sys.constraints.insert(ConstraintTipe::CallResult("rax".to_string(), callee_addr));
                        self.sys.constraints.insert(ConstraintTipe::CallResult("x0".to_string(), callee_addr));
                    }
                },
                OperasiIr::Ret => {
                    self.sys.constraints.insert(ConstraintTipe::ReturnResult("rax".to_string(), current_func));
                    self.sys.constraints.insert(ConstraintTipe::ReturnResult("x0".to_string(), current_func));
                },
                _ => {}
            }
        }
    }
    fn inferensi_pola_memori(&mut self, op: &TipeOperand) {
        if let TipeOperand::Expression { operasi: OperasiIr::Add, operand_kiri, operand_kanan } = op {
            if let Some((base_var, scale_val)) = self.cocokkan_pola_array(operand_kiri, operand_kanan) {
                let elem_type = match scale_val {
                    1 => TipePrimitif::Integer(1),
                    2 => TipePrimitif::Integer(2),
                    4 => TipePrimitif::Integer(4),
                    8 => TipePrimitif::Integer(8),
                    _ => TipePrimitif::Unknown
                };
                self.sys.constraints.insert(ConstraintTipe::IsArrayBase(base_var, elem_type));
            }
        }
    }
    fn cocokkan_pola_array(&self, op1: &TipeOperand, op2: &TipeOperand) -> Option<(String, i64)> {
        if let Some(base) = self.dapatkan_nama_variabel(op1) {
            if let TipeOperand::Expression { operasi: OperasiIr::Imul, operand_kiri: _, operand_kanan } = op2 {
                if let TipeOperand::Immediate(scale) = **operand_kanan {
                    return Some((base, scale));
                }
            }
        }
        if let Some(base) = self.dapatkan_nama_variabel(op2) {
            if let TipeOperand::Expression { operasi: OperasiIr::Imul, operand_kiri: _, operand_kanan } = op1 {
                if let TipeOperand::Immediate(scale) = **operand_kanan {
                    return Some((base, scale));
                }
            }
        }
        None
    }
    fn analisa_data_movement(&mut self, dest: &TipeOperand, src: &TipeOperand) {
        let dest_name = self.dapatkan_nama_variabel(dest);
        let src_name = self.dapatkan_nama_variabel(src);
        if let (Some(d), Some(s)) = (&dest_name, &src_name) {
            self.sys.constraints.insert(ConstraintTipe::Equal(d.clone(), s.clone()));
            return;
        }
        if let Some(d) = dest_name.clone() {
            if let TipeOperand::MemoryRef { base, offset } = src {
                self.sys.constraints.insert(ConstraintTipe::HasField(base.clone(), *offset, d.clone())); 
                return;
            }
            if let TipeOperand::FloatImmediate(_) = src {
                self.sys.constraints.insert(ConstraintTipe::IsType(d, TipePrimitif::Float(4)));
            }
        }
        if let Some(s) = src_name {
            if let TipeOperand::MemoryRef { base, offset } = dest {
                self.sys.constraints.insert(ConstraintTipe::HasField(base.clone(), *offset, s));
                return;
            }
        }
    }
    fn rekonstruksi_struktur_bersarang(&mut self) {
        debug!("Memulai rekonstruksi nested structures...");
        let derived_constraints: Vec<ConstraintTipe> = self.sys.constraints.iter()
            .filter(|c| matches!(c, ConstraintTipe::DerivedPointer(_, _, _)))
            .cloned()
            .collect();
        for cons in derived_constraints {
            if let ConstraintTipe::DerivedPointer(child_var, parent_var, offset) = cons {
                let parent_type = self.sys.variable_types.get(&parent_var).cloned().unwrap_or(TipePrimitif::Unknown);
                if let TipePrimitif::Pointer(inner) = parent_type {
                    if let TipePrimitif::Struct(struct_name) = *inner {
                         if let Some(layout) = self.sys.struct_definitions.get(&struct_name) {
                             if let Some(field_type) = layout.fields.get(&offset) {
                                 let child_type = TipePrimitif::Pointer(Box::new(field_type.clone()));
                                 self.sys.variable_types.insert(child_var, child_type);
                             } 
                         }
                    }
                }
            }
        }
    }
    fn selesaikan_iterasi_constraints(&mut self) -> bool {
        let mut any_change = false;
        let active_constraints: Vec<ConstraintTipe> = self.sys.constraints.iter().cloned().collect();
        for _ in 0..100 {
            let mut changed = false;
            for cons in &active_constraints {
                match cons {
                    ConstraintTipe::IsType(var, tipe) => {
                        if self.unifikasi_variabel_dengan_tipe(var, tipe) { changed = true; }
                    },
                    ConstraintTipe::Equal(v1, v2) => {
                        if self.unifikasi_dua_variabel(v1, v2) { changed = true; }
                    },
                    ConstraintTipe::HasField(base_var, offset, field_val_var) => {
                        if self.proses_struct_field(base_var, *offset, field_val_var) {
                            changed = true;
                        }
                    },
                    ConstraintTipe::ArgPass(var, func_addr, arg_idx) => {
                        if let Some(mut sig) = self.sys.global_signatures.remove(func_addr) {
                            if *arg_idx < sig.arg_types.len() {
                                let sig_type = sig.arg_types[*arg_idx].clone();
                                if sig_type != TipePrimitif::Unknown {
                                    if self.unifikasi_variabel_dengan_tipe(var, &sig_type) {
                                        changed = true;
                                    }
                                }
                                if sig_type == TipePrimitif::Unknown {
                                    let var_type = self.sys.variable_types.get(var).cloned().unwrap_or(TipePrimitif::Unknown);
                                    if var_type != TipePrimitif::Unknown {
                                        let unified = self.gabungkan_tipe_konflik(&sig_type, &var_type);
                                        if sig.arg_types[*arg_idx] != unified {
                                            sig.arg_types[*arg_idx] = unified;
                                            changed = true;
                                        }
                                    }
                                }
                            }
                            self.sys.global_signatures.insert(*func_addr, sig);
                        }
                    },
                    ConstraintTipe::CallResult(dest_var, func_addr) => {
                        let ret_type_opt = self.sys.global_signatures.get(func_addr).map(|s| s.return_type.clone());
                        if let Some(ret_type) = ret_type_opt {
                            if ret_type != TipePrimitif::Unknown {
                                if self.unifikasi_variabel_dengan_tipe(dest_var, &ret_type) {
                                    changed = true;
                                }
                            }
                        }
                    },
                    ConstraintTipe::ReturnResult(reg_name, func_addr) => {
                        let reg_type = self.sys.variable_types.get(reg_name).cloned().unwrap_or(TipePrimitif::Unknown);
                        if reg_type != TipePrimitif::Unknown {
                            if let Some(mut sig) = self.sys.global_signatures.remove(func_addr) {
                                let unified = self.gabungkan_tipe_konflik(&sig.return_type, &reg_type);
                                if sig.return_type != unified {
                                    sig.return_type = unified;
                                    changed = true;
                                }
                                self.sys.global_signatures.insert(*func_addr, sig);
                            }
                        }
                    },
                    ConstraintTipe::IsArrayBase(var, elem_type) => {
                        let ptr_type = TipePrimitif::Pointer(Box::new(elem_type.clone()));
                        if self.unifikasi_variabel_dengan_tipe(var, &ptr_type) {
                            changed = true;
                        }
                    },
                    ConstraintTipe::DerivedPointer(_, _, _) => { }
                }
            }
            if changed {
                any_change = true;
            } else {
                break;
            }
        }
        any_change
    }
    fn proses_struct_field(&mut self, base_var: &str, offset: i64, field_val_var: &str) -> bool {
        let mut changed = false;
        let base_type = self.sys.variable_types.get(base_var).cloned().unwrap_or(TipePrimitif::Unknown);
        let struct_name = match base_type {
            TipePrimitif::Pointer(inner) => {
                match *inner {
                    TipePrimitif::Struct(name) => name,
                    TipePrimitif::Unknown => {
                        let new_name = self.buat_struct_baru();
                        self.sys.variable_types.insert(base_var.to_string(), 
                            TipePrimitif::Pointer(Box::new(TipePrimitif::Struct(new_name.clone()))));
                        changed = true;
                        new_name
                    },
                    _ => return false,
                }
            },
            TipePrimitif::Unknown => {
                let new_name = self.buat_struct_baru();
                self.sys.variable_types.insert(base_var.to_string(), 
                    TipePrimitif::Pointer(Box::new(TipePrimitif::Struct(new_name.clone()))));
                changed = true;
                new_name
            },
            _ => return false,
        };
        let field_val_type = self.sys.variable_types.get(field_val_var).cloned().unwrap_or(TipePrimitif::Unknown);
        let is_recursive_access = if let TipePrimitif::Pointer(inner) = &field_val_type {
             if let TipePrimitif::Struct(n) = &**inner {
                 n == &struct_name
             } else { false }
        } else { false };
        if let Some(mut layout) = self.sys.struct_definitions.remove(&struct_name) {
            if is_recursive_access { layout.is_recursive = true; }
            if let Some(existing_field_type) = layout.fields.get(&offset) {
                let unified = self.gabungkan_tipe_konflik(existing_field_type, &field_val_type);
                if *existing_field_type != unified {
                    layout.fields.insert(offset, unified.clone());
                    self.unifikasi_variabel_dengan_tipe(field_val_var, &unified);
                    changed = true;
                }
            } else {
                layout.fields.insert(offset, field_val_type);
                changed = true;
            }
            self.sys.struct_definitions.insert(struct_name, layout);
        }
        changed
    }
    fn buat_struct_baru(&mut self) -> String {
        self.sys.struct_counter += 1;
        let name = format!("struct_{}", self.sys.struct_counter);
        self.sys.struct_definitions.insert(name.clone(), StructLayout {
            name: name.clone(),
            size: 0,
            fields: BTreeMap::new(),
            is_recursive: false,
        });
        name
    }
    fn unifikasi_dua_variabel(&mut self, v1: &str, v2: &str) -> bool {
         let t1 = self.sys.variable_types.get(v1).cloned().unwrap_or(TipePrimitif::Unknown);
         let t2 = self.sys.variable_types.get(v2).cloned().unwrap_or(TipePrimitif::Unknown);
         if t1 == t2 { return false; }
         self.sys.unification_cache.clear();
         let unified = self.gabungkan_tipe_konflik(&t1, &t2);
         let mut changed = false;
         if t1 != unified { self.sys.variable_types.insert(v1.to_string(), unified.clone()); changed = true; }
         if t2 != unified { self.sys.variable_types.insert(v2.to_string(), unified); changed = true; }
         changed
    }
    fn unifikasi_variabel_dengan_tipe(&mut self, var: &str, tipe: &TipePrimitif) -> bool {
        let current = self.sys.variable_types.get(var).cloned().unwrap_or(TipePrimitif::Unknown);
        if current == *tipe { return false; }
        self.sys.unification_cache.clear();
        let unified = self.gabungkan_tipe_konflik(&current, tipe);
        if current != unified { 
            self.sys.variable_types.insert(var.to_string(), unified); 
            return true; 
        }
        false
    }
    fn gabungkan_tipe_konflik(&mut self, t1: &TipePrimitif, t2: &TipePrimitif) -> TipePrimitif {
        if t1 == t2 { return t1.clone(); }
        if let TipePrimitif::Unknown = t1 { return t2.clone(); }
        if let TipePrimitif::Unknown = t2 { return t1.clone(); }
        if self.sys.unification_cache.contains(&(t1.clone(), t2.clone())) {
            return t1.clone(); 
        }
        self.sys.unification_cache.insert((t1.clone(), t2.clone()));
        match (t1, t2) {
            (TipePrimitif::Pointer(in1), TipePrimitif::Pointer(in2)) => {
                let unified_inner = self.gabungkan_tipe_konflik(in1, in2);
                TipePrimitif::Pointer(Box::new(unified_inner))
            },
            (TipePrimitif::Struct(s1), TipePrimitif::Struct(s2)) => {
                if s1 == s2 { 
                    TipePrimitif::Struct(s1.clone()) 
                } else { 
                    TipePrimitif::Union(vec![t1.clone(), t2.clone()]) 
                }
            },
            (TipePrimitif::Integer(s1), TipePrimitif::Integer(s2)) => TipePrimitif::Integer((*s1).max(*s2)),
            (TipePrimitif::Float(s1), TipePrimitif::Float(s2)) => TipePrimitif::Float((*s1).max(*s2)),
            (TipePrimitif::Integer(_), TipePrimitif::Float(_)) | 
            (TipePrimitif::Float(_), TipePrimitif::Integer(_)) => {
                TipePrimitif::Union(vec![t1.clone(), t2.clone()])
            },
            (TipePrimitif::Union(members), t_new) => {
                let mut new_members = members.clone();
                if !new_members.iter().any(|m| m == t_new) {
                    new_members.push(t_new.clone());
                }
                TipePrimitif::Union(new_members)
            },
            (t_new, TipePrimitif::Union(members)) => {
                let mut new_members = members.clone();
                if !new_members.iter().any(|m| m == t_new) {
                    new_members.push(t_new.clone());
                }
                TipePrimitif::Union(new_members)
            },
            _ => TipePrimitif::Union(vec![t1.clone(), t2.clone()]),
        }
    }
    fn dapatkan_nama_variabel(&self, op: &TipeOperand) -> Option<String> {
        match op {
            TipeOperand::Register(r) => Some(r.clone()),
            TipeOperand::SsaVariable(n, v) => Some(format!("{}_{}", n, v)),
            _ => None
        }
    }
    fn propagasi_ke_callee(&mut self, caller_id: u64, callee: u64, stmts: &[StatementIr]) -> bool {
        let mut changed = false;
        for stmt in stmts {
            if let OperasiIr::Call = stmt.operation_code {
                if let TipeOperand::Immediate(target) = stmt.operand_satu {
                    if target as u64 == callee {
                        if let Some(mut sig) = self.sys.global_signatures.remove(&callee) {
                            for (idx, arg_op) in stmt.operand_tambahan.iter().enumerate() {
                                let arg_type = match arg_op {
                                    TipeOperand::Immediate(_) => TipePrimitif::Integer(8),
                                    TipeOperand::FloatImmediate(_) => TipePrimitif::Float(4),
                                    TipeOperand::Register(r) => self.sys.variable_types.get(r).cloned().unwrap_or(TipePrimitif::Unknown),
                                    TipeOperand::SsaVariable(n, v) => self.sys.variable_types.get(&format!("{}_{}", n, v)).cloned().unwrap_or(TipePrimitif::Unknown),
                                    _ => TipePrimitif::Unknown,
                                };
                                if arg_type != TipePrimitif::Unknown {
                                    if idx < sig.arg_types.len() {
                                        let unified = self.gabungkan_tipe_konflik(&sig.arg_types[idx], &arg_type);
                                        if sig.arg_types[idx] != unified {
                                            warn!(
                                                "CONFLICT [Caller 0x{:x}, Instr 0x{:x}] update Callee 0x{:x} Arg#{}: {:?} -> {:?}",
                                                caller_id, stmt.address_asal, callee, idx, sig.arg_types[idx], unified
                                            );
                                            sig.arg_types[idx] = unified;
                                            changed = true;
                                        }
                                    }
                                }
                            }
                            self.sys.global_signatures.insert(callee, sig);
                        }
                    }
                }
            }
        }
        changed
    }
    fn finalisasi_tipe(&mut self) {
        let var_keys: Vec<String> = self.sys.variable_types.keys().cloned().collect();
        for key in var_keys {
            if let Some(tipe) = self.sys.variable_types.get(&key) {
                let resolved = self.selesaikan_tipe_rekursif(tipe);
                self.sys.variable_types.insert(key, resolved);
            }
        }
        let func_addrs: Vec<u64> = self.sys.global_signatures.keys().cloned().collect();
        for addr in func_addrs {
            if let Some(sig) = self.sys.global_signatures.remove(&addr) {
                let mut new_sig = sig.clone();
                new_sig.return_type = self.selesaikan_tipe_rekursif(&sig.return_type);
                for i in 0..new_sig.arg_types.len() {
                    new_sig.arg_types[i] = self.selesaikan_tipe_rekursif(&new_sig.arg_types[i]);
                }
                self.sys.global_signatures.insert(addr, new_sig);
            }
        }
        let struct_names: Vec<String> = self.sys.struct_definitions.keys().cloned().collect();
        for name in struct_names {
            if let Some(mut layout) = self.sys.struct_definitions.remove(&name) {
                let offsets: Vec<i64> = layout.fields.keys().cloned().collect();
                for offset in offsets {
                    if let Some(field_type) = layout.fields.remove(&offset) {
                         let resolved = self.selesaikan_tipe_rekursif(&field_type);
                         layout.fields.insert(offset, resolved);
                    }
                }
                self.sys.struct_definitions.insert(name, layout);
            }
        }
    }
    fn selesaikan_tipe_rekursif(&self, tipe: &TipePrimitif) -> TipePrimitif {
        match tipe {
            TipePrimitif::Unknown => TipePrimitif::Integer(8), 
            TipePrimitif::Pointer(inner) => {
                TipePrimitif::Pointer(Box::new(self.selesaikan_tipe_rekursif(inner)))
            },
            TipePrimitif::Array(inner, size) => {
                TipePrimitif::Array(Box::new(self.selesaikan_tipe_rekursif(inner)), *size)
            },
            TipePrimitif::Union(members) => {
                let resolved_members: Vec<TipePrimitif> = members.iter()
                    .map(|m| self.selesaikan_tipe_rekursif(m))
                    .collect();
                if resolved_members.iter().all(|m| m == &resolved_members[0]) {
                    resolved_members[0].clone()
                } else {
                    TipePrimitif::Union(resolved_members)
                }
            },
            _ => tipe.clone()
        }
    }
}