use std::collections::{HashMap, HashSet, BTreeMap, VecDeque};
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};
use log::{info, warn};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TipePrimitif {
    Unknown,
    Void,
    Integer(u8),       
    Float(u8),         
    Pointer(Box<TipePrimitif>),
    Struct(String),    
    Array(Box<TipePrimitif>, usize), 
    Vector(u16),       
    Union(Vec<TipePrimitif>), 
}

#[derive(Debug, Clone)]
pub struct StructLayout {
    pub name: String,
    pub size: usize,
    pub fields: BTreeMap<i64, TipePrimitif>,
    pub is_recursive: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignatureFungsi {
    pub return_type: TipePrimitif,
    pub arg_types: Vec<TipePrimitif>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConstraintTipe {
    Equal(String, String),             
    IsType(String, TipePrimitif),      
    HasField(String, i64, String),     
    ArgPass(String, u64, usize),       
    CallResult(String, u64),           
    IsArrayBase(String, TipePrimitif), 
}

pub struct CallGraph {
    edges: HashMap<u64, HashSet<u64>>,
    reverse_edges: HashMap<u64, HashSet<u64>>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self {
            edges: HashMap::new(),
            reverse_edges: HashMap::new(),
        }
    }
    pub fn tambah_edge(&mut self, caller: u64, callee: u64) {
        self.edges.entry(caller).or_default().insert(callee);
        self.reverse_edges.entry(callee).or_default().insert(caller);
    }
    pub fn dapatkan_callees(&self, caller: u64) -> impl Iterator<Item = &u64> {
        self.edges.get(&caller).into_iter().flatten()
    }
    pub fn dapatkan_callers(&self, callee: u64) -> impl Iterator<Item = &u64> {
        self.reverse_edges.get(&callee).into_iter().flatten()
    }
}

pub struct TypeSystem {
    pub global_signatures: HashMap<u64, SignatureFungsi>,
    pub variable_types: HashMap<String, TipePrimitif>,
    pub struct_definitions: HashMap<String, StructLayout>,
    constraints: HashSet<ConstraintTipe>,
    struct_counter: usize,
    unification_cache: HashSet<(TipePrimitif, TipePrimitif)>,
    pub call_graph: CallGraph,
}

impl TypeSystem {
    pub fn new() -> Self {
        Self {
            global_signatures: HashMap::new(),
            variable_types: HashMap::new(),
            struct_definitions: HashMap::new(),
            constraints: HashSet::new(),
            struct_counter: 0,
            unification_cache: HashSet::new(),
            call_graph: CallGraph::new(),
        }
    }
    pub fn analisis_interprosedural(&mut self, all_functions_stmts: &HashMap<u64, Vec<StatementIr>>) {
        info!("Memulai Analisis Tipe Interprosedural...");
        self.bangun_call_graph(all_functions_stmts);
        info!("Call Graph dibangun: {} node terdeteksi.", self.call_graph.edges.len());
        for (addr, _) in all_functions_stmts {
            self.global_signatures.entry(*addr).or_insert(SignatureFungsi {
                return_type: TipePrimitif::Unknown,
                arg_types: vec![TipePrimitif::Unknown; 8],
            });
        }
        let mut antrean_analisis: VecDeque<u64> = all_functions_stmts.keys().cloned().collect();
        let mut in_queue: HashSet<u64> = antrean_analisis.iter().cloned().collect();
        let mut iterasi = 0;
        while let Some(func_addr) = antrean_analisis.pop_front() {
            in_queue.remove(&func_addr);
            let stmts = match all_functions_stmts.get(&func_addr) {
                Some(s) => s,
                None => continue,
            };
            let old_sig = self.global_signatures.get(&func_addr).cloned();
            self.kumpulkan_constraints_lokal(stmts, func_addr);
            let local_changed = self.selesaikan_iterasi_constraints();
            let mut inter_changed = false;
            let current_sig = self.global_signatures.get(&func_addr).unwrap();
            if let Some(old) = old_sig {
                if &old != current_sig {
                    inter_changed = true;
                    for &caller in self.call_graph.dapatkan_callers(func_addr) {
                        if !in_queue.contains(&caller) {
                            antrean_analisis.push_back(caller);
                            in_queue.insert(caller);
                        }
                    }
                }
            }
            let callees: Vec<u64> = self.call_graph.dapatkan_callees(func_addr).cloned().collect();
            for callee_addr in callees {
                if self.propagasi_ke_callee(func_addr, callee_addr, stmts) {
                    if !in_queue.contains(&callee_addr) {
                        antrean_analisis.push_back(callee_addr);
                        in_queue.insert(callee_addr);
                    }
                }
            }
            if local_changed || inter_changed {
                iterasi += 1;
            }
            if iterasi > 10000 {
                warn!("Batas iterasi analisis tipe tercapai.");
                break;
            }
        }
        self.finalisasi_tipe();
        info!("Analisis Tipe Selesai dalam {} iterasi langkah.", iterasi);
    }
    fn bangun_call_graph(&mut self, all_functions: &HashMap<u64, Vec<StatementIr>>) {
        for (caller_addr, stmts) in all_functions {
            for stmt in stmts {
                if let OperasiIr::Call = stmt.operation_code {
                    if let TipeOperand::Immediate(target) = stmt.operand_satu {
                        self.call_graph.tambah_edge(*caller_addr, target as u64);
                    }
                }
            }
        }
    }
    fn kumpulkan_constraints_lokal(&mut self, stmts: &[StatementIr], current_func: u64) {
        self.constraints.clear();
        for stmt in stmts {
            self.analisa_pola_memori(&stmt.operand_satu);
            self.analisa_pola_memori(&stmt.operand_dua);
            match &stmt.operation_code {
                OperasiIr::Mov | OperasiIr::VecMov | OperasiIr::Lea => {
                    self.analisa_data_movement(&stmt.operand_satu, &stmt.operand_dua);
                },
                OperasiIr::Add | OperasiIr::Sub => {
                     if let TipeOperand::Immediate(_) = &stmt.operand_dua {
                     } else if let Some(dest) = self.get_var_name(&stmt.operand_satu) {
                         self.constraints.insert(ConstraintTipe::IsType(dest, TipePrimitif::Integer(8)));
                     }
                },
                OperasiIr::Call => {
                    if let TipeOperand::Immediate(target_addr) = stmt.operand_satu {
                        let callee_addr = target_addr as u64;
                        for (idx, arg_op) in stmt.operand_tambahan.iter().enumerate() {
                            if let Some(var_arg) = self.get_var_name(arg_op) {
                                self.constraints.insert(ConstraintTipe::ArgPass(var_arg, callee_addr, idx));
                            } 
                        }
                        self.constraints.insert(ConstraintTipe::CallResult("rax".to_string(), callee_addr));
                    }
                },
                OperasiIr::Ret => {
                    if let Some(_sig) = self.global_signatures.get_mut(&current_func) {

                    }
                }
                _ => {}
            }
        }
    }
    fn propagasi_ke_callee(&mut self, _caller: u64, callee: u64, stmts: &[StatementIr]) -> bool {
        let mut changed = false;
        for stmt in stmts {
            if let OperasiIr::Call = stmt.operation_code {
                if let TipeOperand::Immediate(target) = stmt.operand_satu {
                    if target as u64 == callee {
                        if let Some(mut sig) = self.global_signatures.remove(&callee) {
                            for (idx, arg_op) in stmt.operand_tambahan.iter().enumerate() {
                                let arg_type = match arg_op {
                                    TipeOperand::Immediate(_) => TipePrimitif::Integer(8),
                                    TipeOperand::FloatImmediate(_) => TipePrimitif::Float(4),
                                    TipeOperand::Register(r) => self.variable_types.get(r).cloned().unwrap_or(TipePrimitif::Unknown),
                                    TipeOperand::SsaVariable(n, v) => self.variable_types.get(&format!("{}_{}", n, v)).cloned().unwrap_or(TipePrimitif::Unknown),
                                    _ => TipePrimitif::Unknown,
                                };
                                if arg_type != TipePrimitif::Unknown {
                                    if idx < sig.arg_types.len() {
                                        let unified = self.gabungkan_tipe_konflik(&sig.arg_types[idx], &arg_type);
                                        if sig.arg_types[idx] != unified {
                                            sig.arg_types[idx] = unified;
                                            changed = true;
                                        }
                                    }
                                }
                            }
                            self.global_signatures.insert(callee, sig);
                        }
                    }
                }
            }
        }
        changed
    }
    fn selesaikan_iterasi_constraints(&mut self) -> bool {
        let mut changed = false;
        let active_constraints: Vec<ConstraintTipe> = self.constraints.iter().cloned().collect();
        for cons in active_constraints {
            match cons {
                ConstraintTipe::IsType(var, tipe) => {
                    if self.unifikasi_variabel_dengan_tipe(&var, &tipe) { changed = true; }
                },
                ConstraintTipe::Equal(v1, v2) => {
                    if self.unifikasi_dua_variabel(&v1, &v2) { changed = true; }
                },
                ConstraintTipe::HasField(base_var, offset, field_val_var) => {
                    if self.proses_struct_field(&base_var, offset, &field_val_var) {
                        changed = true;
                    }
                },
                ConstraintTipe::ArgPass(var, func_addr, arg_idx) => {
                    let var_type = self.variable_types.get(&var).cloned().unwrap_or(TipePrimitif::Unknown);
                    if var_type != TipePrimitif::Unknown {
                        if let Some(mut sig) = self.global_signatures.remove(&func_addr) {
                            if arg_idx < sig.arg_types.len() {
                                let unified = self.gabungkan_tipe_konflik(&sig.arg_types[arg_idx], &var_type);
                                if sig.arg_types[arg_idx] != unified {
                                    sig.arg_types[arg_idx] = unified;
                                    changed = true;
                                }
                            }
                            self.global_signatures.insert(func_addr, sig);
                        }
                    }
                },
                ConstraintTipe::CallResult(dest_var, func_addr) => {
                    let ret_type_opt = self.global_signatures.get(&func_addr).map(|s| s.return_type.clone());
                    if let Some(ret_type) = ret_type_opt {
                        if ret_type != TipePrimitif::Unknown {
                            if self.unifikasi_variabel_dengan_tipe(&dest_var, &ret_type) {
                                changed = true;
                            }
                        }
                    }
                },
                ConstraintTipe::IsArrayBase(var, elem_type) => {
                    let ptr_type = TipePrimitif::Pointer(Box::new(elem_type));
                    if self.unifikasi_variabel_dengan_tipe(&var, &ptr_type) {
                        changed = true;
                    }
                }
            }
        }
        changed
    }
    fn analisa_pola_memori(&mut self, op: &TipeOperand) {
        if let TipeOperand::Expression { operasi: OperasiIr::Add, operand_kiri, operand_kanan } = op {
            if let Some((base_var, scale_val)) = self.match_array_pattern(operand_kiri, operand_kanan) {
                let elem_type = match scale_val {
                    1 => TipePrimitif::Integer(1),
                    2 => TipePrimitif::Integer(2),
                    4 => TipePrimitif::Integer(4),
                    8 => TipePrimitif::Integer(8),
                    _ => TipePrimitif::Unknown
                };
                self.constraints.insert(ConstraintTipe::IsArrayBase(base_var, elem_type));
            }
        }
    }
    fn match_array_pattern(&self, op1: &TipeOperand, op2: &TipeOperand) -> Option<(String, i64)> {
        if let Some(base) = self.get_var_name(op1) {
            if let TipeOperand::Expression { operasi: OperasiIr::Imul, operand_kiri: _, operand_kanan } = op2 {
                if let TipeOperand::Immediate(scale) = **operand_kanan {
                    return Some((base, scale));
                }
            }
        }
        if let Some(base) = self.get_var_name(op2) {
            if let TipeOperand::Expression { operasi: OperasiIr::Imul, operand_kiri: _, operand_kanan } = op1 {
                if let TipeOperand::Immediate(scale) = **operand_kanan {
                    return Some((base, scale));
                }
            }
        }
        None
    }
    fn analisa_data_movement(&mut self, dest: &TipeOperand, src: &TipeOperand) {
        let dest_name = self.get_var_name(dest);
        let src_name = self.get_var_name(src);
        if let (Some(d), Some(s)) = (&dest_name, &src_name) {
            self.constraints.insert(ConstraintTipe::Equal(d.clone(), s.clone()));
            return;
        }
        if let Some(d) = dest_name.clone() {
            if let TipeOperand::MemoryRef { base, offset } = src {
                self.constraints.insert(ConstraintTipe::HasField(base.clone(), *offset, d.clone())); 
                return;
            }
            if let TipeOperand::FloatImmediate(_) = src {
                self.constraints.insert(ConstraintTipe::IsType(d, TipePrimitif::Float(4)));
            }
        }
        if let Some(s) = src_name {
            if let TipeOperand::MemoryRef { base, offset } = dest {
                self.constraints.insert(ConstraintTipe::HasField(base.clone(), *offset, s));
                return;
            }
        }
    }
    fn proses_struct_field(&mut self, base_var: &str, offset: i64, field_val_var: &str) -> bool {
        let mut changed = false;
        let base_type = self.variable_types.get(base_var).cloned().unwrap_or(TipePrimitif::Unknown);
        let struct_name = match base_type {
            TipePrimitif::Pointer(inner) => {
                match *inner {
                    TipePrimitif::Struct(name) => name,
                    TipePrimitif::Unknown => {
                        let new_name = self.generate_struct_baru();
                        self.variable_types.insert(base_var.to_string(), 
                            TipePrimitif::Pointer(Box::new(TipePrimitif::Struct(new_name.clone()))));
                        changed = true;
                        new_name
                    },
                    _ => return false, 
                }
            },
            TipePrimitif::Unknown => {
                let new_name = self.generate_struct_baru();
                self.variable_types.insert(base_var.to_string(), 
                    TipePrimitif::Pointer(Box::new(TipePrimitif::Struct(new_name.clone()))));
                changed = true;
                new_name
            },
            _ => return false,
        };
        let field_val_type = self.variable_types.get(field_val_var).cloned().unwrap_or(TipePrimitif::Unknown);
        let is_recursive_access = if let TipePrimitif::Pointer(inner) = &field_val_type {
             if let TipePrimitif::Struct(n) = &**inner {
                 n == &struct_name
             } else { false }
        } else { false };
        if let Some(mut layout) = self.struct_definitions.remove(&struct_name) {
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
            self.struct_definitions.insert(struct_name, layout);
        }
        changed
    }
    fn unifikasi_dua_variabel(&mut self, v1: &str, v2: &str) -> bool {
        let t1 = self.variable_types.get(v1).cloned().unwrap_or(TipePrimitif::Unknown);
        let t2 = self.variable_types.get(v2).cloned().unwrap_or(TipePrimitif::Unknown);
        if t1 == t2 { return false; }
        self.unification_cache.clear();
        let unified = self.gabungkan_tipe_konflik(&t1, &t2);
        let mut changed = false;
        if t1 != unified {
            self.variable_types.insert(v1.to_string(), unified.clone());
            changed = true;
        }
        if t2 != unified {
            self.variable_types.insert(v2.to_string(), unified);
            changed = true;
        }
        changed
    }
    fn unifikasi_variabel_dengan_tipe(&mut self, var: &str, tipe: &TipePrimitif) -> bool {
        let current = self.variable_types.get(var).cloned().unwrap_or(TipePrimitif::Unknown);
        if current == *tipe { return false; }
        self.unification_cache.clear();
        let unified = self.gabungkan_tipe_konflik(&current, tipe);
        if current != unified {
            self.variable_types.insert(var.to_string(), unified);
            return true;
        }
        false
    }
    fn gabungkan_tipe_konflik(&mut self, t1: &TipePrimitif, t2: &TipePrimitif) -> TipePrimitif {
        if t1 == t2 { return t1.clone(); }
        if self.unification_cache.contains(&(t1.clone(), t2.clone())) {
            return t1.clone(); 
        }
        self.unification_cache.insert((t1.clone(), t2.clone()));
        match (t1, t2) {
            (TipePrimitif::Unknown, t) => t.clone(),
            (t, TipePrimitif::Unknown) => t.clone(),
            (TipePrimitif::Pointer(in1), TipePrimitif::Pointer(in2)) => {
                let unified_inner = self.gabungkan_tipe_konflik(in1, in2);
                TipePrimitif::Pointer(Box::new(unified_inner))
            },
            (TipePrimitif::Struct(s1), TipePrimitif::Struct(s2)) => {
                if s1 == s2 { TipePrimitif::Struct(s1.clone()) } 
                else { TipePrimitif::Union(vec![t1.clone(), t2.clone()]) }
            },
            (TipePrimitif::Integer(s1), TipePrimitif::Integer(s2)) => TipePrimitif::Integer((*s1).max(*s2)),
            (TipePrimitif::Float(s1), TipePrimitif::Float(s2)) => TipePrimitif::Float((*s1).max(*s2)),
            (TipePrimitif::Union(members), t_new) => {
                let mut new_members = members.clone();
                if !new_members.contains(t_new) { new_members.push(t_new.clone()); }
                TipePrimitif::Union(new_members)
            },
            (t_new, TipePrimitif::Union(members)) => {
                let mut new_members = members.clone();
                if !new_members.contains(t_new) { new_members.push(t_new.clone()); }
                TipePrimitif::Union(new_members)
            },
            _ => TipePrimitif::Union(vec![t1.clone(), t2.clone()]),
        }
    }
    fn generate_struct_baru(&mut self) -> String {
        self.struct_counter += 1;
        let name = format!("struct_{}", self.struct_counter);
        self.struct_definitions.insert(name.clone(), StructLayout {
            name: name.clone(),
            size: 0,
            fields: BTreeMap::new(),
            is_recursive: false,
        });
        name
    }
    fn get_var_name(&self, op: &TipeOperand) -> Option<String> {
        match op {
            TipeOperand::Register(r) => Some(r.clone()),
            TipeOperand::SsaVariable(n, v) => Some(format!("{}_{}", n, v)),
            _ => None
        }
    }
    pub fn dapatkan_tipe_c_string(&self, var_name: &str) -> String {
         let tipe = self.variable_types.get(var_name).unwrap_or(&TipePrimitif::Unknown);
         self.konversi_primitif_ke_string(tipe)
    }
    fn konversi_primitif_ke_string(&self, tipe: &TipePrimitif) -> String {
        match tipe {
            TipePrimitif::Unknown => "uintptr_t".to_string(), 
            TipePrimitif::Void => "void".to_string(),
            TipePrimitif::Integer(8) => "int64_t".to_string(),
            TipePrimitif::Integer(4) => "int32_t".to_string(),
            TipePrimitif::Integer(2) => "int16_t".to_string(),
            TipePrimitif::Integer(1) => "char".to_string(),
            TipePrimitif::Integer(_) => "long".to_string(),
            TipePrimitif::Float(4) => "float".to_string(),
            TipePrimitif::Float(8) => "double".to_string(),
            TipePrimitif::Float(_) => "float".to_string(),
            TipePrimitif::Pointer(inner) => {
                let inner_str = self.konversi_primitif_ke_string(inner);
                format!("{}*", inner_str)
            },
            TipePrimitif::Struct(name) => format!("struct {}", name),
            TipePrimitif::Array(inner, len) => {
                let inner_str = self.konversi_primitif_ke_string(inner);
                if *len > 0 { format!("{} /*[{}]*/", inner_str, len) } else { format!("{}*", inner_str) }
            },
            TipePrimitif::Vector(_) => "__vector".to_string(),
            TipePrimitif::Union(members) => {
                if members.is_empty() { return "void*".to_string(); }
                format!("/*union*/ {}", self.konversi_primitif_ke_string(&members[0]))
            }
        }
    }
    pub fn definisi_struct(&self) -> BTreeMap<String, BTreeMap<i64, String>> {
        let mut output = BTreeMap::new();
        for (name, layout) in &self.struct_definitions {
            let mut fields_str = BTreeMap::new();
            for (offset, tipe) in &layout.fields {
                let type_str = self.konversi_primitif_ke_string(tipe);
                fields_str.insert(*offset, type_str);
            }
            output.insert(name.clone(), fields_str);
        }
        output
    }
    fn finalisasi_tipe(&mut self) {

    }
}