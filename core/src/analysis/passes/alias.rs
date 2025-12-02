use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use crate::ir::types::{TipeOperand, OperasiIr, StatementIr};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub enum NodeId {
    Variable(u64),
    AbstractHeap(u64),
    StackSlot(i64),
    Global(u64),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MemoryRegion {
    Global(u64),
    Stack(i64),
    Heap(u64),
    Symbolic(String),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueInterval {
    pub min: i64,
    pub max: i64,
    pub stride: u64,
}

impl ValueInterval {
    fn single(val: i64) -> Self {
        Self { min: val, max: val, stride: 0 }
    }
    fn unknown() -> Self {
        Self { min: i64::MIN, max: i64::MAX, stride: 1 }
    }
    fn union(&self, other: &Self) -> Self {
        let new_min = self.min.min(other.min);
        let new_max = self.max.max(other.max);
        let new_stride = if self.stride == other.stride { self.stride } else { 1 };
        Self { min: new_min, max: new_max, stride: new_stride }
    }
    fn add(&self, val: i64) -> Self {
        Self {
            min: self.min.saturating_add(val),
            max: self.max.saturating_add(val),
            stride: self.stride,
        }
    }
}

impl fmt::Display for ValueInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.min == i64::MIN && self.max == i64::MAX {
            write!(f, "any")
        } else if self.min == self.max {
            if self.min < 0 {
                write!(f, "neg_{}", self.min.abs())
            } else {
                write!(f, "{}", self.min)
            }
        } else {
            let min_s = if self.min == i64::MIN { "min".to_string() } else { self.min.to_string().replace("-", "neg_") };
            let max_s = if self.max == i64::MAX { "max".to_string() } else { self.max.to_string().replace("-", "neg_") };
            write!(f, "{}_to_{}", min_s, max_s)?;
            if self.stride > 1 {
                write!(f, "_step_{}", self.stride)?;
            }
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct StatePointer {
    pub base_region: MemoryRegion,
    pub offset: ValueInterval,
    pub is_escaped: bool,
    pub field_hints: HashSet<i64>, 
}

#[derive(Debug, Clone)]
enum ConstraintAlias {
    AddrOf { dest: NodeId, target: NodeId },
    Copy { dest: NodeId, src: NodeId },
    Load { dest: NodeId, src_base: NodeId, offset: i64 },
    Store { dest_base: NodeId, offset: i64, src: NodeId },
    Gep { dest: NodeId, src: NodeId, offset: i64 },
}

pub struct PointsToGraph {
    points_to: HashMap<NodeId, HashSet<NodeId>>,
    field_map: HashMap<NodeId, HashMap<i64, NodeId>>,
    constraints: VecDeque<ConstraintAlias>,
    var_cache: HashMap<String, NodeId>,
}

impl PointsToGraph {
    fn new() -> Self {
        Self {
            points_to: HashMap::new(),
            field_map: HashMap::new(),
            constraints: VecDeque::new(),
            var_cache: HashMap::new(),
        }
    }
    fn get_or_create_field_node(&mut self, base: NodeId, offset: i64) -> NodeId {
        if offset == 0 { return base; }
        let entry = self.field_map.entry(base).or_default();
        if let Some(&field_id) = entry.get(&offset) {
            return field_id;
        }
        let new_id_val = match base {
            NodeId::AbstractHeap(addr) => addr.wrapping_add(offset as u64),
            NodeId::StackSlot(off) => (off + offset) as u64, 
            NodeId::Variable(h) => h.wrapping_add(offset as u64),
            _ => 0,
        };
        let field_id = NodeId::AbstractHeap(new_id_val ^ 0xDEADBEEF); 
        entry.insert(offset, field_id);
        field_id
    }
    fn add_points_to(&mut self, ptr: NodeId, obj: NodeId) -> bool {
        self.points_to.entry(ptr).or_default().insert(obj)
    }
    fn get_points_to_set(&self, ptr: &NodeId) -> Option<&HashSet<NodeId>> {
        self.points_to.get(ptr)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HasilAliasing {
    MustAlias,
    MayAlias,
    NoAlias,
}

pub struct AliasAnalyzer {
    graph: PointsToGraph,
    tracker_offset_pointer: HashMap<String, ValueInterval>,
    set_variabel_escaped: HashSet<String>,
}

impl AliasAnalyzer {
    pub fn new() -> Self {
        Self {
            graph: PointsToGraph::new(),
            tracker_offset_pointer: HashMap::new(),
            set_variabel_escaped: HashSet::new(),
        }
    }
    pub fn analisis_pointer_lanjutan(&mut self, stmts: &[StatementIr], frame_pointer: &str) {
        self.reset_analisis();
        self.registrasi_node_spesial(frame_pointer);
        for stmt in stmts {
            self.generate_constraint_dari_ir(stmt, frame_pointer);
        }
        self.selesaikan_constraints();
        self.update_escaped_status();
    }
    fn reset_analisis(&mut self) {
        self.graph = PointsToGraph::new();
        self.tracker_offset_pointer.clear();
        self.set_variabel_escaped.clear();
    }
    fn registrasi_node_spesial(&mut self, fp: &str) {
        let fp_id = self.dapatkan_node_id(fp);
        let stack_base = NodeId::StackSlot(0);
        self.graph.add_points_to(fp_id, stack_base);
        self.tracker_offset_pointer.insert(fp.to_string(), ValueInterval::single(0));
    }
    fn generate_constraint_dari_ir(&mut self, stmt: &StatementIr, fp: &str) {
        match &stmt.operation_code {
            OperasiIr::Mov | OperasiIr::VecMov => self.handle_instruction_mov(stmt, fp),
            OperasiIr::Lea => self.handle_instruction_lea(stmt, fp),
            OperasiIr::Add | OperasiIr::Sub => self.handle_arithmetic_ptr(stmt),
            OperasiIr::Call => self.handle_instruction_call(stmt),
            OperasiIr::Phi => self.handle_phi_node(stmt),
            _ => {}
        }
    }
    fn handle_instruction_mov(&mut self, stmt: &StatementIr, _fp: &str) {
        let dest_op = &stmt.operand_satu;
        let src_op = &stmt.operand_dua;
        match (dest_op, src_op) {
            (TipeOperand::Register(d) | TipeOperand::SsaVariable(d, _), 
             TipeOperand::Register(s) | TipeOperand::SsaVariable(s, _)) => {
                let d_id = self.dapatkan_node_id(d);
                let s_id = self.dapatkan_node_id(s);
                self.graph.constraints.push_back(ConstraintAlias::Copy { dest: d_id, src: s_id });
                
                if let Some(interval) = self.tracker_offset_pointer.get(s) {
                    self.tracker_offset_pointer.insert(d.clone(), interval.clone());
                }
            },
            (TipeOperand::Register(d) | TipeOperand::SsaVariable(d, _),
             TipeOperand::MemoryRef { base, offset }) => {
                let d_id = self.dapatkan_node_id(d);
                let b_id = self.dapatkan_node_id(base);
                self.graph.constraints.push_back(ConstraintAlias::Load { dest: d_id, src_base: b_id, offset: *offset });
                self.tracker_offset_pointer.remove(d); 
            },
            (TipeOperand::MemoryRef { base, offset },
             TipeOperand::Register(s) | TipeOperand::SsaVariable(s, _)) => {
                let b_id = self.dapatkan_node_id(base);
                let s_id = self.dapatkan_node_id(s);
                self.graph.constraints.push_back(ConstraintAlias::Store { dest_base: b_id, offset: *offset, src: s_id });
            },
            _ => {}
        }
    }
    fn handle_instruction_lea(&mut self, stmt: &StatementIr, _fp: &str) {
        if let Some(dest_name) = self.extract_nama_variabel(&stmt.operand_satu) {
            let dest_id = self.dapatkan_node_id(&dest_name);
            match &stmt.operand_dua {
                TipeOperand::MemoryRef { base, offset } => {
                    if base == "rip" {
                        let global_addr = stmt.address_asal.wrapping_add(*offset as u64);
                        let global_obj = NodeId::Global(global_addr);
                        self.graph.constraints.push_back(ConstraintAlias::AddrOf { dest: dest_id, target: global_obj });
                        self.tracker_offset_pointer.insert(dest_name, ValueInterval::single(0));
                    } else {
                        let base_id = self.dapatkan_node_id(base);
                        self.graph.constraints.push_back(ConstraintAlias::Gep { dest: dest_id, src: base_id, offset: *offset });
                        if let Some(base_interval) = self.tracker_offset_pointer.get(base) {
                            self.tracker_offset_pointer.insert(dest_name, base_interval.add(*offset));
                        }
                    }
                },
                _ => {}
            }
        }
    }
    fn handle_arithmetic_ptr(&mut self, stmt: &StatementIr) {
        let dest_name = match self.extract_nama_variabel(&stmt.operand_satu) {
            Some(n) => n,
            None => return,
        };
        let dest_id = self.dapatkan_node_id(&dest_name);
        match &stmt.operand_dua {
            TipeOperand::Immediate(val) => {
                self.graph.constraints.push_back(ConstraintAlias::Gep { dest: dest_id, src: dest_id, offset: *val });
                if let Some(curr) = self.tracker_offset_pointer.get(&dest_name).cloned() {
                     self.tracker_offset_pointer.insert(dest_name, curr.add(*val));
                }
            },
            _ => {
                self.tracker_offset_pointer.insert(dest_name, ValueInterval::unknown());
            }
        }
    }
    fn handle_instruction_call(&mut self, stmt: &StatementIr) {
        let func_name = if let TipeOperand::Register(r) = &stmt.operand_satu { r } else { return };
        let is_allocator = matches!(func_name.as_str(), "malloc" | "calloc" | "operator new");
        if is_allocator {
            let heap_obj = NodeId::AbstractHeap(stmt.address_asal);
            let ret_reg = "rax".to_string(); 
            let ret_id = self.dapatkan_node_id(&ret_reg);
            self.graph.constraints.push_back(ConstraintAlias::AddrOf { dest: ret_id, target: heap_obj });
            self.tracker_offset_pointer.insert(ret_reg, ValueInterval::single(0));
        }
    }
    fn handle_phi_node(&mut self, stmt: &StatementIr) {
        if let Some(dest_name) = self.extract_nama_variabel(&stmt.operand_satu) {
            let dest_id = self.dapatkan_node_id(&dest_name);
            let mut merged_interval: Option<ValueInterval> = None;
            for op in &stmt.operand_tambahan {
                if let Some(src_name) = self.extract_nama_variabel(op) {
                    let src_id = self.dapatkan_node_id(&src_name);
                    self.graph.constraints.push_back(ConstraintAlias::Copy { dest: dest_id, src: src_id });
                    if let Some(interval) = self.tracker_offset_pointer.get(&src_name) {
                        merged_interval = match merged_interval {
                            Some(current) => Some(current.union(interval)),
                            None => Some(interval.clone()),
                        };
                    } else {
                        merged_interval = Some(ValueInterval::unknown());
                    }
                }
            }
            if let Some(interval) = merged_interval {
                self.tracker_offset_pointer.insert(dest_name, interval);
            }
        }
    }
    fn selesaikan_constraints(&mut self) {
        let mut changed = true;
        let mut iterasi = 0;
        while changed && iterasi < 500 {
            changed = false;
            iterasi += 1;
            let current_constraints: Vec<ConstraintAlias> = self.graph.constraints.iter().cloned().collect();
            for constraint in current_constraints {
                match constraint {
                    ConstraintAlias::AddrOf { dest, target } => {
                        if self.graph.add_points_to(dest, target) { changed = true; }
                    },
                    ConstraintAlias::Copy { dest, src } => {
                        if let Some(src_set) = self.graph.points_to.get(&src).cloned() {
                            for obj in src_set {
                                if self.graph.add_points_to(dest, obj) { changed = true; }
                            }
                        }
                    },
                    ConstraintAlias::Gep { dest, src, offset } => {
                        if let Some(src_set) = self.graph.points_to.get(&src).cloned() {
                            for obj in src_set {
                                let field_node = self.graph.get_or_create_field_node(obj, offset);
                                if self.graph.add_points_to(dest, field_node) { changed = true; }
                            }
                        }
                    },
                    ConstraintAlias::Load { dest, src_base, offset } => {
                        if let Some(base_objects) = self.graph.points_to.get(&src_base).cloned() {
                            for obj in base_objects {
                                let field_node = self.graph.get_or_create_field_node(obj, offset);
                                if let Some(pointed_values) = self.graph.points_to.get(&field_node).cloned() {
                                    for val in pointed_values {
                                        if self.graph.add_points_to(dest, val) { changed = true; }
                                    }
                                }
                            }
                        }
                    },
                    ConstraintAlias::Store { dest_base, offset, src } => {
                        if let Some(base_objects) = self.graph.points_to.get(&dest_base).cloned() {
                            if let Some(src_values) = self.graph.points_to.get(&src).cloned() {
                                for obj in base_objects {
                                    let field_node = self.graph.get_or_create_field_node(obj, offset);
                                    for val in &src_values {
                                        if self.graph.add_points_to(field_node, *val) { changed = true; }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    fn update_escaped_status(&mut self) {
        for (node_id, targets) in &self.graph.points_to {
            let mut node_escaped = false;
            for target in targets {
                 if matches!(target, NodeId::Global(_) | NodeId::Unknown) {
                     node_escaped = true;
                     break;
                 }
            }
            if node_escaped {
                for (name, id) in &self.graph.var_cache {
                    if id == node_id {
                        self.set_variabel_escaped.insert(name.clone());
                    }
                }
            }
        }
    }
    pub fn infer_region_state(&self, op: &TipeOperand, _frame_pointer: &str) -> Option<StatePointer> {
        let name = self.extract_nama_variabel(op)?;
        let id = self.get_cached_node_id(&name);
        let targets = self.graph.get_points_to_set(&id)?;
        if targets.is_empty() { return None; }
        let primary_target = targets.iter().next().unwrap();
        let region = match primary_target {
            NodeId::Global(addr) => MemoryRegion::Global(*addr),
            NodeId::StackSlot(off) => MemoryRegion::Stack(*off),
            NodeId::AbstractHeap(site) => MemoryRegion::Heap(*site),
            NodeId::Variable(_) => MemoryRegion::Symbolic(name.clone()),
            _ => MemoryRegion::Unknown,
        };
        let offset = self.tracker_offset_pointer.get(&name).cloned().unwrap_or(ValueInterval::single(0));
        let escaped = self.set_variabel_escaped.contains(&name);
        Some(StatePointer {
            base_region: region,
            offset,
            is_escaped: escaped,
            field_hints: HashSet::new(),
        })
    }
    pub fn cek_aliasing(&self, op1: &TipeOperand, op2: &TipeOperand, _fp: &str) -> HasilAliasing {
        let name1 = self.extract_nama_variabel(op1);
        let name2 = self.extract_nama_variabel(op2);
        if let (Some(n1), Some(n2)) = (name1, name2) {
            let id1 = self.get_cached_node_id(&n1);
            let id2 = self.get_cached_node_id(&n2);
            let set1 = self.graph.get_points_to_set(&id1);
            let set2 = self.graph.get_points_to_set(&id2);
            match (set1, set2) {
                (Some(s1), Some(s2)) => {
                    let intersection: HashSet<_> = s1.intersection(s2).collect();
                    if intersection.is_empty() {
                        return HasilAliasing::NoAlias;
                    } else if s1.len() == 1 && s2.len() == 1 && s1 == s2 {
                        return HasilAliasing::MustAlias;
                    } else {
                        return HasilAliasing::MayAlias;
                    }
                },
                _ => return HasilAliasing::MayAlias,
            }
        }
        HasilAliasing::MayAlias
    }
    fn dapatkan_node_id(&mut self, var_name: &str) -> NodeId {
        if let Some(id) = self.graph.var_cache.get(var_name) {
            return *id;
        }
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(var_name, &mut hasher);
        let hash = std::hash::Hasher::finish(&hasher);
        let id = NodeId::Variable(hash);
        self.graph.var_cache.insert(var_name.to_string(), id);
        id
    }
    fn get_cached_node_id(&self, var_name: &str) -> NodeId {
        if let Some(id) = self.graph.var_cache.get(var_name) {
            return *id;
        }
        NodeId::Unknown
    }
    fn extract_nama_variabel(&self, op: &TipeOperand) -> Option<String> {
        match op {
            TipeOperand::Register(r) => Some(r.clone()),
            TipeOperand::SsaVariable(n, _) => Some(n.clone()),
            _ => None
        }
    }
    pub fn is_escaped(&self, var_name: &str) -> bool {
        self.set_variabel_escaped.contains(var_name)
    }
}