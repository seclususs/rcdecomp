use std::collections::{HashMap, HashSet, BTreeMap};
use crate::ir::types::StatementIr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TipePrimitif {
    Unknown,
    Void,
    Integer(u8),       
    Float(u8),         
    Pointer(Box<TipePrimitif>),
    Struct(String),
    Class(String),
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

#[derive(Debug, Clone)]
pub struct ClassLayout {
    pub name: String,
    pub parent_name: Option<String>,
    pub vtable_address: Option<u64>,
    pub fields: BTreeMap<i64, TipePrimitif>,
    pub virtual_methods: Vec<u64>,
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
    ReturnResult(String, u64),
    IsArrayBase(String, TipePrimitif),
    DerivedPointer(String, String, i64),
}

pub struct CallGraph {
    edges: HashMap<u64, HashSet<u64>>,
    reverse_edges: HashMap<u64, HashSet<u64>>,
}

impl CallGraph {
    pub fn new() -> Self { Self { edges: HashMap::new(), reverse_edges: HashMap::new() } }
    pub fn tambah_edge(&mut self, caller: u64, callee: u64) {
        self.edges.entry(caller).or_default().insert(callee);
        self.reverse_edges.entry(callee).or_default().insert(caller);
    }
    pub fn dapatkan_callees(&self, caller: u64) -> impl Iterator<Item = &u64> { self.edges.get(&caller).into_iter().flatten() }
    pub fn dapatkan_callers(&self, callee: u64) -> impl Iterator<Item = &u64> { self.reverse_edges.get(&callee).into_iter().flatten() }
}

pub struct TypeSystem {
    pub global_signatures: HashMap<u64, SignatureFungsi>,
    pub variable_types: HashMap<String, TipePrimitif>,
    pub struct_definitions: HashMap<String, StructLayout>,
    pub class_definitions: HashMap<String, ClassLayout>,
    pub constraints: HashSet<ConstraintTipe>,
    pub struct_counter: usize,
    pub unification_cache: HashSet<(TipePrimitif, TipePrimitif)>,
    pub call_graph: CallGraph,
}

impl TypeSystem {
    pub fn new() -> Self {
        Self {
            global_signatures: HashMap::new(),
            variable_types: HashMap::new(),
            struct_definitions: HashMap::new(),
            class_definitions: HashMap::new(),
            constraints: HashSet::new(),
            struct_counter: 0,
            unification_cache: HashSet::new(),
            call_graph: CallGraph::new(),
        }
    }
    pub fn analisis_interprosedural(&mut self, all_functions_stmts: &HashMap<u64, Vec<StatementIr>>) {
        use super::solve::TypeSolver;
        let mut solver = TypeSolver::new(self);
        solver.jalankan_analisis(all_functions_stmts);
    }
    pub fn dapatkan_tipe_c_string(&self, var_name: &str) -> String {
         let tipe = self.variable_types.get(var_name).unwrap_or(&TipePrimitif::Unknown);
         self.konversi_primitif_ke_string(tipe)
    }
    pub fn konversi_primitif_ke_string(&self, tipe: &TipePrimitif) -> String {
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
            TipePrimitif::Pointer(inner) => format!("{}*", self.konversi_primitif_ke_string(inner)),
            TipePrimitif::Struct(name) => format!("struct {}", name),
            TipePrimitif::Class(name) => format!("class {}", name),
            _ => "void*".to_string()
         }
    }
    pub fn definisi_struct(&self) -> BTreeMap<String, BTreeMap<i64, String>> {
        let mut output = BTreeMap::new();
        for (name, layout) in &self.struct_definitions {
            let mut fields_str = BTreeMap::new();
            for (offset, tipe) in &layout.fields {
                fields_str.insert(*offset, self.konversi_primitif_ke_string(tipe));
            }
            output.insert(name.clone(), fields_str);
        }
        for (name, layout) in &self.class_definitions {
            let mut fields_str = BTreeMap::new();
            if layout.vtable_address.is_some() {
                 fields_str.insert(0, "void** /* vptr */".to_string());
            }
            for (offset, tipe) in &layout.fields {
                fields_str.insert(*offset, self.konversi_primitif_ke_string(tipe));
            }
            output.insert(name.clone(), fields_str);
        }
        output
    }
}