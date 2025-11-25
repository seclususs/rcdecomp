use std::collections::{HashMap, BTreeMap};
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};

#[derive(Debug, Clone, PartialEq)]
pub enum JenisTipe {
    Void,
    Integer,
    Pointer,
    Boolean,
    Struct { nama: String, field_offsets: BTreeMap<i64, JenisTipe> },
    Array { elemen: Box<JenisTipe> },
}

pub struct TypeSystem {
    pub tabel_tipe: HashMap<String, JenisTipe>,
    pub definisi_struct: HashMap<String, BTreeMap<i64, JenisTipe>>,
}

impl TypeSystem {
    pub fn new() -> Self {
        Self {
            tabel_tipe: HashMap::new(),
            definisi_struct: HashMap::new(),
        }
    }
    pub fn jalankan_inferensi(&mut self, statements: &[StatementIr]) {
        for stmt in statements {
            self.analisa_statement(stmt);
        }
        self.analisa_memori_komposit(statements);
    }
    fn analisa_statement(&mut self, stmt: &StatementIr) {
        match stmt.operation_code {
            OperasiIr::Mov => {
                if let TipeOperand::Register(reg) = &stmt.operand_satu {
                    self.update_tipe(reg, JenisTipe::Integer);
                }
            },
            OperasiIr::Add | OperasiIr::Sub | OperasiIr::Imul => {
                if let TipeOperand::Register(reg) = &stmt.operand_satu {
                    self.update_tipe(reg, JenisTipe::Integer);
                }
            },
            OperasiIr::Je | OperasiIr::Jne => {

            },
            _ => {}
        }
    }
    fn analisa_memori_komposit(&mut self, stmts: &[StatementIr]) {
        let mut struct_candidates: HashMap<String, BTreeMap<i64, JenisTipe>> = HashMap::new();
        for stmt in stmts {
            self.cek_pola_struct(&stmt.operand_dua, &mut struct_candidates);
            self.cek_pola_struct(&stmt.operand_satu, &mut struct_candidates);
            self.cek_pola_array(&stmt.operand_dua);
        }
        for (base_reg, fields) in struct_candidates {
            if fields.len() > 1 {
                let struct_name = format!("Struct_{}", base_reg);
                self.definisi_struct.insert(struct_name.clone(), fields.clone());
                self.tabel_tipe.insert(base_reg, JenisTipe::Struct { 
                    nama: struct_name, 
                    field_offsets: fields 
                });
            }
        }
    }
    fn cek_pola_struct(&self, op: &TipeOperand, candidates: &mut HashMap<String, BTreeMap<i64, JenisTipe>>) {
        if let TipeOperand::MemoryRef { base, offset } = op {
            if base != "rbp" {
                let fields = candidates.entry(base.clone()).or_default();
                fields.entry(*offset).or_insert(JenisTipe::Integer);
            }
        }
    }
    fn cek_pola_array(&mut self, op: &TipeOperand) {
        if let TipeOperand::Expression { operasi, operand_kiri, operand_kanan } = op {
            if *operasi == OperasiIr::Add {
                if let TipeOperand::Register(base) = &**operand_kiri {
                    if let TipeOperand::Expression { operasi: op_inner, .. } = &**operand_kanan {
                        if *op_inner == OperasiIr::Imul {
                            self.tabel_tipe.insert(base.clone(), JenisTipe::Array { 
                                elemen: Box::new(JenisTipe::Integer) 
                            });
                        }
                    }
                }
            }
        }
    }
    fn update_tipe(&mut self, reg_name: &str, tipe_baru: JenisTipe) {
        let entry = self.tabel_tipe.entry(reg_name.to_string()).or_insert(JenisTipe::Void);
        if *entry == JenisTipe::Void {
            *entry = tipe_baru;
        } else if *entry == JenisTipe::Integer && tipe_baru == JenisTipe::Pointer {
            *entry = JenisTipe::Pointer;
        }
    }
    pub fn dapatkan_tipe_c(&self, reg_name: &str) -> String {
        match self.tabel_tipe.get(reg_name) {
            Some(JenisTipe::Pointer) => "void*".to_string(),
            Some(JenisTipe::Boolean) => "bool".to_string(),
            Some(JenisTipe::Struct { nama, .. }) => format!("{}*", nama),
            Some(JenisTipe::Array { .. }) => "long*".to_string(),
            _ => "long".to_string(),
        }
    }
}