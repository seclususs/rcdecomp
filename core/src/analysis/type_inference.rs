use std::collections::HashMap;
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};

#[derive(Debug, Clone, PartialEq)]
pub enum JenisTipe {
    Void,
    Integer,
    Pointer,
    Boolean,
}

pub struct TypeSystem {
    pub tabel_tipe: HashMap<String, JenisTipe>,
}

impl TypeSystem {
    pub fn new() -> Self {
        Self {
            tabel_tipe: HashMap::new(),
        }
    }
    pub fn jalankan_inferensi(&mut self, statements: &[StatementIr]) {
        for stmt in statements {
            self.analisa_statement(stmt);
        }
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
            _ => "long".to_string(),
        }
    }
}