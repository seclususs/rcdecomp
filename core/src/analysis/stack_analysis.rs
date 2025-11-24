use std::collections::HashMap;
use crate::ir::types::{StatementIr, TipeOperand};

#[derive(Debug, Clone)]
pub struct StackVariable {
    pub offset: i64,
    pub nama_var: String,
    pub tipe_data: String,
}

pub struct StackFrame {
    pub daftar_variabel: HashMap<i64, StackVariable>,
    pub frame_size: i64,
}

impl StackFrame {
    pub fn new() -> Self {
        Self {
            daftar_variabel: HashMap::new(),
            frame_size: 0,
        }
    }
    pub fn analisis_stack_frame(stmts: &[StatementIr]) -> Self {
        let mut frame = Self::new();
        for stmt in stmts {
            frame.periksa_operand(&stmt.operand_satu);
            frame.periksa_operand(&stmt.operand_dua);
        }
        frame
    }
    fn periksa_operand(&mut self, op: &TipeOperand) {
        if let TipeOperand::MemoryRef { base, offset } = op {
            if base == "rbp" {
                if !self.daftar_variabel.contains_key(offset) {
                    let nama = if *offset < 0 {
                        format!("var_{}", offset.abs())
                    } else {
                        format!("arg_{}", offset)
                    };
                    let var = StackVariable {
                        offset: *offset,
                        nama_var: nama,
                        tipe_data: "int".to_string(),
                    };
                    self.daftar_variabel.insert(*offset, var);
                }
            }
        }
    }
    pub fn ambil_nama_variabel(&self, offset: i64) -> Option<String> {
        self.daftar_variabel.get(&offset).map(|v| v.nama_var.clone())
    }
}