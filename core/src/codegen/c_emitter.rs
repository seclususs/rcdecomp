use std::collections::BTreeMap;
use crate::analysis::structuring::NodeAst;
use crate::analysis::type_inference::{TypeSystem, TipePrimitif};
use crate::analysis::stack_analysis::StackFrame;
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};
use crate::arch::Architecture;

pub struct CEmitter {
    indent_level: usize,
}

impl CEmitter {
    pub fn new() -> Self {
        Self { indent_level: 0 }
    }
    pub fn generate_header_includes(&self) -> String {
        let mut source = String::from("// Decompiled by RCDecomp\n");
        source.push_str("#include <stdio.h>\n");
        source.push_str("#include <stdbool.h>\n");
        source.push_str("#include <stdint.h>\n\n");
        source
    }
    pub fn generate_struct_defs(&self, types: &TypeSystem) -> String {
        let mut source = String::new();
        let struct_defs = types.definisi_struct();
        if !struct_defs.is_empty() {
            source.push_str("// Detected Structures\n");
            for (nama, fields) in &struct_defs {
                source.push_str(&format!("typedef struct {} {{\n", nama));
                for (offset, tipe_str) in fields {
                    source.push_str(&format!("    {} field_{};\n", tipe_str, offset));
                }
                source.push_str(&format!("}} {};\n\n", nama));
            }
        }
        source
    }
    pub fn hasilkan_fungsi_tunggal(
        &mut self,
        func_name: &str,
        ast: &NodeAst, 
        types: &TypeSystem, 
        stack_frame: &StackFrame,
        symbol_map: &BTreeMap<u64, String>,
        entry_params: &[String],
        arch: &dyn Architecture
    ) -> String {
        let mut source = String::new();
        let params_str = if entry_params.is_empty() {
            "void".to_string()
        } else {
            let p: Vec<String> = entry_params.iter().map(|s| {
                let base_name = s.split('_').next().unwrap_or(s);
                let tipe = types.dapatkan_tipe_c(base_name);
                format!("{} {}", tipe, s)
            }).collect();
            p.join(", ")
        };
        source.push_str(&format!("void {}({}) {{\n", func_name, params_str));
        self.indent_level = 1;
        if !stack_frame.map_offset_variabel.is_empty() {
            let indent = "    ".repeat(self.indent_level);
            source.push_str(&format!("{}// Local Stack Variables\n", indent));
            let mut all_vars = Vec::new();
            for vars in stack_frame.map_offset_variabel.values() {
                for var in vars {
                    all_vars.push(var);
                }
            }
            all_vars.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.nama_var.cmp(&b.nama_var)));
            for var in all_vars {
                let addr_taken_marker = if var.is_address_taken { " // &addr_taken" } else { "" };
                source.push_str(&format!("{}{} {}; // [fp {:+}]{}\n", 
                    indent, var.tipe_data, var.nama_var, var.offset, addr_taken_marker));
            }
            source.push_str("\n");
        }
        source.push_str(&self.emit_node_ast(ast, types, stack_frame, symbol_map, arch));
        source.push_str("}\n\n");
        source
    }
    fn emit_node_ast(&mut self, node: &NodeAst, types: &TypeSystem, stack_frame: &StackFrame, symbol_map: &BTreeMap<u64, String>, arch: &dyn Architecture) -> String {
        let mut code = String::new();
        let indent = "    ".repeat(self.indent_level);
        match node {
            NodeAst::Block(stmts) => {
                for stmt in stmts {
                    code.push_str(&format!("{}{}\n", indent, self.konversi_stmt_ke_c(stmt, types, stack_frame, symbol_map, arch)));
                }
            },
            NodeAst::Sequence(nodes) => {
                for n in nodes {
                    code.push_str(&self.emit_node_ast(n, types, stack_frame, symbol_map, arch));
                }
            },
            NodeAst::IfElse { condition, true_branch, false_branch } => {
                code.push_str(&format!("{}if ({}) {{\n", indent, condition));
                self.indent_level += 1;
                code.push_str(&self.emit_node_ast(true_branch, types, stack_frame, symbol_map, arch));
                self.indent_level -= 1;
                if let Some(false_node) = false_branch {
                    code.push_str(&format!("{}}} else {{\n", indent));
                    self.indent_level += 1;
                    code.push_str(&self.emit_node_ast(false_node, types, stack_frame, symbol_map, arch));
                    self.indent_level -= 1;
                }
                code.push_str(&format!("{}}}\n", indent));
            },
            NodeAst::Switch { variable, cases, default } => {
                code.push_str(&format!("{}switch ({}) {{\n", indent, variable));
                self.indent_level += 1;
                let case_indent = "    ".repeat(self.indent_level);
                for (val, body) in cases {
                    code.push_str(&format!("{}case {}:\n", case_indent, val));
                    self.indent_level += 1;
                    code.push_str(&self.emit_node_ast(body, types, stack_frame, symbol_map, arch));
                    code.push_str(&format!("{}    break;\n", case_indent));
                    self.indent_level -= 1;
                }
                if let Some(def_body) = default {
                    code.push_str(&format!("{}default:\n", case_indent));
                    self.indent_level += 1;
                    code.push_str(&self.emit_node_ast(def_body, types, stack_frame, symbol_map, arch));
                    self.indent_level -= 1;
                } 
                self.indent_level -= 1;
                code.push_str(&format!("{}}}\n", indent));
            },
            NodeAst::WhileLoop { condition, body, is_do_while: _ } => {
                code.push_str(&format!("{}while ({}) {{\n", indent, condition));
                self.indent_level += 1;
                code.push_str(&self.emit_node_ast(body, types, stack_frame, symbol_map, arch));
                self.indent_level -= 1;
                code.push_str(&format!("{}}}\n", indent));
            },
            NodeAst::UnstructuredGoto(target) => {
                code.push_str(&format!("{}goto addr_0x{:x};\n", indent, target));
            },
            NodeAst::Break => {
                code.push_str(&format!("{}break;\n", indent));
            },
            NodeAst::Continue => {
                code.push_str(&format!("{}continue;\n", indent));
            },
            NodeAst::Empty => {}
        }
        code
    }
    fn konversi_stmt_ke_c(&self, stmt: &StatementIr, types: &TypeSystem, stack_frame: &StackFrame, symbol_map: &BTreeMap<u64, String>, arch: &dyn Architecture) -> String {
        let label = format!("addr_0x{:x}: ", stmt.address_asal);
        match stmt.operation_code {
             OperasiIr::Mov | 
             OperasiIr::Add | OperasiIr::Sub | OperasiIr::Imul | OperasiIr::Div |
             OperasiIr::And | OperasiIr::Or | OperasiIr::Xor | 
             OperasiIr::Shl | OperasiIr::Shr => {
                let op1 = self.format_operand(&stmt.operand_satu, types, stack_frame, arch, stmt.address_asal);
                let op2 = self.format_operand(&stmt.operand_dua, types, stack_frame, arch, stmt.address_asal);
                return format!("{}{} = {};", label, op1, op2);
            },
            _ => {}
        }
        let operation = match stmt.operation_code {
            OperasiIr::Call => {
                let func_name = if let TipeOperand::Immediate(addr) = stmt.operand_satu {
                    if let Some(sym) = symbol_map.get(&(addr as u64)) {
                        sym.clone()
                    } else {
                        format!("sub_{:x}", addr)
                    }
                } else {
                    self.format_operand(&stmt.operand_satu, types, stack_frame, arch, stmt.address_asal)
                };
                let mut args_str = Vec::new();
                for arg in &stmt.operand_tambahan {
                     args_str.push(self.format_operand(arg, types, stack_frame, arch, stmt.address_asal));
                }
                if args_str.is_empty() {
                    format!("{}(...);", func_name)
                } else {
                    format!("{}({});", func_name, args_str.join(", "))
                }
            },
            OperasiIr::Ret => "return;".to_string(),
            OperasiIr::Phi => {
                let target = self.format_operand(&stmt.operand_satu, types, stack_frame, arch, stmt.address_asal);
                let args: Vec<String> = stmt.operand_tambahan.iter()
                    .map(|op| self.format_operand(op, types, stack_frame, arch, stmt.address_asal))
                    .collect();
                format!("{} = PHI({});", target, args.join(", "))
            }
            _ => format!("// asm: {:?}", stmt.operation_code)
        };
        format!("{}{}", label, operation)
    }
    fn format_operand(
        &self, 
        op: &TipeOperand, 
        types: &TypeSystem, 
        stack_frame: &StackFrame, 
        arch: &dyn Architecture,
        current_addr: u64
    ) -> String {
        match op {
            TipeOperand::Register(r) => r.clone(),
            TipeOperand::SsaVariable(name, ver) => format!("{}_{}", name, ver),
            TipeOperand::Immediate(val) => format!("0x{:x}", val),
            TipeOperand::Memory(addr) => format!("*(long*)0x{:x}", addr),
            TipeOperand::MemoryRef { base, offset } => {
                if let Some(TipePrimitif::Struct(_)) = types.variable_types.get(base) {
                     return format!("{}->field_{}", base, offset);
                }
                if base == &arch.dapatkan_frame_pointer() {
                    if let Some(nama) = stack_frame.ambil_variabel_kontekstual(*offset, current_addr) {
                        return nama;
                    }
                }
                let sign = if *offset >= 0 { "+" } else { "" };
                format!("*(long*)({} {} {})", base, sign, offset)
            },
            TipeOperand::Expression { operasi, operand_kiri, operand_kanan } => {
                let kiri_str = self.format_operand(operand_kiri, types, stack_frame, arch, current_addr);
                let kanan_str = self.format_operand(operand_kanan, types, stack_frame, arch, current_addr);
                let op_symbol = match operasi {
                    OperasiIr::Add => "+",
                    OperasiIr::Sub => "-",
                    OperasiIr::Imul => "*",
                    OperasiIr::Div => "/",
                    OperasiIr::And => "&",
                    OperasiIr::Or => "|",
                    OperasiIr::Xor => "^",
                    OperasiIr::Shl => "<<",
                    OperasiIr::Shr => ">>",
                    _ => "?",
                };
                format!("({} {} {})", kiri_str, op_symbol, kanan_str)
            },
            TipeOperand::None => "".to_string(),
        }
    }
}