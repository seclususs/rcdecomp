use std::collections::HashMap;
use crate::analysis::structuring::NodeAst;
use crate::analysis::type_inference::TypeSystem;
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
    pub fn hasilkan_kode_c(
        &mut self, 
        ast: &NodeAst, 
        types: &TypeSystem, 
        stack_frame: &StackFrame,
        symbol_map: &HashMap<u64, String>,
        entry_params: &[String],
        arch: &dyn Architecture
    ) -> String {
        let mut source = String::from("// Decompiled by RCDecomp\n");
        source.push_str("#include <stdio.h>\n");
        source.push_str("#include <stdbool.h>\n\n");
        if !types.definisi_struct.is_empty() {
            source.push_str("// Detected Structures\n");
            for (nama, fields) in &types.definisi_struct {
                source.push_str(&format!("typedef struct {} {{\n", nama));
                for (offset, _) in fields {
                    source.push_str(&format!("    long field_{};\n", offset));
                }
                source.push_str(&format!("}} {};\n\n", nama));
            }
        }
        source.push_str("// Register Variables (SSA Mode)\n");
        source.push_str("// (Implicit declarations for SSA variables)\n");
        source.push_str("\n");
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
        source.push_str(&format!("void entry_function({}) {{\n", params_str));
        self.indent_level += 1;
        if !stack_frame.daftar_variabel.is_empty() {
            let indent = "    ".repeat(self.indent_level);
            source.push_str(&format!("{}// Local Stack Variables\n", indent));
            let mut vars: Vec<_> = stack_frame.daftar_variabel.values().collect();
            vars.sort_by_key(|v| v.offset);
            for var in vars {
                source.push_str(&format!("{}{} {}; // [rbp {:+}]\n", indent, var.tipe_data, var.nama_var, var.offset));
            }
            source.push_str("\n");
        }
        source.push_str(&self.emit_node_ast(ast, types, stack_frame, symbol_map, arch));
        self.indent_level -= 1;
        source.push_str("}\n");
        source
    }
    fn emit_node_ast(&mut self, node: &NodeAst, types: &TypeSystem, stack_frame: &StackFrame, symbol_map: &HashMap<u64, String>, arch: &dyn Architecture) -> String {
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
            NodeAst::WhileLoop { condition, body } => {
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
            }
        }
        code
    }
    fn konversi_stmt_ke_c(&self, stmt: &StatementIr, types: &TypeSystem, stack_frame: &StackFrame, symbol_map: &HashMap<u64, String>, arch: &dyn Architecture) -> String {
        let label = format!("addr_0x{:x}: ", stmt.address_asal);
        let operation = match stmt.operation_code {
            OperasiIr::Mov => {
                let op1 = self.format_operand(&stmt.operand_satu, types, stack_frame, arch);
                let op2 = self.format_operand(&stmt.operand_dua, types, stack_frame, arch);
                format!("{} = {};", op1, op2)
            },
            OperasiIr::Add => {
                let op1 = self.format_operand(&stmt.operand_satu, types, stack_frame, arch);
                let op2 = self.format_operand(&stmt.operand_dua, types, stack_frame, arch);
                format!("{} += {};", op1, op2)
            },
            OperasiIr::Sub => {
                let op1 = self.format_operand(&stmt.operand_satu, types, stack_frame, arch);
                let op2 = self.format_operand(&stmt.operand_dua, types, stack_frame, arch);
                format!("{} -= {};", op1, op2)
            },
            OperasiIr::Call => {
                let func_name = if let TipeOperand::Immediate(addr) = stmt.operand_satu {
                    if let Some(sym) = symbol_map.get(&(addr as u64)) {
                        sym.clone()
                    } else {
                        self.format_operand(&stmt.operand_satu, types, stack_frame, arch)
                    }
                } else {
                    self.format_operand(&stmt.operand_satu, types, stack_frame, arch)
                };
                let mut args_str = Vec::new();
                for arg in &stmt.operand_tambahan {
                    if let TipeOperand::SsaVariable(_, _) = arg {
                         args_str.push(self.format_operand(arg, types, stack_frame, arch));
                    }
                }
                if args_str.is_empty() {
                    format!("{}(...);", func_name)
                } else {
                    format!("{}({});", func_name, args_str.join(", "))
                }
            },
            OperasiIr::Ret => "return;".to_string(),
            OperasiIr::Phi => {
                let target = self.format_operand(&stmt.operand_satu, types, stack_frame, arch);
                let args: Vec<String> = stmt.operand_tambahan.iter()
                    .map(|op| self.format_operand(op, types, stack_frame, arch))
                    .collect();
                format!("{} = PHI({});", target, args.join(", "))
            }
            _ => format!("// asm: {:?}", stmt.operation_code)
        };
        format!("{}{}", label, operation)
    }
    fn format_operand(&self, op: &TipeOperand, types: &TypeSystem, stack_frame: &StackFrame, arch: &dyn Architecture) -> String {
        match op {
            TipeOperand::Register(r) => r.clone(),
            TipeOperand::SsaVariable(name, ver) => format!("{}_{}", name, ver),
            TipeOperand::Immediate(val) => format!("0x{:x}", val),
            TipeOperand::Memory(addr) => format!("*(long*)0x{:x}", addr),
            TipeOperand::MemoryRef { base, offset } => {
                if let Some(crate::analysis::type_inference::JenisTipe::Struct { .. }) = types.tabel_tipe.get(base) {
                    return format!("{}->field_{}", base, offset);
                }
                if base == &arch.dapatkan_frame_pointer() {
                    if let Some(nama) = stack_frame.ambil_nama_variabel(*offset) {
                        return nama;
                    }
                }
                let sign = if *offset >= 0 { "+" } else { "" };
                format!("*(long*)({} {} {})", base, sign, offset)
            },
            TipeOperand::Expression { operasi, operand_kiri, operand_kanan } => {
                if *operasi == OperasiIr::Add {
                    if let TipeOperand::Expression { operasi: op_mul, operand_kiri: idx, operand_kanan: _scale } = &**operand_kanan {
                        if *op_mul == OperasiIr::Imul {
                            let base_str = self.format_operand(operand_kiri, types, stack_frame, arch);
                            let index_str = self.format_operand(idx, types, stack_frame, arch);
                            return format!("{}[{}]", base_str, index_str);
                        }
                    }
                }
                let kiri_str = self.format_operand(operand_kiri, types, stack_frame, arch);
                let kanan_str = self.format_operand(operand_kanan, types, stack_frame, arch);
                let op_symbol = match operasi {
                    OperasiIr::Add => "+",
                    OperasiIr::Sub => "-",
                    OperasiIr::Imul => "*",
                    _ => "?",
                };
                format!("({} {} {})", kiri_str, op_symbol, kanan_str)
            },
            TipeOperand::None => "".to_string(),
        }
    }
}