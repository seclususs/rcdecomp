use std::collections::HashMap;
use crate::analysis::structuring::NodeAst;
use crate::analysis::type_inference::TypeSystem;
use crate::analysis::stack_analysis::StackFrame;
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};

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
        _types: &TypeSystem, 
        stack_frame: &StackFrame,
        symbol_map: &HashMap<u64, String>
    ) -> String {
        let mut source = String::from("// Decompiled by RCDecomp\n");
        source.push_str("#include <stdio.h>\n");
        source.push_str("#include <stdbool.h>\n\n");
        source.push_str("// Register Variables (SSA Mode)\n");
        source.push_str("// (Implicit declarations for SSA variables)\n");
        source.push_str("\n");
        source.push_str("void entry_function() {\n");
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
        source.push_str(&self.emit_node_ast(ast, stack_frame, symbol_map));
        self.indent_level -= 1;
        source.push_str("}\n");
        source
    }
    fn emit_node_ast(&mut self, node: &NodeAst, stack_frame: &StackFrame, symbol_map: &HashMap<u64, String>) -> String {
        let mut code = String::new();
        let indent = "    ".repeat(self.indent_level);
        match node {
            NodeAst::Block(stmts) => {
                for stmt in stmts {
                    code.push_str(&format!("{}{}\n", indent, self.konversi_stmt_ke_c(stmt, stack_frame, symbol_map)));
                }
            },
            NodeAst::Sequence(nodes) => {
                for n in nodes {
                    code.push_str(&self.emit_node_ast(n, stack_frame, symbol_map));
                }
            },
            NodeAst::IfElse { condition, true_branch, false_branch } => {
                code.push_str(&format!("{}if ({}) {{\n", indent, condition));
                self.indent_level += 1;
                code.push_str(&self.emit_node_ast(true_branch, stack_frame, symbol_map));
                self.indent_level -= 1;
                
                if let Some(false_node) = false_branch {
                    code.push_str(&format!("{}}} else {{\n", indent));
                    self.indent_level += 1;
                    code.push_str(&self.emit_node_ast(false_node, stack_frame, symbol_map));
                    self.indent_level -= 1;
                }
                code.push_str(&format!("{}}}\n", indent));
            },
            NodeAst::WhileLoop { condition, body } => {
                code.push_str(&format!("{}while ({}) {{\n", indent, condition));
                self.indent_level += 1;
                code.push_str(&self.emit_node_ast(body, stack_frame, symbol_map));
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
    fn konversi_stmt_ke_c(&self, stmt: &StatementIr, stack_frame: &StackFrame, symbol_map: &HashMap<u64, String>) -> String {
        let label = format!("addr_0x{:x}: ", stmt.address_asal);
        let operation = match stmt.operation_code {
            OperasiIr::Mov => {
                let op1 = self.format_operand(&stmt.operand_satu, stack_frame);
                let op2 = self.format_operand(&stmt.operand_dua, stack_frame);
                format!("{} = {};", op1, op2)
            },
            OperasiIr::Add => {
                let op1 = self.format_operand(&stmt.operand_satu, stack_frame);
                let op2 = self.format_operand(&stmt.operand_dua, stack_frame);
                format!("{} += {};", op1, op2)
            },
            OperasiIr::Sub => {
                let op1 = self.format_operand(&stmt.operand_satu, stack_frame);
                let op2 = self.format_operand(&stmt.operand_dua, stack_frame);
                format!("{} -= {};", op1, op2)
            },
            OperasiIr::Call => {
                let func_name = if let TipeOperand::Immediate(addr) = stmt.operand_satu {
                    if let Some(sym) = symbol_map.get(&(addr as u64)) {
                        sym.clone()
                    } else {
                        self.format_operand(&stmt.operand_satu, stack_frame)
                    }
                } else {
                    self.format_operand(&stmt.operand_satu, stack_frame)
                };
                format!("{}(...);", func_name)
            },
            OperasiIr::Ret => "return;".to_string(),
            OperasiIr::Phi => {
                let target = self.format_operand(&stmt.operand_satu, stack_frame);
                let args: Vec<String> = stmt.operand_tambahan.iter()
                    .map(|op| self.format_operand(op, stack_frame))
                    .collect();
                format!("{} = PHI({});", target, args.join(", "))
            }
            _ => format!("// asm: {:?}", stmt.operation_code)
        };
        format!("{}{}", label, operation)
    }
    fn format_operand(&self, op: &TipeOperand, stack_frame: &StackFrame) -> String {
        match op {
            TipeOperand::Register(r) => r.clone(),
            TipeOperand::SsaVariable(name, ver) => format!("{}_{}", name, ver),
            TipeOperand::Immediate(val) => format!("0x{:x}", val),
            TipeOperand::Memory(addr) => format!("*(long*)0x{:x}", addr),
            TipeOperand::MemoryRef { base, offset } => {
                if base == "rbp" {
                    if let Some(nama) = stack_frame.ambil_nama_variabel(*offset) {
                        return nama;
                    }
                }
                let sign = if *offset >= 0 { "+" } else { "" };
                format!("*(long*)({} {} {})", base, sign, offset)
            },
            TipeOperand::None => "".to_string(),
        }
    }
}