use crate::analysis::structuring::NodeAst;
use crate::analysis::type_inference::TypeSystem;
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};

pub struct CEmitter {
    indent_level: usize,
}

impl CEmitter {
    pub fn new() -> Self {
        Self { indent_level: 0 }
    }
    pub fn emit_full_program(&mut self, ast: &NodeAst, types: &TypeSystem) -> String {
        let mut source = String::from("// Decompiled by RCDecomp\n");
        source.push_str("#include <stdio.h>\n");
        source.push_str("#include <stdbool.h>\n\n");
        source.push_str("// Register Variables\n");
        for (reg, _tipe) in &types.tabel_tipe {
            let c_type = types.dapatkan_tipe_c(reg);
            source.push_str(&format!("{} {};\n", c_type, reg));
        }
        source.push_str("\n");
        source.push_str("void entry_function() {\n");
        self.indent_level += 1;
        source.push_str(&self.emit_node_ast(ast));
        self.indent_level -= 1;
        source.push_str("}\n");
        source
    }
    fn emit_node_ast(&mut self, node: &NodeAst) -> String {
        let mut code = String::new();
        let indent = "    ".repeat(self.indent_level);
        match node {
            NodeAst::Block(stmts) => {
                for stmt in stmts {
                    code.push_str(&format!("{}{}\n", indent, self.convert_stmt_to_c(stmt)));
                }
            },
            NodeAst::Sequence(nodes) => {
                for n in nodes {
                    code.push_str(&self.emit_node_ast(n));
                }
            },
            NodeAst::IfElse { condition, true_branch, false_branch } => {
                code.push_str(&format!("{}if ({}) {{\n", indent, condition));
                self.indent_level += 1;
                code.push_str(&self.emit_node_ast(true_branch));
                self.indent_level -= 1;
                
                if let Some(false_node) = false_branch {
                    code.push_str(&format!("{}}} else {{\n", indent));
                    self.indent_level += 1;
                    code.push_str(&self.emit_node_ast(false_node));
                    self.indent_level -= 1;
                }
                code.push_str(&format!("{}}}\n", indent));
            },
            NodeAst::WhileLoop { condition, body } => {
                code.push_str(&format!("{}while ({}) {{\n", indent, condition));
                self.indent_level += 1;
                code.push_str(&self.emit_node_ast(body));
                self.indent_level -= 1;
                code.push_str(&format!("{}}}\n", indent));
            },
            NodeAst::UnstructuredGoto(target) => {
                code.push_str(&format!("{}goto addr_0x{:x};\n", indent, target));
            }
        }
        code
    }
    fn convert_stmt_to_c(&self, stmt: &StatementIr) -> String {
        let label = format!("addr_0x{:x}: ", stmt.address_asal);
        let operation = match stmt.operation_code {
            OperasiIr::Mov => {
                let op1 = self.fmt_operand(&stmt.operand_satu);
                let op2 = self.fmt_operand(&stmt.operand_dua);
                format!("{} = {};", op1, op2)
            },
            OperasiIr::Add => {
                let op1 = self.fmt_operand(&stmt.operand_satu);
                let op2 = self.fmt_operand(&stmt.operand_dua);
                format!("{} += {};", op1, op2)
            },
            OperasiIr::Call => {
                let func = self.fmt_operand(&stmt.operand_satu);
                format!("call_func({});", func)
            },
            OperasiIr::Ret => "return;".to_string(),
            _ => format!("// asm: {:?}", stmt.operation_code)
        };
        format!("{}{}", label, operation)
    }
    fn fmt_operand(&self, op: &TipeOperand) -> String {
        match op {
            TipeOperand::Register(r) => r.clone(),
            TipeOperand::Immediate(val) => format!("0x{:x}", val),
            TipeOperand::Memory(addr) => format!("*(long*)0x{:x}", addr),
            TipeOperand::None => "".to_string(),
        }
    }
}