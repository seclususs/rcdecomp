use std::collections::{BTreeMap, HashMap, HashSet};
use crate::analysis::structuring::NodeAst;
use crate::analysis::type_inference::{TypeSystem, TipePrimitif};
use crate::analysis::stack_analysis::StackFrame;
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};
use crate::arch::Architecture;

#[derive(PartialEq, PartialOrd, Clone, Copy)]
#[allow(dead_code)]
enum Precedence {
    Comma = 0,
    Assignment = 1,
    Ternary = 2,
    LogicalOr = 3,
    LogicalAnd = 4,
    BitwiseOr = 5,
    BitwiseXor = 6,
    BitwiseAnd = 7,
    Equality = 8,
    Relational = 9,
    Shift = 10,
    AddSub = 11,
    MulDivMod = 12,
    Prefix = 13,
    Postfix = 14,
    Atom = 15,
}

pub struct CEmitter {
    indent_level: usize,
    var_rename_map: HashMap<String, String>,
    declared_vars: HashSet<String>,
}

impl CEmitter {
    pub fn new() -> Self {
        Self { 
            indent_level: 0,
            var_rename_map: HashMap::new(),
            declared_vars: HashSet::new(),
        }
    }
    pub fn generate_header_includes(&self) -> String {
        let mut source = String::from("/* Decompiled by RCDecomp */\n");
        source.push_str("#include <stdio.h>\n");
        source.push_str("#include <stdbool.h>\n");
        source.push_str("#include <stdint.h>\n");
        source.push_str("#include <stdlib.h>\n");
        source.push_str("#include <string.h>\n");
        source.push_str("#include <math.h>\n");
        source.push_str("// Pseudo-definitions for intrinsics\n");
        source.push_str("typedef float __m128 __attribute__((__vector_size__(16)));\n");
        source.push_str("typedef double __m128d __attribute__((__vector_size__(16)));\n\n");
        source
    }
    pub fn generate_struct_defs(&self, types: &TypeSystem) -> String {
        let mut source = String::new();
        let struct_defs = types.definisi_struct();
        if !struct_defs.is_empty() {
            source.push_str("// Structures\n");
            for (nama, fields) in &struct_defs {
                source.push_str(&format!("struct {} {{\n", nama));
                let mut last_offset = 0;
                for (offset, tipe_str) in fields {
                    if *offset > last_offset {
                        let pad = offset - last_offset;
                        source.push_str(&format!("    char pad_{}[{}];\n", last_offset, pad));
                    }
                    source.push_str(&format!("    {} field_{:x};\n", tipe_str, offset));
                    last_offset = *offset + 8; 
                }
                source.push_str("};\n\n");
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
        self.var_rename_map.clear();
        self.declared_vars.clear();
        let params_str = if entry_params.is_empty() {
            "void".to_string()
        } else {
            let p: Vec<String> = entry_params.iter().map(|s| {
                let clean_name = self.bersihkan_nama_variabel(s);
                let tipe = types.dapatkan_tipe_c_string(s);
                format!("{} {}", tipe, clean_name)
            }).collect();
            p.join(", ")
        };
        source.push_str(&format!("long {}({}) {{\n", func_name, params_str));
        self.indent_level = 1;
        let indent = "    ".repeat(self.indent_level);
        if !stack_frame.map_offset_variabel.is_empty() {
            source.push_str(&format!("{}// Local Variables\n", indent));
            let mut all_vars = Vec::new();
            for vars in stack_frame.map_offset_variabel.values() {
                for var in vars {
                    all_vars.push(var);
                }
            }
            all_vars.sort_by(|a, b| a.offset.cmp(&b.offset));
            for var in all_vars {
                let clean_name = self.bersihkan_nama_variabel(&var.nama_var);
                let tipe_str = types.dapatkan_tipe_c_string(&var.nama_var);
                if !self.declared_vars.contains(&clean_name) {
                    source.push_str(&format!("{}{} {};\n", indent, tipe_str, clean_name));
                    self.declared_vars.insert(clean_name);
                }
            }
            source.push_str("\n");
        }
        source.push_str(&self.emit_node_ast(ast, types, stack_frame, symbol_map, arch));
        source.push_str("}\n\n");
        source
    }
    fn emit_node_ast(
        &mut self, 
        node: &NodeAst, 
        types: &TypeSystem, 
        stack_frame: &StackFrame, 
        symbol_map: &BTreeMap<u64, String>, 
        arch: &dyn Architecture
    ) -> String {
        let mut code = String::new();
        let indent = "    ".repeat(self.indent_level);
        match node {
            NodeAst::Block(stmts) => {
                for stmt in stmts {
                    let stmt_str = self.konversi_stmt_ke_c(stmt, types, stack_frame, symbol_map, arch);
                    if !stmt_str.is_empty() {
                        code.push_str(&format!("{}{}\n", indent, stmt_str));
                    }
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
            NodeAst::TernaryOp { target_var, condition, true_val, false_val } => {
                code.push_str(&format!("{}{} = ({}) ? {} : {};\n", 
                    indent, target_var, condition, true_val, false_val));
            },
            NodeAst::Switch { variable, cases, default } => {
                code.push_str(&format!("{}switch ({}) {{\n", indent, variable));
                self.indent_level += 1;
                let case_indent = "    ".repeat(self.indent_level);
                for (vals, body) in cases {
                    for val in vals {
                        code.push_str(&format!("{}case 0x{:x}:\n", case_indent, val));
                    }
                    self.indent_level += 1;
                    code.push_str(&self.emit_node_ast(body, types, stack_frame, symbol_map, arch));
                    code.push_str(&format!("{}    break;\n", "    ".repeat(self.indent_level)));
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
            NodeAst::WhileLoop { condition, body, is_do_while } => {
                if *is_do_while {
                    code.push_str(&format!("{}do {{\n", indent));
                    self.indent_level += 1;
                    code.push_str(&self.emit_node_ast(body, types, stack_frame, symbol_map, arch));
                    self.indent_level -= 1;
                    code.push_str(&format!("{}}} while ({});\n", indent, condition));
                } else {
                    code.push_str(&format!("{}while ({}) {{\n", indent, condition));
                    self.indent_level += 1;
                    code.push_str(&self.emit_node_ast(body, types, stack_frame, symbol_map, arch));
                    self.indent_level -= 1;
                    code.push_str(&format!("{}}}\n", indent));
                }
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
    fn konversi_stmt_ke_c(
        &self, 
        stmt: &StatementIr, 
        types: &TypeSystem, 
        stack_frame: &StackFrame, 
        symbol_map: &BTreeMap<u64, String>, 
        arch: &dyn Architecture
    ) -> String {
        let prefix = format!("/* 0x{:x} */ ", stmt.address_asal);
        let fmt = |op| self.format_operand_safe(op, types, stack_frame, arch, stmt.address_asal, Precedence::Assignment);
        match &stmt.operation_code {
             OperasiIr::Lea => {
                let op1 = fmt(&stmt.operand_satu);
                let op2 = self.format_address_only(&stmt.operand_dua, types, stack_frame, arch, stmt.address_asal);
                format!("{}{} = {};", prefix, op1, op2)
             },
             OperasiIr::Add | OperasiIr::Sub | OperasiIr::Imul | 
             OperasiIr::And | OperasiIr::Or | OperasiIr::Xor | 
             OperasiIr::Shl | OperasiIr::Shr => {
                let op1 = fmt(&stmt.operand_satu);
                let op2 = fmt(&stmt.operand_dua);
                let symbol = match stmt.operation_code {
                    OperasiIr::Add => "+=", OperasiIr::Sub => "-=",
                    OperasiIr::Imul => "*=", OperasiIr::And => "&=", 
                    OperasiIr::Or => "|=", OperasiIr::Xor => "^=",
                    OperasiIr::Shl => "<<=", OperasiIr::Shr => ">>=",
                    _ => "="
                };
                format!("{}{} {} {};", prefix, op1, symbol, op2)
            },
            OperasiIr::Mov | OperasiIr::VecMov => {
                let op1 = fmt(&stmt.operand_satu);
                let op2 = fmt(&stmt.operand_dua);
                format!("{}{} = {};", prefix, op1, op2)
            },
            OperasiIr::Div | OperasiIr::FDiv | OperasiIr::VecDiv => {
                let op1 = fmt(&stmt.operand_satu);
                let op2 = fmt(&stmt.operand_dua);
                format!("{}{} /= {};", prefix, op1, op2)
            },
            OperasiIr::Call => {
                let func_target = if let TipeOperand::Immediate(addr) = stmt.operand_satu {
                    if let Some(sym) = symbol_map.get(&(addr as u64)) {
                        sym.clone()
                    } else {
                        format!("sub_{:x}", addr)
                    }
                } else {
                    fmt(&stmt.operand_satu)
                };
                let args: Vec<String> = stmt.operand_tambahan.iter()
                    .map(|arg| self.format_operand_safe(arg, types, stack_frame, arch, stmt.address_asal, Precedence::Comma))
                    .collect();
                format!("{}{}({});", prefix, func_target, args.join(", "))
            },
            OperasiIr::Ret => format!("{}return;", prefix),
            OperasiIr::Phi => {
                let target = fmt(&stmt.operand_satu);
                format!("{}// PHI node: {} = ...", prefix, target)
            }
            OperasiIr::Cmp | OperasiIr::Test | OperasiIr::FCmp => {
                String::new() 
            },
            _ => format!("{}// Unhandled Op: {:?}", prefix, stmt.operation_code)
        }
    }
    fn format_operand_safe(
        &self, 
        op: &TipeOperand, 
        types: &TypeSystem, 
        stack_frame: &StackFrame, 
        arch: &dyn Architecture,
        addr: u64,
        parent_prec: Precedence
    ) -> String {
        match op {
            TipeOperand::Register(r) => self.bersihkan_nama_variabel(r),
            TipeOperand::SsaVariable(name, ver) => format!("{}_{}", self.bersihkan_nama_variabel(name), ver),
            TipeOperand::Immediate(val) => format!("0x{:x}", val),
            TipeOperand::FloatImmediate(val) => format!("{:.4}f", val),
            TipeOperand::Memory(addr) => format!("*(long*)0x{:x}", addr),
            TipeOperand::MemoryRef { base, offset } => {
                let base_clean = self.bersihkan_nama_variabel(base);
                if let Some(TipePrimitif::Pointer(inner)) = types.variable_types.get(&base_clean) {
                    if let TipePrimitif::Struct(_) = **inner {
                         return format!("{}->field_{:x}", base_clean, offset);
                    }
                }
                if base == &arch.dapatkan_frame_pointer() {
                    if let Some(nama) = stack_frame.ambil_variabel_kontekstual(*offset, addr) {
                        return self.bersihkan_nama_variabel(&nama);
                    }
                }
                let expr = if *offset != 0 {
                    format!("{} + 0x{:x}", base_clean, offset)
                } else {
                    base_clean
                };
                format!("*(long*)({})", expr)
            },
            TipeOperand::Expression { operasi, operand_kiri, operand_kanan } => {
                let my_prec = self.get_operator_precedence(operasi);
                let left = self.format_operand_safe(operand_kiri, types, stack_frame, arch, addr, my_prec);
                let right = self.format_operand_safe(operand_kanan, types, stack_frame, arch, addr, my_prec);
                let op_str = self.get_operator_str(operasi);
                let expr_str = format!("{} {} {}", left, op_str, right);
                if my_prec < parent_prec {
                    format!("({})", expr_str)
                } else {
                    expr_str
                }
            },
            TipeOperand::None => "/*err*/".to_string(),
        }
    }
    fn format_address_only(
        &self,
        op: &TipeOperand,
        types: &TypeSystem,
        stack_frame: &StackFrame,
        arch: &dyn Architecture,
        addr: u64
    ) -> String {
        match op {
            TipeOperand::MemoryRef { base, offset } => {
                let base_clean = self.bersihkan_nama_variabel(base);
                if base == &arch.dapatkan_frame_pointer() {
                    if let Some(nama) = stack_frame.ambil_variabel_kontekstual(*offset, addr) {
                        return format!("&{}", self.bersihkan_nama_variabel(&nama));
                    }
                }
                if *offset != 0 {
                    format!("{} + 0x{:x}", base_clean, offset)
                } else {
                    base_clean
                }
            },
            _ => self.format_operand_safe(op, types, stack_frame, arch, addr, Precedence::Comma)
        }
    }
    fn get_operator_precedence(&self, op: &OperasiIr) -> Precedence {
        match op {
            OperasiIr::Imul | OperasiIr::Div | OperasiIr::FMul | OperasiIr::FDiv => Precedence::MulDivMod,
            OperasiIr::Add | OperasiIr::Sub | OperasiIr::FAdd | OperasiIr::FSub => Precedence::AddSub,
            OperasiIr::Shl | OperasiIr::Shr => Precedence::Shift,
            OperasiIr::And => Precedence::BitwiseAnd,
            OperasiIr::Xor | OperasiIr::VecXor => Precedence::BitwiseXor,
            OperasiIr::Or => Precedence::BitwiseOr,
            OperasiIr::Je | OperasiIr::Jne => Precedence::Equality,
            OperasiIr::Jg | OperasiIr::Jl | OperasiIr::Jge | OperasiIr::Jle |
            OperasiIr::Cmp | OperasiIr::FCmp => Precedence::Relational,
            _ => Precedence::Atom,
        }
    }
    fn get_operator_str(&self, op: &OperasiIr) -> &str {
        match op {
            OperasiIr::Add | OperasiIr::FAdd | OperasiIr::VecAdd => "+",
            OperasiIr::Sub | OperasiIr::FSub | OperasiIr::VecSub => "-",
            OperasiIr::Imul | OperasiIr::FMul | OperasiIr::VecMul => "*",
            OperasiIr::Div | OperasiIr::FDiv | OperasiIr::VecDiv => "/",
            OperasiIr::And | OperasiIr::VecAnd => "&",
            OperasiIr::Or | OperasiIr::VecOr => "|",
            OperasiIr::Xor | OperasiIr::VecXor => "^",
            OperasiIr::Shl => "<<",
            OperasiIr::Shr => ">>",
            OperasiIr::Je => "==",
            OperasiIr::Jne => "!=",
            OperasiIr::Jg => ">",
            OperasiIr::Jge => ">=",
            OperasiIr::Jl => "<",
            OperasiIr::Jle => "<=",
            _ => "?",
        }
    }
    fn bersihkan_nama_variabel(&self, raw_name: &str) -> String {
        let mut safe_name = raw_name.replace(|c: char| !c.is_alphanumeric() && c != '_', "_");
        if safe_name.chars().next().map(char::is_numeric).unwrap_or(false) {
            safe_name.insert(0, '_');
        }
        if safe_name.starts_with("var__") {
            safe_name = safe_name.replace("var__", "local_");
        } else if safe_name.starts_with("var_") {
             safe_name = safe_name.replace("var_", "local_");
        }
        safe_name
    }
}