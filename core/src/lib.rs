pub mod loader;
pub mod disasm;
pub mod ir;
pub mod analysis;
pub mod codegen;
pub mod arch;

use libc::{c_char, c_int};
use std::ffi::CStr;
use std::collections::HashMap;
use log::{info, error};
use crate::arch::Architecture;
use crate::loader::LoaderError;

pub struct ContextDecompiler {
    pub is_initialized: bool,
    pub last_error: String,
}

#[unsafe(no_mangle)]
pub extern "C" fn buat_konteks_decompiler() -> *mut ContextDecompiler {
    let context = ContextDecompiler {
        is_initialized: true,
        last_error: String::new(),
    };
    Box::into_raw(Box::new(context))
}

#[unsafe(no_mangle)]
pub extern "C" fn hapus_konteks_decompiler(ctx_ptr: *mut ContextDecompiler) {
    if !ctx_ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ctx_ptr);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn muat_file_biner(
    ctx_ptr: *mut ContextDecompiler,
    path_ptr: *const c_char
) -> c_int {
    if ctx_ptr.is_null() || path_ptr.is_null() {
        return -1;
    }
    let context = unsafe { &mut *ctx_ptr };
    let c_str = unsafe { CStr::from_ptr(path_ptr) };
    match c_str.to_str() {
        Ok(path_str) => {
            match loader::proses_muat_file(path_str) {
                Ok(vmem) => {
                    info!("Berhasil muat: {}", path_str);
                    info!("Arsitektur: {}", vmem.arsitektur);
                    let arsitektur: Box<dyn Architecture> = if vmem.arsitektur == "x86_64" {
                        Box::new(arch::x86::X86Arsitektur64)
                    } else if vmem.arsitektur.contains("arm") {
                        Box::new(arch::arm64::Arm64Arsitektur)
                    } else {
                        Box::new(arch::x86::X86Arsitektur64)
                    };
                    let mut analyzer = analysis::recovery::explorer::RecursiveDescent::new(&vmem.arsitektur);
                    analyzer.lakukan_analisis_full(&vmem);
                    let hasil_fungsi = analyzer.ambil_hasil_fungsi();
                    let jump_targets_map = &analyzer.global_jump_targets;
                    let mut all_source_code = String::new();
                    let mut emitter = codegen::c_gen::CEmitter::new();
                    all_source_code.push_str(&emitter.generate_header_includes());
                    let mut type_sys = analysis::recovery::types::TypeSystem::new();
                    let std_lib_manager = analysis::recovery::std_lib::StdLibManager::new();
                    std_lib_manager.terapkan_signature_standar(&vmem.simbol_global, &mut type_sys);
                    let mut map_ir_global = HashMap::new();
                    for (addr, ctx) in hasil_fungsi {
                        map_ir_global.insert(*addr, ctx.ir_code.clone());
                    }
                    type_sys.analisis_interprosedural(&map_ir_global);
                    all_source_code.push_str(&emitter.generate_struct_defs(&type_sys));
                    let mut fungsi_sorted: Vec<_> = hasil_fungsi.keys().collect();
                    fungsi_sorted.sort();
                    for func_addr in fungsi_sorted {
                        let ctx = hasil_fungsi.get(func_addr).unwrap();
                        let ir_statements = &ctx.ir_code;
                        let mut cfg = analysis::graph::cfg::ControlFlowGraph::bangun_execution_graph(ir_statements.clone(), jump_targets_map);
                        let stack_frame = analysis::recovery::stack::StackFrame::analisis_stack_frame(ir_statements, arsitektur.as_ref());
                        let mut dom_tree = analysis::graph::dom::DominatorTree::new();
                        dom_tree.hitung_dominators(&cfg);
                        let mut ssa_trans = analysis::passes::ssa::SsaTransformer::new();
                        ssa_trans.lakukan_transformasi_ssa(&mut cfg, &dom_tree);
                        ssa_trans.optimasi_propagasi_konstanta(&mut cfg);
                        let mut expr_opt = analysis::passes::opt_expr::ExpressionOptimizer::new();
                        expr_opt.jalankan_optimasi(&mut cfg);  
                        ssa_trans.optimasi_dead_code(&mut cfg); 
                        let calling_conv = analysis::recovery::abi::CallingConventionAnalyzer::new(arsitektur.as_ref());
                        let params = calling_conv.deteksi_entry_params(&cfg);
                        let mut structurer = analysis::recovery::ast::ControlFlowStructurer::new();
                        let ast = structurer.bangun_tree_struktur(&mut cfg);
                        let nama_fungsi = if let Some(sym) = vmem.simbol_global.get(func_addr) {
                            sym.clone()
                        } else if *func_addr == vmem.entry_point {
                            "entry_point".to_string()
                        } else {
                            format!("sub_{:x}", func_addr)
                        };
                        let func_code = emitter.hasilkan_fungsi_tunggal(&nama_fungsi, &ast, &type_sys, &stack_frame, &vmem.simbol_global, &params, arsitektur.as_ref());
                        all_source_code.push_str(&func_code);
                    }
                    info!("{}", all_source_code);
                    0
                },
                Err(e) => {
                    let code = match e {
                        LoaderError::NotFound => -2,
                        LoaderError::InvalidFormat => -3,
                        LoaderError::ParseError(_) => -4,
                        LoaderError::IoError(_) => -5,
                        LoaderError::OutOfBoundsError => -6,
                    };
                    let error_msg = format!("Load Fail: {}", e);
                    error!("{}", error_msg);
                    context.last_error = error_msg;
                    code
                }
            }
        },
        Err(_) => -1 
    }
}