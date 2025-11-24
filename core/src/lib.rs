pub mod loader;
pub mod disasm;
pub mod ir;
pub mod analysis;
pub mod codegen;

use libc::{c_char, c_int};
use std::ffi::CStr;
use log::{info, error, debug};

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
                Ok((code_bytes, entry_point, arch, symbol_map)) => {
                    info!("Berhasil muat_file_biner: {} (Arch: {})", path_str, arch);
                    info!("Ditemukan {} simbol.", symbol_map.len());
                    let engine = disasm::engine::DisasmEngine::buat_engine_baru(&arch);
                    info!("Mulai disassembly section .text...");
                    let instructions = engine.lakukan_disassembly(&code_bytes, entry_point);
                    let lifter = ir::lifter::IrLifter::new();
                    let mut ir_statements = Vec::new();
                    for instr in &instructions {
                        ir_statements.push(lifter.konversi_instruksi_ke_ir(instr));
                    }
                    let mut cfg = analysis::cfg::ControlFlowGraph::bangun_execution_graph(ir_statements.clone());
                    let mut type_sys = analysis::type_inference::TypeSystem::new();
                    type_sys.jalankan_inferensi(&ir_statements);
                    info!("Menjalankan analisa stack frame...");
                    let stack_frame = analysis::stack_analysis::StackFrame::analisis_stack_frame(&ir_statements);
                    info!("Membangun struktur kontrol & SSA...");
                    let mut dom_tree = analysis::dominator::DominatorTree::new();
                    dom_tree.hitung_dominators(&cfg);
                    info!("Transformasi ke SSA Form...");
                    let mut ssa_trans = analysis::ssa::SsaTransformer::new();
                    ssa_trans.lakukan_transformasi_ssa(&mut cfg, &dom_tree);
                    info!("Menjalankan optimasi...");
                    ssa_trans.optimasi_propagasi_konstanta(&mut cfg);
                    ssa_trans.optimasi_dead_code(&mut cfg);
                    let mut structurer = analysis::structuring::ControlFlowStructurer::new();
                    let ast = structurer.bangun_tree_struktur(&cfg);
                    info!("Generate C Code...");
                    let mut emitter = codegen::c_emitter::CEmitter::new();
                    let source_c = emitter.hasilkan_kode_c(&ast, &type_sys, &stack_frame, &symbol_map);
                    debug!("\n--- Hasil Dekompilasi (SSA Optimized) ---\n");
                    info!("{}", source_c);
                    debug!("-------------------------\n");
                    0
                },
                Err(e) => {
                    let error_msg = format!("Gagal memuat: {}", e);
                    error!("{}", error_msg);
                    context.last_error = error_msg;
                    -2
                }
            }
        },
        Err(_) => -3
    }
}