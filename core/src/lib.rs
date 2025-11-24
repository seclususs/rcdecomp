pub mod loader;
pub mod disasm;
pub mod ir;
pub mod analysis;
pub mod codegen;

use libc::{c_char, c_int};
use std::ffi::CStr;

pub struct ContextDecompiler {
    pub is_initialized: bool,
    pub last_error: String,
}

#[unsafe(no_mangle)]
pub extern "C" fn create_contextDecompiler() -> *mut ContextDecompiler {
    let context = ContextDecompiler {
        is_initialized: true,
        last_error: String::new(),
    };
    Box::into_raw(Box::new(context))
}

#[unsafe(no_mangle)]
pub extern "C" fn free_contextDecompiler(ctx_ptr: *mut ContextDecompiler) {
    if !ctx_ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ctx_ptr);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn load_binaryFile(
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
            match loader::process_muat_file(path_str) {
                Ok((code_bytes, entry_point, arch)) => {
                    println!("Berhasil load_binaryFile: {} (Arch: {})", path_str, arch);
                    let engine = disasm::engine::DisasmEngine::buat_engine_baru(&arch);
                    println!("Mulai disassembly section .text...");
                    let instructions = engine.disassemble_buffer(&code_bytes, entry_point);
                    for instr in &instructions {
                        println!("0x{:x}: {:<10} {}", instr.address, instr.mnemonic, instr.op_str);
                    }
                    println!("Total instruksi didapat: {}", instructions.len());
                    0
                },
                Err(e) => {
                    context.last_error = format!("Gagal memuat: {}", e);
                    -2
                }
            }
        },
        Err(_) => -3
    }
}