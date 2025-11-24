use std::ffi::CString;
use rcdecomp_core::{create_contextDecompiler, load_binaryFile, free_contextDecompiler};

fn main() {
    println!("RCDecomp CLI - Memulai...");
    let ctx_ptr = create_contextDecompiler();
    if ctx_ptr.is_null() {
        eprintln!("Gagal create_contextDecompiler!");
        return;
    }
    println!("Context berhasil dibuat.");
    let path_target = "test_binary.elf";
    let c_path = CString::new(path_target).expect("CString conversion failed");
    let status_code = load_binaryFile(ctx_ptr, c_path.as_ptr());
    if status_code == 0 {
        println!("Sukses memanggil load_binaryFile untuk: {}", path_target);
    } else {
        eprintln!("Gagal load_binaryFile dengan kode: {}", status_code);
    }
    free_contextDecompiler(ctx_ptr);
    println!("Selesai cleanup_resources.");
}