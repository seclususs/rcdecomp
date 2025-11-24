use std::ffi::CString;
use rcdecomp_core::{buat_konteks_decompiler, muat_file_biner, hapus_konteks_decompiler};
use env_logger;
use log::{info, error};

fn main() {
    env_logger::init();
    info!("RCDecomp CLI - Memulai...");
    let ctx_ptr = buat_konteks_decompiler();
    if ctx_ptr.is_null() {
        error!("Gagal buat_konteks_decompiler!");
        return;
    }
    info!("Context berhasil dibuat.");
    let path_target = "test_binary.elf"; 
    let c_path = CString::new(path_target).expect("CString conversion failed");
    let status_code = muat_file_biner(ctx_ptr, c_path.as_ptr());
    if status_code == 0 {
        info!("Sukses memanggil muat_file_biner untuk: {}", path_target);
    } else {
        error!("Gagal muat_file_biner dengan kode: {}", status_code);
    }
    hapus_konteks_decompiler(ctx_ptr);
    info!("Selesai cleanup_resources.");
}