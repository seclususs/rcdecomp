use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let nama_package = env::var("CARGO_PKG_NAME").unwrap();
    let output_file = PathBuf::from(&crate_dir)
        .parent()
        .unwrap()
        .join("include")
        .join("rcdecomp.h");
    if let Some(parent) = output_file.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).unwrap();
        }
    }
    let nama_header_guard = format!("{}_H", nama_package.to_uppercase().replace("-", "_"));
    let header_komentar = format!("/* Shared Library Header: {} - Auto Generated */", nama_package);
    let mut konfigurasi_builder = cbindgen::Config::from_file("cbindgen.toml").expect("Gagal load config");
    konfigurasi_builder.include_guard = Some(nama_header_guard);
    konfigurasi_builder.header = Some(header_komentar);
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(konfigurasi_builder)
        .generate()
        .expect("Gagal generate_headerC")
        .write_to_file(output_file);
}