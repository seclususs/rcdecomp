use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let _package_name = env::var("CARGO_PKG_NAME").unwrap();
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
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(cbindgen::Config::from_file("cbindgen.toml").unwrap())
        .generate()
        .expect("Gagal generate_headerC")
        .write_to_file(output_file);
}