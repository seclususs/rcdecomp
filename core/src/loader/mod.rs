pub mod elf;
pub mod pe;
pub mod mach_o;
pub mod dex;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum LoaderError {
    #[error("File tidak ditemukan")]
    NotFound,
    #[error("Format tidak dikenali")]
    InvalidFormat,
    #[error("Gagal parsing: {0}")]
    ParseError(String),
}

pub fn process_muat_file(file_path: &str) -> Result<(Vec<u8>, u64, String), LoaderError> {
    let mut parser = elf::ElfParser::new(file_path);
    match parser.extract_raw_code() {
        Ok(result) => return Ok(result),
        Err(_) => {

        }
    }
    Err(LoaderError::InvalidFormat)
}