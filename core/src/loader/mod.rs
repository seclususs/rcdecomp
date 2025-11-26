pub mod elf;
pub mod pe;
pub mod mach_o;
pub mod dex;
pub mod vmem;

use thiserror::Error;
use std::fs::File;
use std::io::Read;
use self::vmem::VirtualMemory;

#[derive(Error, Debug)]
pub enum LoaderError {
    #[error("File target tidak ditemukan di path")]
    NotFound,
    #[error("Format binary tidak dikenali atau magic bytes mismatch")]
    InvalidFormat,
    #[error("Gagal parsing struktur internal: {0}")]
    ParseError(String),
    #[error("Terjadi IO Error saat membaca: {0}")]
    IoError(String),
    #[error("Terdeteksi malformed binary (buffer overflow/bounds check violation)")]
    OutOfBoundsError,
}

pub fn proses_muat_file(file_path: &str) -> Result<VirtualMemory, LoaderError> {
    let mut file = File::open(file_path).map_err(|_| LoaderError::NotFound)?;
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return Err(LoaderError::InvalidFormat);
    }
    if magic[0] == 0x7F && magic[1] == b'E' && magic[2] == b'L' && magic[3] == b'F' {
        let mut parser = elf::ElfParser::new(file_path);
        parser.muat_virtual_memory()
    } else if magic[0] == 0x4D && magic[1] == 0x5A {
        let parser = pe::PeLoader::new(file_path);
        parser.muat_virtual_memory()
    } else if (magic[0] == 0xFE && magic[1] == 0xED && magic[2] == 0xFA) ||
              (magic[0] == 0xCF && magic[1] == 0xFA && magic[2] == 0xED && magic[3] == 0xFE) ||
              (magic[0] == 0xCA && magic[1] == 0xFE && magic[2] == 0xBA && magic[3] == 0xBE) {
         let parser = mach_o::MachoLoader::new(file_path);
         parser.muat_virtual_memory()
    } else if magic[0] == 0x64 && magic[1] == 0x65 && magic[2] == 0x78 && magic[3] == 0x0A {
        let mut parser = dex::DexLoader::new(file_path);
        parser.muat_virtual_memory()
    } else {
        Err(LoaderError::InvalidFormat)
    }
}