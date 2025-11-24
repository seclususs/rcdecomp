pub mod elf;
pub mod pe;
pub mod mach_o;
pub mod dex;

use thiserror::Error;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

#[derive(Error, Debug)]
pub enum LoaderError {
    #[error("File tidak ditemukan")]
    NotFound,
    #[error("Format tidak dikenali")]
    InvalidFormat,
    #[error("Gagal parsing: {0}")]
    ParseError(String),
    #[error("IO Error: {0}")]
    IoError(String),
}

pub fn proses_muat_file(file_path: &str) -> Result<(Vec<u8>, u64, String, HashMap<u64, String>), LoaderError> {
    let mut file = File::open(file_path).map_err(|_| LoaderError::NotFound)?;
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return Err(LoaderError::InvalidFormat);
    }
    if magic[0] == 0x7F && magic[1] == b'E' && magic[2] == b'L' && magic[3] == b'F' {
        let mut parser = elf::ElfParser::new(file_path);
        parser.ekstrak_kode_mentah().map_err(LoaderError::ParseError)
    } else if magic[0] == 0x4D && magic[1] == 0x5A {
        let parser = pe::PeLoader::new(file_path);
        parser.ekstrak_data_pe().map_err(LoaderError::ParseError)
    } else if magic[0] == 0xFE && magic[1] == 0xED && magic[2] == 0xFA {
        let parser = mach_o::MachoLoader::new(file_path);
        parser.ekstrak_data_macho().map_err(LoaderError::ParseError)
    } else if magic[1] == 0xFA && magic[2] == 0xED && magic[3] == 0xFE {
        let parser = mach_o::MachoLoader::new(file_path);
        parser.ekstrak_data_macho().map_err(LoaderError::ParseError)
    } else {
        if magic[0] == 0xCA && magic[1] == 0xFE && magic[2] == 0xBA && magic[3] == 0xBE {
             let parser = mach_o::MachoLoader::new(file_path);
             return parser.ekstrak_data_macho().map_err(LoaderError::ParseError);
        }
        Err(LoaderError::InvalidFormat)
    }
}