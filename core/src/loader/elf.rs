use std::fs;
use std::path::Path;
use std::collections::HashMap;
use goblin::elf::Elf;
use log::debug;

pub struct ElfParser {
    pub file_path: String,
    pub is_64bit: bool,
}

impl ElfParser {
    pub fn new(path: &str) -> Self {
        Self {
            file_path: path.to_string(),
            is_64bit: false,
        }
    }
    pub fn validasi_magic_number(&self, header_bytes: &[u8]) -> bool {
        if header_bytes.len() < 4 {
            return false;
        }
        header_bytes[0] == 0x7F && 
        header_bytes[1] == b'E' && 
        header_bytes[2] == b'L' && 
        header_bytes[3] == b'F'
    }
    pub fn baca_section_header(&self) {
        debug!("Membaca section header dari {}", self.file_path);
    }
    pub fn hitung_entry_point(&self, buffer: &[u8]) -> Result<u64, String> {
        let elf = Elf::parse(buffer).map_err(|e| e.to_string())?;
        Ok(elf.entry)
    }
    pub fn ekstrak_kode_mentah(&mut self) -> Result<(Vec<u8>, u64, String, HashMap<u64, String>), String> {
        let path = Path::new(&self.file_path);
        let buffer = fs::read(path).map_err(|e| e.to_string())?;
        if !self.validasi_magic_number(&buffer) {
            return Err("Invalid ELF magic bytes".to_string());
        }
        let elf = Elf::parse(&buffer).map_err(|e| e.to_string())?;
        self.is_64bit = elf.is_64;
        let entry_point = elf.entry;
        let arch_str = if elf.is_64 { "x86_64" } else { "x86" };
        let mut symbol_map = HashMap::new();
        for sym in &elf.syms {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() && sym.st_value != 0 {
                    symbol_map.insert(sym.st_value, name.to_string());
                }
            }
        }
        for sym in &elf.dynsyms {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() && sym.st_value != 0 {
                    symbol_map.insert(sym.st_value, name.to_string());
                }
            }
        }
        let mut code_bytes = Vec::new();
        let mut found_text = false;
        for section in elf.section_headers {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                if name == ".text" {
                    let start = section.sh_offset as usize;
                    let end = start + section.sh_size as usize;
                    if end <= buffer.len() {
                        code_bytes = buffer[start..end].to_vec();
                        found_text = true;
                    }
                    break;
                }
            }
        }
        if !found_text {
            return Err("Section .text tidak ditemukan".to_string());
        }
        Ok((code_bytes, entry_point, arch_str.to_string(), symbol_map))
    }
}