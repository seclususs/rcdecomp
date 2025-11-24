use std::fs;
use std::path::Path;
use std::collections::HashMap;
use goblin::pe::PE;

pub struct PeLoader {
    pub file_path: String,
}

impl PeLoader {
    pub fn new(target_file: &str) -> Self {
        Self {
            file_path: target_file.to_string(),
        }
    }
    pub fn ekstrak_data_pe(&self) -> Result<(Vec<u8>, u64, String, HashMap<u64, String>), String> {
        let path = Path::new(&self.file_path);
        let buffer = fs::read(path).map_err(|e| e.to_string())?;
        let pe = PE::parse(&buffer).map_err(|e| e.to_string())?;
        let is_64 = pe.is_64;
        let arch_str = if is_64 { "x86_64" } else { "x86" };
        let entry_rva = pe.entry;
        let mut code_bytes = Vec::new();
        let mut found_text = false;
        for section in &pe.sections {
            if let Ok(name) = section.name() {
                if name == ".text" || name == "CODE" {
                    let start = section.pointer_to_raw_data as usize;
                    let size = section.size_of_raw_data as usize;
                    let end = start + size;
                    if end <= buffer.len() {
                        code_bytes = buffer[start..end].to_vec();
                        found_text = true;
                    }
                    break;
                }
            }
        }
        if !found_text {
            return Err("Section .text tidak ditemukan dalam PE".to_string());
        }
        let image_base = pe.image_base as u64;
        let absolute_entry = image_base + entry_rva as u64;
        let mut peta_simbol = HashMap::new();
        for export in &pe.exports {
            if let Some(name) = export.name {
                let addr = image_base + export.rva as u64;
                peta_simbol.insert(addr, name.to_string());
            }
        }
        for import in &pe.imports {
            let name = format!("{}:{}", import.dll, import.name);
            let addr = image_base + import.rva as u64; 
            peta_simbol.insert(addr, name);
        }
        Ok((code_bytes, absolute_entry, arch_str.to_string(), peta_simbol))
    }
}