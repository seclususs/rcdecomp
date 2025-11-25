use std::fs;
use std::path::Path;
use goblin::pe::PE;
use crate::loader::memory::{VirtualMemory, IzinAkses};

pub struct PeLoader {
    pub file_path: String,
}

impl PeLoader {
    pub fn new(target_file: &str) -> Self {
        Self {
            file_path: target_file.to_string(),
        }
    }
    pub fn muat_virtual_memory(&self) -> Result<VirtualMemory, String> {
        let path = Path::new(&self.file_path);
        let buffer = fs::read(path).map_err(|e| e.to_string())?;
        let pe = PE::parse(&buffer).map_err(|e| e.to_string())?;
        let is_64 = pe.is_64;
        let arch_str = if is_64 { "x86_64" } else { "x86" };
        let image_base = pe.image_base as u64;
        let absolute_entry = image_base + pe.entry as u64;
        let mut vmem = VirtualMemory::baru(absolute_entry, arch_str);
        for section in &pe.sections {
            let start = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;
            let v_addr = image_base + section.virtual_address as u64;
            if start + size <= buffer.len() {
                let data = buffer[start..start+size].to_vec();
                let characteristics = section.characteristics;
                let mut perm_val = 0;
                if characteristics & 0x20000000 != 0 { perm_val |= 4; }
                if characteristics & 0x40000000 != 0 { perm_val |= 1; }
                if characteristics & 0x80000000 != 0 { perm_val |= 2; }
                let nama = section.name().unwrap_or("unknown").to_string();
                vmem.tambah_segment(v_addr, data, IzinAkses::from_u32(perm_val), nama);
            }
        }
        for export in &pe.exports {
            if let Some(name) = export.name {
                let addr = image_base + export.rva as u64;
                vmem.simbol_global.insert(addr, name.to_string());
            }
        }
        for import in &pe.imports {
            let name = format!("{}:{}", import.dll, import.name);
            let addr = image_base + import.rva as u64; 
            vmem.simbol_global.insert(addr, name);
        }
        Ok(vmem)
    }
}