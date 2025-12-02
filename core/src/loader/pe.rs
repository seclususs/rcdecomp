use std::fs;
use std::path::Path;
use goblin::pe::PE;
use crate::loader::vmem::{VirtualMemory, IzinAkses};
use crate::loader::LoaderError;
use log::warn;

pub struct PeLoader {
    pub file_path: String,
}

impl PeLoader {
    pub fn new(target_file: &str) -> Self {
        Self {
            file_path: target_file.to_string(),
        }
    }
    pub fn muat_virtual_memory(&self) -> Result<VirtualMemory, LoaderError> {
        let path = Path::new(&self.file_path);
        let buffer = fs::read(path).map_err(|e| LoaderError::IoError(e.to_string()))?;
        let pe = PE::parse(&buffer).map_err(|e| LoaderError::ParseError(e.to_string()))?;
        let is_64 = pe.is_64;
        let arch_str = if is_64 { "x86_64" } else { "x86" };
        let image_base = pe.image_base as u64;
        let entry_rva = pe.entry as u64;
        let absolute_entry = image_base.checked_add(entry_rva).ok_or(LoaderError::OutOfBoundsError)?;
        let mut vmem = VirtualMemory::baru(absolute_entry, arch_str, "pe");
        for section in &pe.sections {
            let start = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;
            let v_addr_offset = section.virtual_address as u64;
            let v_addr = image_base.checked_add(v_addr_offset).ok_or(LoaderError::OutOfBoundsError)?;
            let end_offset = start.checked_add(size).ok_or(LoaderError::OutOfBoundsError)?;
            if end_offset <= buffer.len() {
                let data = buffer[start..end_offset].to_vec();
                let characteristics = section.characteristics;
                let mut perm_val = 0;
                if characteristics & 0x20000000 != 0 { perm_val |= 4; }
                if characteristics & 0x40000000 != 0 { perm_val |= 1; }
                if characteristics & 0x80000000 != 0 { perm_val |= 2; }
                let nama = section.name().unwrap_or("corrupt_section").to_string();
                vmem.tambah_segment(v_addr, data, IzinAkses::from_u32(perm_val), nama);
            } else {
                warn!("Section {} melewati batas buffer file. Diabaikan.", section.name().unwrap_or("?"));
            }
        }
        for export in &pe.exports {
            if let Some(name) = export.name {
                let rva = export.rva as u64;
                if let Some(addr) = image_base.checked_add(rva) {
                    vmem.simbol_global.insert(addr, name.to_string());
                }
            }
        }
        for import in &pe.imports {
            let name_full = format!("{}:{}", import.dll, import.name);
            let rva = import.rva as u64;
            if let Some(addr) = image_base.checked_add(rva) {
                vmem.simbol_global.insert(addr, name_full);
            }
        }
        Ok(vmem)
    }
}