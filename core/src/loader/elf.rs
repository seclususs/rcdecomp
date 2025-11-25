use std::fs;
use std::path::Path;
use goblin::elf::{Elf, section_header};
use crate::loader::memory::{VirtualMemory, IzinAkses};

pub struct ElfParser {
    pub file_path: String,
}

impl ElfParser {
    pub fn new(path: &str) -> Self {
        Self {
            file_path: path.to_string(),
        }
    }
    pub fn muat_virtual_memory(&mut self) -> Result<VirtualMemory, String> {
        let path = Path::new(&self.file_path);
        let buffer = fs::read(path).map_err(|e| e.to_string())?;
        let elf = Elf::parse(&buffer).map_err(|e| e.to_string())?;
        let arch_str = if elf.is_64 { "x86_64" } else { "x86" };
        let mut vmem = VirtualMemory::baru(elf.entry, arch_str);
        for section in &elf.section_headers {
            if section.sh_flags & (section_header::SHF_ALLOC as u64) != 0 {
                let start = section.sh_offset as usize;
                let size = section.sh_size as usize;
                if start + size <= buffer.len() {
                    let data = buffer[start..start+size].to_vec();
                    let mut perm_val = 0;
                    if section.sh_flags & (section_header::SHF_WRITE as u64) != 0 { perm_val |= 2; }
                    if section.sh_flags & (section_header::SHF_EXECINSTR as u64) != 0 { perm_val |= 4; }
                    perm_val |= 1;
                    let nama = if let Some(n) = elf.shdr_strtab.get_at(section.sh_name) {
                        n.to_string()
                    } else {
                        "unknown".to_string()
                    };
                    vmem.tambah_segment(section.sh_addr, data, IzinAkses::from_u32(perm_val), nama);
                }
            }
        }
        for sym in &elf.syms {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() && sym.st_value != 0 {
                    vmem.simbol_global.insert(sym.st_value, name.to_string());
                }
            }
        }
        for sym in &elf.dynsyms {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() && sym.st_value != 0 {
                    vmem.simbol_global.insert(sym.st_value, name.to_string());
                }
            }
        }
        Ok(vmem)
    }
}