use std::fs;
use std::path::Path;
use goblin::mach::{Mach, MachO};
use crate::loader::memory::{VirtualMemory, IzinAkses};

pub struct MachoLoader {
    pub file_path: String,
}

impl MachoLoader {
    pub fn new(path: &str) -> Self {
        Self {
            file_path: path.to_string(),
        }
    }
    pub fn muat_virtual_memory(&self) -> Result<VirtualMemory, String> {
        let path = Path::new(&self.file_path);
        let buffer = fs::read(path).map_err(|e| e.to_string())?;
        match Mach::parse(&buffer).map_err(|e| e.to_string())? {
            Mach::Binary(macho) => {
                self.parse_macho_ke_memory(macho, &buffer)
            },
            Mach::Fat(fat) => {
                let mut selected_arch = None;
                for arch_res in fat.iter_arches() {
                    if let Ok(arch) = arch_res {
                        if arch.cputype == goblin::mach::constants::cputype::CPU_TYPE_X86_64 {
                            selected_arch = Some(arch);
                            break;
                        }
                    }
                }
                if selected_arch.is_none() {
                     if let Some(Ok(arch)) = fat.iter_arches().next() {
                         selected_arch = Some(arch);
                     }
                }
                if let Some(arch) = selected_arch {
                    let start = arch.offset as usize;
                    let size = arch.size as usize;
                    if start + size > buffer.len() {
                        return Err("Slice range out of bounds".to_string());
                    }
                    let slice_bytes = &buffer[start..start+size];
                    let macho = MachO::parse(slice_bytes, 0).map_err(|e| e.to_string())?;
                    self.parse_macho_ke_memory(macho, slice_bytes)
                } else {
                    Err("Tidak ditemukan slice arsitektur yang valid".to_string())
                }
            }
        }
    }
    fn parse_macho_ke_memory(&self, macho: MachO, data: &[u8]) -> Result<VirtualMemory, String> {
        let is_64 = macho.is_64;
        let arch_str = if is_64 { "x86_64" } else { "x86" };
        let mut vmem = VirtualMemory::baru(macho.entry, arch_str);
        for segment in &macho.segments {
            for (section, _) in &segment.sections().map_err(|e| e.to_string())? {
                let start = section.offset as usize;
                let size = section.size as usize;
                if start + size <= data.len() {
                    let seg_data = data[start..start+size].to_vec();
                    let mut perm_val = 1;
                    if segment.initprot & 0x2 != 0 { perm_val |= 2; }
                    if segment.initprot & 0x4 != 0 { perm_val |= 4; }
                    let nama = section.name().unwrap_or("unknown").to_string();
                    vmem.tambah_segment(section.addr, seg_data, IzinAkses::from_u32(perm_val), nama);
                }
            }
        }
        for sym in macho.symbols() {
            if let Ok((name, nlist)) = sym {
                if nlist.n_value != 0 && !name.is_empty() {
                    vmem.simbol_global.insert(nlist.n_value, name.to_string());
                }
            }
        }
        Ok(vmem)
    }
}