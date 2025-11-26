use std::fs;
use std::path::Path;
use goblin::mach::{Mach, MachO};
use crate::loader::vmem::{VirtualMemory, IzinAkses};
use crate::loader::LoaderError;
use log::{info, error};

pub struct MachoLoader {
    pub file_path: String,
}

impl MachoLoader {
    pub fn new(path: &str) -> Self {
        Self {
            file_path: path.to_string(),
        }
    }
    pub fn muat_virtual_memory(&self) -> Result<VirtualMemory, LoaderError> {
        let path = Path::new(&self.file_path);
        let buffer = fs::read(path).map_err(|e| LoaderError::IoError(e.to_string()))?;
        match Mach::parse(&buffer).map_err(|e| LoaderError::ParseError(e.to_string()))? {
            Mach::Binary(macho) => {
                self.parse_macho_ke_memory_aman(macho, &buffer)
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
                    let end = start.checked_add(size).ok_or(LoaderError::OutOfBoundsError)?;
                    if end > buffer.len() {
                        error!("FAT slice bounds check failed");
                        return Err(LoaderError::OutOfBoundsError);
                    }
                    let slice_bytes = &buffer[start..end];
                    let macho = MachO::parse(slice_bytes, 0).map_err(|e| LoaderError::ParseError(e.to_string()))?;
                    self.parse_macho_ke_memory_aman(macho, slice_bytes)
                } else {
                    Err(LoaderError::ParseError("Tidak ada arsitektur valid di Fat Binary".into()))
                }
            }
        }
    }
    fn parse_macho_ke_memory_aman(&self, macho: MachO, data: &[u8]) -> Result<VirtualMemory, LoaderError> {
        let is_64 = macho.is_64;
        let arch_str = if is_64 { "x86_64" } else { "x86" };
        let mut vmem = VirtualMemory::baru(macho.entry, arch_str);
        for segment in &macho.segments {
            for (section, _) in &segment.sections().map_err(|e| LoaderError::ParseError(e.to_string()))? {
                let start = section.offset as usize;
                let size = section.size as usize;
                let end = start.checked_add(size).ok_or(LoaderError::OutOfBoundsError)?;
                if end <= data.len() {
                    let seg_data = data[start..end].to_vec();
                    let mut perm_val = 0;
                    if segment.initprot & 0x1 != 0 { perm_val |= 1; }
                    if segment.initprot & 0x2 != 0 { perm_val |= 2; }
                    if segment.initprot & 0x4 != 0 { perm_val |= 4; }
                    let nama = section.name().unwrap_or("unknown").to_string();
                    if perm_val == 0 && nama == "__text" {
                        perm_val = 5; 
                    }
                    vmem.tambah_segment(section.addr, seg_data, IzinAkses::from_u32(perm_val), nama);
                } else {
                    info!("Section {} diabaikan (OOB)", section.name().unwrap_or("?"));
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