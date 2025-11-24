use std::fs;
use std::path::Path;
use std::collections::HashMap;
use goblin::mach::{Mach, MachO};

pub struct MachoLoader {
    pub file_path: String,
}

impl MachoLoader {
    pub fn new(path: &str) -> Self {
        Self {
            file_path: path.to_string(),
        }
    }
    pub fn ekstrak_data_macho(&self) -> Result<(Vec<u8>, u64, String, HashMap<u64, String>), String> {
        let path = Path::new(&self.file_path);
        let buffer = fs::read(path).map_err(|e| e.to_string())?;
        match Mach::parse(&buffer).map_err(|e| e.to_string())? {
            Mach::Binary(macho) => {
                self.parse_macho_tunggal(macho, &buffer)
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
                    self.parse_macho_tunggal(macho, slice_bytes)
                } else {
                    Err("Tidak ditemukan slice arsitektur yang valid dalam Fat Binary".to_string())
                }
            }
        }
    }
    fn parse_macho_tunggal(&self, macho: MachO, data: &[u8]) -> Result<(Vec<u8>, u64, String, HashMap<u64, String>), String> {
        let is_64 = macho.is_64;
        let arch_str = if is_64 { "x86_64" } else { "x86" };
        let entry_point = macho.entry;
        let mut code_bytes = Vec::new();
        let mut found_text = false;
        for segment in &macho.segments {
            if let Ok(seg_name) = segment.name() {
                if seg_name == "__TEXT" {
                    for (section, _) in &segment.sections().map_err(|e| e.to_string())? {
                        if let Ok(sec_name) = section.name() {
                            if sec_name == "__text" {
                                let start = section.offset as usize;
                                let size = section.size as usize;
                                if start + size <= data.len() {
                                    code_bytes = data[start..start+size].to_vec();
                                    found_text = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        if !found_text {
            return Err("Section __text tidak ditemukan dalam Mach-O".to_string());
        }
        let mut peta_simbol = HashMap::new();
        for sym in macho.symbols() {
            if let Ok((name, nlist)) = sym {
                if nlist.n_value != 0 && !name.is_empty() {
                        peta_simbol.insert(nlist.n_value, name.to_string());
                }
            }
        }
        Ok((code_bytes, entry_point, arch_str.to_string(), peta_simbol))
    }
}