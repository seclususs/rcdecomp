use std::collections::{HashMap, BTreeMap};
use std::fs;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use log::{info, debug};
use serde::{Deserialize, Serialize};

use crate::analysis::type_inference::{TypeSystem, SignatureFungsi, TipePrimitif};
use crate::disasm::engine::DisasmEngine;
use crate::disasm::instruction::JenisOperandDisasm;
use crate::loader::memory::VirtualMemory;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalFunctionEntry {
    pub name: String,
    pub hash_signature: Option<String>,
    pub return_type: String,
    pub arg_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalLibraryDb {
    pub library_name: String,
    pub architecture: String,
    pub functions: Vec<ExternalFunctionEntry>,
}

pub struct StdLibManager {
    signature_by_name: HashMap<String, SignatureFungsi>,
    signature_by_hash: HashMap<String, (String, SignatureFungsi)>,
}

impl StdLibManager {
    pub fn new() -> Self {
        let mut manager = Self { 
            signature_by_name: HashMap::new(),
            signature_by_hash: HashMap::new(),
        };
        manager.muat_default_hardcoded();
        manager
    }
    fn muat_default_hardcoded(&mut self) {
        self.tambah_definisi_manual("malloc", "void*", vec!["int"]);
        self.tambah_definisi_manual("free", "void", vec!["void*"]);
        self.tambah_definisi_manual("printf", "int", vec!["char*"]);
        self.tambah_definisi_manual("memcpy", "void*", vec!["void*", "void*", "int"]);
        self.tambah_definisi_manual("strlen", "int", vec!["char*"]);
        self.tambah_definisi_manual("strcpy", "char*", vec!["char*", "char*"]);
    }
    fn tambah_definisi_manual(&mut self, nama: &str, ret: &str, args: Vec<&str>) {
        let sig = SignatureFungsi {
            return_type: self.parse_tipe_string(ret),
            arg_types: args.iter().map(|s| self.parse_tipe_string(s)).collect(),
        };
        self.signature_by_name.insert(nama.to_string(), sig);
    }
    pub fn muat_database_eksternal(&mut self, file_path: &str) -> Result<(), String> {
        let content = fs::read_to_string(file_path).map_err(|e| e.to_string())?;
        let db: ExternalLibraryDb = serde_json::from_str(&content).map_err(|e| e.to_string())?;
        info!("Memuat pustaka eksternal: {} ({})", db.library_name, db.architecture);
        for entry in db.functions {
            let sig = SignatureFungsi {
                return_type: self.parse_tipe_string(&entry.return_type),
                arg_types: entry.arg_types.iter().map(|s| self.parse_tipe_string(s)).collect(),
            };
            self.signature_by_name.insert(entry.name.clone(), sig.clone());
            if let Some(hash) = entry.hash_signature {
                self.signature_by_hash.insert(hash, (entry.name, sig));
            }
        }
        Ok(())
    }
    pub fn terapkan_signature_standar(&self, simbol_global: &BTreeMap<u64, String>, type_sys: &mut TypeSystem) {
        for (addr, nama_raw) in simbol_global {
            let nama_bersih = self.bersihkan_nama_simbol(nama_raw);
            if let Some(sig) = self.signature_by_name.get(&nama_bersih) {
                debug!("Menerapkan signature standar untuk {} di 0x{:x}", nama_bersih, addr);
                type_sys.global_signatures.insert(*addr, sig.clone());
            }
        }
    }
    pub fn identifikasi_fungsi_statis(
        &self, 
        vmem: &mut VirtualMemory, 
        detected_functions: &HashMap<u64, crate::analysis::recursive_descent::FunctionContext>,
        type_sys: &mut TypeSystem,
        arch: &str
    ) {
        let engine = DisasmEngine::buat_engine_baru(arch);
        for (addr, ctx) in detected_functions {
            if !vmem.simbol_global.contains_key(addr) {
                let hash = self.hitung_hash_fungsi(vmem, *addr, ctx.instruction_count, &engine);
                if let Some(hash_str) = hash {
                    if let Some((nama, sig)) = self.signature_by_hash.get(&hash_str) {
                        info!("MATCH: Fungsi statis di 0x{:x} diidentifikasi sebagai '{}'", addr, nama);
                        vmem.simbol_global.insert(*addr, nama.clone());
                        type_sys.global_signatures.insert(*addr, sig.clone());
                    }
                }
            }
        }
    }
    fn hitung_hash_fungsi(&self, vmem: &VirtualMemory, start_addr: u64, limit_instr: usize, engine: &DisasmEngine) -> Option<String> {
        let mut hasher = DefaultHasher::new();
        let mut curr_addr = start_addr;
        let mut count = 0;
        let max_check = limit_instr.min(50); 
        while count < max_check {
            let buffer = vmem.baca_array(curr_addr, 16)?;
            if let Some(instr) = engine.ambil_satu_instruksi(&buffer, curr_addr) {
                instr.mnemonic.hash(&mut hasher);
                for op in &instr.operands_detail {
                    match op {
                        JenisOperandDisasm::Register(reg) => {
                            "REG".hash(&mut hasher);
                            reg.hash(&mut hasher);
                        },
                        JenisOperandDisasm::Immediate(_) => {
                            "IMM".hash(&mut hasher); 
                        },
                        JenisOperandDisasm::Memory { base, index, scale, disp: _ } => {
                            "MEM".hash(&mut hasher);
                            base.hash(&mut hasher);
                            index.hash(&mut hasher);
                            scale.hash(&mut hasher);
                        },
                        JenisOperandDisasm::Unknown => {
                            "UNK".hash(&mut hasher);
                        }
                    }
                }
                curr_addr += instr.hitung_panjang_byte() as u64;
                count += 1;
                if instr.mnemonic == "ret" || instr.mnemonic == "retn" {
                    break;
                }
            } else {
                break;
            }
        }
        if count == 0 { return None; }
        let hash_val = hasher.finish();
        Some(hex::encode(hash_val.to_be_bytes()))
    }
    fn bersihkan_nama_simbol(&self, raw: &str) -> String {
        let tanpa_underscore = raw.strip_prefix("_").unwrap_or(raw);
        let base_name = tanpa_underscore.split('@').next().unwrap_or(tanpa_underscore);
        base_name.to_string()
    }
    fn parse_tipe_string(&self, type_str: &str) -> TipePrimitif {
        match type_str {
            "void" => TipePrimitif::Void,
            "int" | "long" | "int32_t" => TipePrimitif::Integer(4),
            "char" | "int8_t" => TipePrimitif::Integer(1),
            "short" | "int16_t" => TipePrimitif::Integer(2),
            "long long" | "int64_t" => TipePrimitif::Integer(8),
            "float" => TipePrimitif::Float(4),
            "double" => TipePrimitif::Float(8),
            s if s.ends_with('*') => {
                let inner = s.trim_end_matches('*').trim();
                TipePrimitif::Pointer(Box::new(self.parse_tipe_string(inner)))
            },
            s => TipePrimitif::Struct(s.to_string()),
        }
    }
}