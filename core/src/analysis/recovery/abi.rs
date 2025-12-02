use std::collections::{HashMap, HashSet};
use crate::analysis::graph::cfg::ControlFlowGraph;
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};
use crate::arch::Architecture;
use log::info;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TipeAbi {
    SystemV,
    MicrosoftX64,
    Arm64Aapcs,
    Unknown
}

#[derive(Debug, Clone)]
pub struct ProfilAbi {
    pub tipe: TipeAbi,
    pub register_integer: Vec<String>,
    pub register_float: Vec<String>,
    pub shadow_space: i64,
    pub volatile_registers: HashSet<String>,
}

impl ProfilAbi {
    pub fn buat_profil_otomatis(arch: &dyn Architecture, format_biner: &str) -> Self {
        let arch_stack_ptr = arch.dapatkan_stack_pointer();
        if arch_stack_ptr == "rsp" {
            if format_biner == "pe" {
                info!("Mengaktifkan Profil ABI: Microsoft x64 (Windows)");
                Self {
                    tipe: TipeAbi::MicrosoftX64,
                    register_integer: vec![
                        "rcx".to_string(), "rdx".to_string(), 
                        "r8".to_string(), "r9".to_string()
                    ],
                    register_float: vec![
                        "xmm0".to_string(), "xmm1".to_string(), 
                        "xmm2".to_string(), "xmm3".to_string()
                    ],
                    shadow_space: 32,
                    volatile_registers: HashSet::from_iter(vec![
                        "rax".to_string(), "rcx".to_string(), "rdx".to_string(), 
                        "r8".to_string(), "r9".to_string(), "r10".to_string(), "r11".to_string(),
                        "xmm0".to_string(), "xmm1".to_string(), "xmm2".to_string(), "xmm3".to_string(), 
                        "xmm4".to_string(), "xmm5".to_string()
                    ]),
                }
            } else {
                info!("Mengaktifkan Profil ABI: System V AMD64 (Unix-like)");
                Self {
                    tipe: TipeAbi::SystemV,
                    register_integer: vec![
                        "rdi".to_string(), "rsi".to_string(), "rdx".to_string(), 
                        "rcx".to_string(), "r8".to_string(), "r9".to_string()
                    ],
                    register_float: vec![
                        "xmm0".to_string(), "xmm1".to_string(), "xmm2".to_string(), 
                        "xmm3".to_string(), "xmm4".to_string(), "xmm5".to_string(), 
                        "xmm6".to_string(), "xmm7".to_string()
                    ],
                    shadow_space: 0,
                    volatile_registers: HashSet::from_iter(vec![
                        "rax".to_string(), "rdi".to_string(), "rsi".to_string(), 
                        "rdx".to_string(), "rcx".to_string(), "r8".to_string(), 
                        "r9".to_string(), "r10".to_string(), "r11".to_string()
                    ]),
                }
            }
        } else if arch_stack_ptr == "sp" {
            info!("Mengaktifkan Profil ABI: AAPCS64 (ARM64)");
            Self {
                tipe: TipeAbi::Arm64Aapcs,
                register_integer: vec![
                    "x0".to_string(), "x1".to_string(), "x2".to_string(), 
                    "x3".to_string(), "x4".to_string(), "x5".to_string(),
                    "x6".to_string(), "x7".to_string()
                ],
                register_float: vec![
                    "v0".to_string(), "v1".to_string(), "v2".to_string(), 
                    "v3".to_string(), "v4".to_string(), "v5".to_string(),
                    "v6".to_string(), "v7".to_string()
                ],
                shadow_space: 0,
                volatile_registers: HashSet::from_iter(vec![
                    "x0".to_string(), "x1".to_string(), "x2".to_string(), "x3".to_string(),
                    "x4".to_string(), "x5".to_string(), "x6".to_string(), "x7".to_string(),
                    "x8".to_string(), "x9".to_string(), "x10".to_string(), "x11".to_string(),
                    "x12".to_string(), "x13".to_string(), "x14".to_string(), "x15".to_string(),
                    "x16".to_string(), "x17".to_string(), "x18".to_string()
                ]),
            }
        } else {
            info!("Arsitektur tidak dikenal, menggunakan fallback ABI.");
            Self {
                tipe: TipeAbi::Unknown,
                register_integer: Vec::new(),
                register_float: Vec::new(),
                shadow_space: 0,
                volatile_registers: HashSet::new(),
            }
        }
    }
}

pub struct CallingConventionAnalyzer {
    pub profil: ProfilAbi,
}

impl CallingConventionAnalyzer {
    pub fn new(arch: &dyn Architecture, format_biner: &str) -> Self {
        Self {
            profil: ProfilAbi::buat_profil_otomatis(arch, format_biner),
        }
    }
    pub fn terapkan_analisa_call_args(&self, cfg: &mut ControlFlowGraph) {
        let mut global_reg_versions: HashMap<String, usize> = HashMap::new();
        for reg in self.profil.register_integer.iter().chain(self.profil.register_float.iter()) {
            global_reg_versions.insert(reg.clone(), 0);
        }
        let mut block_ids: Vec<u64> = cfg.blocks.keys().cloned().collect();
        block_ids.sort();
        for id in block_ids {
            if let Some(block) = cfg.blocks.get_mut(&id) {
                for stmt in &mut block.instruksi_list {
                    self.update_reg_tracker(stmt, &mut global_reg_versions);
                    if stmt.operation_code == OperasiIr::Call {
                        let mut detected_args = Vec::new();
                        for abi_reg in &self.profil.register_integer {
                            let ver = *global_reg_versions.get(abi_reg).unwrap_or(&0);
                            detected_args.push(TipeOperand::SsaVariable(abi_reg.clone(), ver));
                        }
                        stmt.operand_tambahan = detected_args;
                    }
                }
            }
        }
    }
    fn update_reg_tracker(&self, stmt: &StatementIr, tracker: &mut HashMap<String, usize>) {
        if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_satu {
            if tracker.contains_key(name) {
                tracker.insert(name.clone(), *ver);
            }
        }
        if let TipeOperand::SsaVariable(name, ver) = &stmt.operand_dua {
            if tracker.contains_key(name) {
                tracker.insert(name.clone(), *ver);
            }
        }
    }
    pub fn deteksi_entry_params(&self, cfg: &ControlFlowGraph) -> Vec<String> {
        let mut params = Vec::new();
        let entry_id = cfg.entry_point;
        if let Some(block) = cfg.blocks.get(&entry_id) {
            let mut written = HashSet::new();
            let mut read_params = HashSet::new();
            for stmt in &block.instruksi_list {
                self.cek_usage_sebagai_param(&stmt.operand_dua, &written, &mut read_params);
                match stmt.operation_code {
                    OperasiIr::Cmp | OperasiIr::Test => {
                        self.cek_usage_sebagai_param(&stmt.operand_satu, &written, &mut read_params);
                    },
                    _ => {}
                }
                match stmt.operation_code {
                    OperasiIr::Mov | OperasiIr::Add | OperasiIr::Sub | OperasiIr::Imul |
                    OperasiIr::And | OperasiIr::Or | OperasiIr::Xor | OperasiIr::Lea => {
                        if let TipeOperand::SsaVariable(name, _) = &stmt.operand_satu {
                            written.insert(name.clone());
                        } else if let TipeOperand::Register(name) = &stmt.operand_satu {
                            written.insert(name.clone());
                        }
                    },
                    _ => {}
                }
            }
            if self.profil.tipe == TipeAbi::MicrosoftX64 {
                for i in 0..4 {
                    let int_reg = self.profil.register_integer.get(i);
                    let float_reg = self.profil.register_float.get(i);
                    let mut slot_used = false;
                    if let Some(r) = int_reg {
                        if read_params.contains(r) {
                            params.push(format!("{}_0", r));
                            slot_used = true;
                        }
                    }
                    if !slot_used {
                        if let Some(f) = float_reg {
                            if read_params.contains(f) {
                                params.push(format!("{}_0", f));
                            }
                        }
                    }
                }
            } else {
                for reg in &self.profil.register_integer {
                    if read_params.contains(reg) {
                        params.push(format!("{}_0", reg));
                    }
                }
                for reg in &self.profil.register_float {
                    if read_params.contains(reg) {
                        params.push(format!("{}_0", reg));
                    }
                }
            }
        }
        params
    }
    fn cek_usage_sebagai_param(&self, op: &TipeOperand, written: &HashSet<String>, read_out: &mut HashSet<String>) {
        match op {
            TipeOperand::SsaVariable(name, _) | TipeOperand::Register(name) => {
                let is_abi_reg = self.profil.register_integer.contains(name) || self.profil.register_float.contains(name);
                if is_abi_reg && !written.contains(name) {
                    read_out.insert(name.clone());
                }
            },
            TipeOperand::Expression { operand_kiri, operand_kanan, .. } => {
                self.cek_usage_sebagai_param(operand_kiri, written, read_out);
                self.cek_usage_sebagai_param(operand_kanan, written, read_out);
            },
            _ => {}
        }
    }
}