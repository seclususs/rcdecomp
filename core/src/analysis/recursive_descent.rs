use std::collections::{HashSet, VecDeque, HashMap};
use log::{info, debug};
use crate::loader::memory::VirtualMemory;
use crate::disasm::engine::DisasmEngine;
use crate::ir::lifter::IrLifter;
use crate::ir::types::StatementIr;
use crate::disasm::instruction::InstructionNormalized;
use crate::analysis::indirect_jump::JumpTableAnalyzer;

pub struct FunctionContext {
    pub entry_point: u64,
    pub ir_code: Vec<StatementIr>,
    pub instruction_count: usize,
}

pub struct RecursiveDescent {
    engine: DisasmEngine,
    lifter: IrLifter,
    visited_global: HashSet<u64>, 
    functions_queue: VecDeque<u64>, 
    detected_functions: HashMap<u64, FunctionContext>,
    pub global_jump_targets: HashMap<u64, Vec<u64>>, 
}

impl RecursiveDescent {
    pub fn new(arch: &str) -> Self {
        Self {
            engine: DisasmEngine::buat_engine_baru(arch),
            lifter: IrLifter::new(),
            visited_global: HashSet::new(),
            functions_queue: VecDeque::new(),
            detected_functions: HashMap::new(),
            global_jump_targets: HashMap::new(),
        }
    }
    pub fn lakukan_analisis_full(&mut self, vmem: &VirtualMemory) {
        self.tambah_antrean_fungsi(vmem.entry_point);
        while let Some(func_addr) = self.functions_queue.pop_front() {
            if self.detected_functions.contains_key(&func_addr) {
                continue;
            }
            info!("Menganalisis Fungsi di 0x{:x}", func_addr);
            let result = self.analisa_fungsi_tunggal(vmem, func_addr);
            self.detected_functions.insert(func_addr, result);
        }
    }
    fn tambah_antrean_fungsi(&mut self, addr: u64) {
        if !self.visited_global.contains(&addr) {
            self.functions_queue.push_back(addr);
        }
    }
    fn analisa_fungsi_tunggal(&mut self, vmem: &VirtualMemory, start_addr: u64) -> FunctionContext {
        let mut instructions_ir = Vec::new();
        let mut worklist_block = VecDeque::new();
        let mut visited_local = HashSet::new();
        worklist_block.push_back(start_addr);
        while let Some(curr_addr) = worklist_block.pop_front() {
            if visited_local.contains(&curr_addr) || self.visited_global.contains(&curr_addr) {
                continue;
            }
            let buffer_opt = vmem.baca_array(curr_addr, 16); 
            if buffer_opt.is_none() {
                continue;
            }
            let buffer = buffer_opt.unwrap();
            if let Some(instr) = self.engine.ambil_satu_instruksi(&buffer, curr_addr) {
                visited_local.insert(curr_addr);
                self.visited_global.insert(curr_addr);
                let next_addr = curr_addr + instr.hitung_panjang_byte() as u64;
                let is_terminator = self.analisa_control_flow(&instr, next_addr, &mut worklist_block, vmem);
                let micro_ops = self.lifter.konversi_instruksi_ke_microcode(&instr);
                instructions_ir.extend(micro_ops);
                if !is_terminator {
                    if self.cek_function_prologue(vmem, next_addr) {
                        debug!("Function prologue terdeteksi di 0x{:x}", next_addr);
                        self.tambah_antrean_fungsi(next_addr);
                    } else {
                        worklist_block.push_back(next_addr);
                    }
                }
            }
        }
        instructions_ir.sort_by_key(|k| k.address_asal);
        FunctionContext {
            entry_point: start_addr,
            ir_code: instructions_ir.clone(),
            instruction_count: instructions_ir.len(),
        }
    }
    fn analisa_control_flow(
        &mut self, 
        instr: &InstructionNormalized, 
        _next_addr: u64,
        worklist: &mut VecDeque<u64>,
        vmem: &VirtualMemory
    ) -> bool {
        let mnemonic = instr.mnemonic.as_str();
        match mnemonic {
            "call" | "bl" => {
                if let Some(target) = self.ekstrak_target_address(instr) {
                    self.tambah_antrean_fungsi(target);
                }
                false 
            },
            "jmp" | "b" => {
                if let Some(target) = self.ekstrak_target_address(instr) {
                    worklist.push_back(target);
                } else {
                    if let Some(targets) = JumpTableAnalyzer::analisis_jump_table(instr, vmem) {
                        info!("Resolved Indirect Jump di 0x{:x} ke {} target", instr.address, targets.len());
                        self.global_jump_targets.insert(instr.address, targets.clone());
                        for t in targets {
                            worklist.push_back(t);
                        }
                    } else {
                        debug!("Unresolved indirect jump di 0x{:x}", instr.address);
                    }
                }
                true
            },
            "ret" | "retn" => true,
            _ => {
                if mnemonic.starts_with('j') || mnemonic.starts_with("b.") || mnemonic.starts_with("cbz") {
                     if let Some(target) = self.ekstrak_target_address(instr) {
                        worklist.push_back(target);
                    }
                    false
                } else {
                    false
                }
            }
        }
    }
    fn ekstrak_target_address(&self, instr: &InstructionNormalized) -> Option<u64> {
        if let Some(op) = instr.operands_detail.first() {
            if let crate::disasm::instruction::JenisOperandDisasm::Immediate(val) = op {
                return Some(*val as u64);
            }
        }
        None
    }
    fn cek_function_prologue(&self, vmem: &VirtualMemory, addr: u64) -> bool {
        let arch = &self.engine.arch;
        if let Some(bytes) = vmem.baca_array(addr, 4) {
            if arch == "x86_64" {
                if bytes[0] == 0x55 && bytes[1] == 0x48 && bytes[2] == 0x89 && bytes[3] == 0xE5 {
                    return true;
                }
            } else if arch == "aarch64" || arch == "arm64" {
                 if let Some(instr) = self.engine.ambil_satu_instruksi(&bytes, addr) {
                     if instr.mnemonic == "stp" && instr.op_str.contains("x29") && instr.op_str.contains("x30") {
                         return true;
                     }
                 }
            }
        }
        false
    }
    pub fn ambil_hasil_fungsi(&self) -> &HashMap<u64, FunctionContext> {
        &self.detected_functions
    }
}