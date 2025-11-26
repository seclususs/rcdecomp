use std::collections::{HashSet, VecDeque, HashMap};
use log::{info, debug};
use rayon::prelude::*;
use crate::loader::vmem::VirtualMemory;
use crate::disasm::engine::DisasmEngine;
use crate::ir::lift::IrLifter;
use crate::ir::types::StatementIr;
use crate::disasm::instruction::InstructionNormalized;
use crate::analysis::recovery::indirect::JumpTableAnalyzer;

pub struct FunctionContext {
    pub entry_point: u64,
    pub ir_code: Vec<StatementIr>,
    pub instruction_count: usize,
    pub end_address: u64, 
}

pub struct RecursiveDescent {
    arch_target: String, 
    lifter: IrLifter,
    visited_global: HashSet<u64>, 
    detected_functions: HashMap<u64, FunctionContext>,
    pub global_jump_targets: HashMap<u64, Vec<u64>>, 
}

impl RecursiveDescent {
    pub fn new(arch: &str) -> Self {
        Self {
            arch_target: arch.to_string(),
            lifter: IrLifter::new(),
            visited_global: HashSet::new(),
            detected_functions: HashMap::new(),
            global_jump_targets: HashMap::new(),
        }
    }
    pub fn lakukan_analisis_full(&mut self, vmem: &VirtualMemory) {
        info!("Memulai Analisis Recursive Descent Fase 1...");
        let mut frontier_functions: Vec<u64> = self.inisialisasi_queue_dari_simbol(vmem);
        if frontier_functions.is_empty() {
            frontier_functions.push(vmem.entry_point);
        }
        let mut visited_addresses: HashSet<u64> = HashSet::new();
        self.jalankan_fase_recursive(vmem, frontier_functions, &mut visited_addresses);
        self.lakukan_analisis_gap_dan_sweep(vmem, &mut visited_addresses);
        info!("Analisis selesai. Ditemukan {} fungsi.", self.detected_functions.len());
    }
    fn jalankan_fase_recursive(&mut self, vmem: &VirtualMemory, mut frontier: Vec<u64>, visited_addresses: &mut HashSet<u64>) {
        let arch_clone = self.arch_target.clone();
        let lifter_clone = self.lifter;
        for &addr in &frontier {
            self.visited_global.insert(addr);
        }
        while !frontier.is_empty() {
            info!("Memproses batch paralel: {} fungsi...", frontier.len());
            let results: Vec<(u64, FunctionContext, Vec<u64>, HashMap<u64, Vec<u64>>, HashSet<u64>)> = frontier
                .par_iter()
                .map(|&func_addr| {
                    let engine_local = DisasmEngine::buat_engine_baru(&arch_clone);   
                    Self::analisa_fungsi_worker(
                        func_addr, 
                        vmem, 
                        &engine_local, 
                        lifter_clone
                    )
                })
                .collect();
            let mut next_frontier = HashSet::new();
            for (addr, ctx, new_targets, jump_tables, covered_addrs) in results {
                self.detected_functions.insert(addr, ctx);
                self.global_jump_targets.extend(jump_tables);
                visited_addresses.extend(covered_addrs);
                for target in new_targets {
                    if !self.visited_global.contains(&target) {
                        self.visited_global.insert(target);
                        next_frontier.insert(target);
                    }
                }
            }
            frontier = next_frontier.into_iter().collect();
        }
    }
    fn lakukan_analisis_gap_dan_sweep(&mut self, vmem: &VirtualMemory, visited_addresses: &mut HashSet<u64>) {
        info!("Memulai Gap Analysis untuk menemukan fungsi tersembunyi...");
        let exec_regions = vmem.ambil_executable_regions();
        let mut detected_gap_funcs = Vec::new();
        let arch_clone = self.arch_target.clone();
        let align = if self.arch_target.contains("64") { 16 } else { 4 };
        for (start_seg, data) in exec_regions {
            let end_seg = start_seg + data.len() as u64;
            let mut curr = start_seg;
            while curr < end_seg {
                if visited_addresses.contains(&curr) {
                    curr += 1;
                    while curr % align != 0 { curr += 1; }
                    continue;
                }
                if let Some(bytes) = vmem.baca_array(curr, 4) {
                    if bytes.iter().all(|&b| b == 0x00) || bytes.iter().all(|&b| b == 0xCC) {
                        curr += align;
                        continue;
                    }
                    let engine = DisasmEngine::buat_engine_baru(&arch_clone);
                    if Self::cek_heuristic_gap_entry(vmem, curr, &engine) {
                        info!("Fungsi ditemukan via Gap Analysis di 0x{:x}", curr);
                        detected_gap_funcs.push(curr);
                        let (_, _, _, _, covered) = Self::analisa_fungsi_worker(curr, vmem, &engine, self.lifter);
                        visited_addresses.extend(covered);
                        curr += 16; 
                    } else {
                        curr += align;
                    }
                } else {
                    curr += align;
                }
            }
        }
        if !detected_gap_funcs.is_empty() {
            info!("Memproses {} fungsi tambahan dari Gap Analysis...", detected_gap_funcs.len());
            self.jalankan_fase_recursive(vmem, detected_gap_funcs, visited_addresses);
        }
    }
    fn cek_heuristic_gap_entry(vmem: &VirtualMemory, addr: u64, engine: &DisasmEngine) -> bool {
        let bytes = match vmem.baca_array(addr, 16) {
            Some(b) => b,
            None => return false,
        };
        let mut curr_offset = 0;
        for _ in 0..3 {
            if let Some(instr) = engine.ambil_satu_instruksi(&bytes[curr_offset..], addr + curr_offset as u64) {
                if instr.mnemonic == "INVALID" { return false; }
                let mnem = instr.mnemonic.as_str();
                let op = instr.op_str.as_str();
                if mnem == "push" && op == "rbp" { return true; }
                if mnem == "sub" && op.starts_with("rsp") { return true; }
                if mnem == "endbr64" { return true; }
                if mnem == "stp" && (op.contains("x29") || op.contains("fp")) { return true; }
                if mnem == "pacibsp" { return true; }
                curr_offset += instr.hitung_panjang_byte();
            } else {
                break;
            }
        }
        false
    }
    fn inisialisasi_queue_dari_simbol(&self, vmem: &VirtualMemory) -> Vec<u64> {
        let mut queue = Vec::new();
        for &addr in vmem.simbol_global.keys() {
            if self.is_executable_address(vmem, addr) {
                queue.push(addr);
            }
        }
        queue
    }
    fn analisa_fungsi_worker(
        start_addr: u64, 
        vmem: &VirtualMemory, 
        engine: &DisasmEngine,
        lifter: IrLifter
    ) -> (u64, FunctionContext, Vec<u64>, HashMap<u64, Vec<u64>>, HashSet<u64>) {
        let mut instructions_ir = Vec::new();
        let mut worklist_block = VecDeque::new();
        let mut visited_local = HashSet::new();
        let mut found_call_targets = Vec::new();
        let mut local_jump_targets = HashMap::new();
        let mut max_addr = start_addr;
        worklist_block.push_back(start_addr);
        while let Some(curr_addr) = worklist_block.pop_front() {
            if visited_local.contains(&curr_addr) {
                continue;
            }
            let buffer_opt = vmem.baca_array(curr_addr, 16); 
            if buffer_opt.is_none() { continue; }
            let buffer = buffer_opt.unwrap();
            if let Some(instr) = engine.ambil_satu_instruksi(&buffer, curr_addr) {
                visited_local.insert(curr_addr);
                if curr_addr > max_addr { max_addr = curr_addr; }
                let next_addr = curr_addr + instr.hitung_panjang_byte() as u64;
                let (is_terminator, new_targets, jump_table_res) = Self::analisa_control_flow_lokal(
                    &instr, 
                    vmem,
                    &mut found_call_targets
                );
                if let Some(targets) = jump_table_res {
                    local_jump_targets.insert(instr.address, targets.clone());
                    for t in targets {
                        worklist_block.push_back(t);
                    }
                }
                for t in new_targets {
                    worklist_block.push_back(t);
                }
                let micro_ops = lifter.konversi_instruksi_ke_microcode(&instr);
                instructions_ir.extend(micro_ops);
                if !is_terminator {
                    if vmem.simbol_global.contains_key(&next_addr) {
                         debug!("Control flow stop: fallthrough ke simbol global di 0x{:x}", next_addr);
                    } else {
                        worklist_block.push_back(next_addr);
                    }
                }
            }
        }
        instructions_ir.sort_by_key(|k| k.address_asal);
        let context = FunctionContext {
            entry_point: start_addr,
            ir_code: instructions_ir.clone(),
            instruction_count: instructions_ir.len(),
            end_address: max_addr,
        };
        (start_addr, context, found_call_targets, local_jump_targets, visited_local)
    }
    fn analisa_control_flow_lokal(
        instr: &InstructionNormalized, 
        vmem: &VirtualMemory,
        global_targets_collector: &mut Vec<u64>
    ) -> (bool, Vec<u64>, Option<Vec<u64>>) {
        let mnemonic = instr.mnemonic.as_str();
        let mut local_targets = Vec::new();
        let mut jump_table_targets = None;
        let mut is_terminator = false;
        match mnemonic {
            "call" | "bl" => {
                if let Some(target) = Self::ekstrak_target_address(instr) {
                    global_targets_collector.push(target);
                }
            },
            "jmp" | "b" => {
                if let Some(target) = Self::ekstrak_target_address(instr) {
                    local_targets.push(target);
                } else {
                    if let Some(targets) = JumpTableAnalyzer::analisis_jump_table(instr, vmem) {
                        jump_table_targets = Some(targets);
                    }
                }
                is_terminator = true;
            },
            "ret" | "retn" => {
                is_terminator = true;
            },
            _ => {
                if mnemonic.starts_with('j') || mnemonic.starts_with("b.") || mnemonic.starts_with("cbz") || mnemonic.starts_with("cbnz") {
                     if let Some(target) = Self::ekstrak_target_address(instr) {
                        local_targets.push(target);
                    }
                }
            }
        }
        (is_terminator, local_targets, jump_table_targets)
    }
    fn ekstrak_target_address(instr: &InstructionNormalized) -> Option<u64> {
        if let Some(op) = instr.operands_detail.first() {
            if let crate::disasm::instruction::JenisOperandDisasm::Immediate(val) = op {
                return Some(*val as u64);
            }
        }
        None
    }
    fn is_executable_address(&self, vmem: &VirtualMemory, addr: u64) -> bool {
        for seg in &vmem.segments {
            if addr >= seg.start_addr && addr < seg.end_addr {
                match seg.permissions {
                    crate::loader::vmem::IzinAkses::Execute | 
                    crate::loader::vmem::IzinAkses::ReadExecute | 
                    crate::loader::vmem::IzinAkses::Full => return true,
                    _ => {}
                }
            }
        }
        false
    }
    pub fn ambil_hasil_fungsi(&self) -> &HashMap<u64, FunctionContext> {
        &self.detected_functions
    }
}