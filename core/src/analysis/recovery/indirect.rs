use crate::disasm::instruction::{InstructionNormalized, JenisOperandDisasm};
use crate::loader::vmem::{VirtualMemory, IzinAkses};
use log::{info, warn};

pub struct JumpTableAnalyzer;

impl JumpTableAnalyzer {
    pub fn analisa_jump_table_slicing(
        instr: &InstructionNormalized,
        riwayat_instruksi: &[InstructionNormalized],
        vmem: &VirtualMemory
    ) -> Option<Vec<u64>> {
        if instr.mnemonic != "jmp" && instr.mnemonic != "br" && instr.mnemonic != "b" {
            return None;
        }
        let operand = instr.operands_detail.first()?;
        match operand {
            JenisOperandDisasm::Memory { base, index, scale, disp } => {
                let mut table_base_addr = 0u64;
                let index_reg_opt = index.clone();
                if let Some(base_reg) = base {
                    if let Some(resolved_addr) = Self::lacak_sumber_register(base_reg, riwayat_instruksi, instr.address) {
                        table_base_addr = resolved_addr.wrapping_add(*disp as u64);
                    } else if *disp != 0 && base_reg == "rip" {
                         table_base_addr = instr.address.wrapping_add(instr.hitung_panjang_byte() as u64).wrapping_add(*disp as u64);
                    } else {
                        if index.is_some() && *disp > 0x1000 {
                             table_base_addr = *disp as u64;
                        } else {
                            return None;
                        }
                    }
                } else if *disp != 0 {
                    table_base_addr = *disp as u64;
                }
                if index_reg_opt.is_none() {
                    return None;
                }
                let index_reg = index_reg_opt.unwrap();
                let table_size_limit = if let Some(limit) = Self::temukan_batas_switch(&index_reg, riwayat_instruksi) {
                    limit as usize
                } else {
                    warn!("Bounds check tidak ditemukan untuk jump table di 0x{:x}, menggunakan limit heuristik.", instr.address);
                    256 
                };
                if table_base_addr != 0 {
                    info!("Jump Table Candidates: Base=0x{:x}, Size={}, IndexReg={}", table_base_addr, table_size_limit, index_reg);
                    return Self::baca_entry_tabel(vmem, table_base_addr, *scale, table_size_limit);
                }
            }
            _ => {}
        }
        None
    }
    fn lacak_sumber_register(
        target_reg: &str, 
        history: &[InstructionNormalized], 
        current_addr: u64
    ) -> Option<u64> {
        for instr in history.iter().rev() {
            if current_addr - instr.address > 0x100 { 
                break; 
            }
            match instr.mnemonic.as_str() {
                "lea" => {
                    if let Some(dest) = instr.operands_detail.get(0) {
                        if let JenisOperandDisasm::Register(r) = dest {
                            if r == target_reg {
                                if let Some(src) = instr.operands_detail.get(1) {
                                    if let JenisOperandDisasm::Memory { base, disp, .. } = src {
                                        if let Some(b) = base {
                                            if b == "rip" {
                                                let next_ip = instr.address + instr.hitung_panjang_byte() as u64;
                                                return Some(next_ip.wrapping_add(*disp as u64));
                                            }
                                        }
                                        if base.is_none() {
                                            return Some(*disp as u64);
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "mov" => {
                    if let Some(dest) = instr.operands_detail.get(0) {
                        if let JenisOperandDisasm::Register(r) = dest {
                            if r == target_reg {
                                if let Some(src) = instr.operands_detail.get(1) {
                                    if let JenisOperandDisasm::Immediate(val) = src {
                                        return Some(*val as u64);
                                    }
                                }
                            }
                        }
                    }
                },
                "adr" | "adrp" => {
                    if let Some(dest) = instr.operands_detail.get(0) {
                        if let JenisOperandDisasm::Register(r) = dest {
                            if r == target_reg {
                                if let Some(src) = instr.operands_detail.get(1) {
                                    if let JenisOperandDisasm::Immediate(val) = src {
                                        let _page_base = instr.address & !0xFFF;
                                        return Some(instr.address.wrapping_add(*val as u64));
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }
    fn temukan_batas_switch(
        index_reg: &str,
        history: &[InstructionNormalized]
    ) -> Option<u64> {
        for instr in history.iter().rev() {
            if instr.mnemonic == "cmp" || instr.mnemonic == "cmpq" || instr.mnemonic == "cmpl" {
                let op0 = instr.operands_detail.get(0);
                let op1 = instr.operands_detail.get(1);
                if let (Some(JenisOperandDisasm::Register(r)), Some(JenisOperandDisasm::Immediate(imm))) = (op0, op1) {
                    if r == index_reg {
                        return Some((*imm + 1) as u64);
                    }
                }
                if let (Some(JenisOperandDisasm::Immediate(imm)), Some(JenisOperandDisasm::Register(r))) = (op0, op1) {
                    if r == index_reg {
                         return Some((*imm + 1) as u64);
                    }
                }
            }
             if !instr.operands_detail.is_empty() {
                if let JenisOperandDisasm::Register(r) = &instr.operands_detail[0] {
                    if r == index_reg && instr.mnemonic != "cmp" && instr.mnemonic != "test" {

                    }
                }
            }
        }
        None
    }
    fn baca_entry_tabel(
        vmem: &VirtualMemory,
        base_addr: u64,
        scale: i32,
        limit: usize
    ) -> Option<Vec<u64>> {
        let mut targets = Vec::new();
        let step = if scale == 0 { 4 } else { scale as u64 };
        let safe_limit = if limit > 1024 { 1024 } else { limit };
        for i in 0..safe_limit {
            let entry_addr = base_addr + (i as u64 * step);
            let target_val = if step == 8 {
                match vmem.baca_array(entry_addr, 8) {
                    Some(b) => u64::from_le_bytes(b.try_into().unwrap()),
                    None => break,
                }
            } else {
                match vmem.baca_array(entry_addr, 4) {
                    Some(b) => u32::from_le_bytes(b.try_into().unwrap()) as u64,
                    None => break,
                }
            };
            if Self::is_valid_code_ptr(vmem, target_val) {
                if !targets.contains(&target_val) {
                    targets.push(target_val);
                }
            } else {
                 if i > 0 && targets.is_empty() {
                    break;
                 }
            }
        }
        if !targets.is_empty() {
            Some(targets)
        } else {
            None
        }
    }
    fn is_valid_code_ptr(vmem: &VirtualMemory, addr: u64) -> bool {
        for seg in &vmem.segments {
            if addr >= seg.start_addr && addr < seg.end_addr {
                match seg.permissions {
                    IzinAkses::Execute | IzinAkses::ReadExecute | IzinAkses::Full => return true,
                    _ => {}
                }
            }
        }
        false
    }
}