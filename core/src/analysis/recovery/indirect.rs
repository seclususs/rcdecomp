use crate::disasm::instruction::{InstructionNormalized, JenisOperandDisasm};
use crate::loader::vmem::{VirtualMemory, IzinAkses};
use log::{debug, info};

pub struct JumpTableAnalyzer;

impl JumpTableAnalyzer {
    pub fn analisis_jump_table(
        instr: &InstructionNormalized, 
        vmem: &VirtualMemory
    ) -> Option<Vec<u64>> {
        if instr.mnemonic != "jmp" && instr.mnemonic != "br" {
            return None;
        }
        if let Some(operand) = instr.operands_detail.first() {
            match operand {
                JenisOperandDisasm::Memory { base: _, index, scale, disp } => {
                    if index.is_some() && *disp != 0 {
                        info!("Potensi Jump Table terdeteksi di 0x{:x}, Base Table: 0x{:x}", instr.address, disp);
                        return Self::ekstrak_target_dari_rodata(vmem, *disp as u64, *scale);
                    }
                }
                _ => {}
            }
        }
        None
    }
    fn ekstrak_target_dari_rodata(
        vmem: &VirtualMemory, 
        table_addr: u64, 
        scale: i32
    ) -> Option<Vec<u64>> {
        let mut daftar_target = Vec::new();
        let mut current_addr = table_addr;
        let max_entries = 256; 
        for _ in 0..max_entries {
            let target_addr = if scale == 8 {
                if let Some(bytes) = vmem.baca_array(current_addr, 8) {
                    u64::from_le_bytes(bytes.try_into().unwrap())
                } else {
                    break;
                }
            } else if scale == 4 {
                if let Some(bytes) = vmem.baca_array(current_addr, 4) {
                    u32::from_le_bytes(bytes.try_into().unwrap()) as u64
                } else {
                    break;
                }
            } else {
                break;
            };
            if Self::is_valid_code_ptr(vmem, target_addr) {
                if daftar_target.last() != Some(&target_addr) {
                    daftar_target.push(target_addr);
                }
                current_addr += scale as u64;
            } else {
                break;
            }
        }
        if !daftar_target.is_empty() {
            debug!("Jump Table berhasil diekstrak: {} targets ditemukan.", daftar_target.len());
            Some(daftar_target)
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