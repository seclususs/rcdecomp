use std::collections::HashMap;
use log::{info, debug};
use crate::loader::vmem::{VirtualMemory, IzinAkses};
use crate::ir::types::{StatementIr, OperasiIr, TipeOperand};
use crate::analysis::recovery::types::{TypeSystem, ClassLayout, TipePrimitif};

#[derive(Debug, Clone)]
pub struct VirtualTableInfo {
    pub address_awal: u64,
    pub panjang_entry: usize,
    pub list_fungsi: Vec<u64>,
    pub nama_simbol: Option<String>,
}

pub struct VtableAnalyzer {
    pub detected_vtables: HashMap<u64, VirtualTableInfo>,
    pub pointer_size: usize,
}

impl VtableAnalyzer {
    pub fn new(pointer_size: usize) -> Self {
        Self {
            detected_vtables: HashMap::new(),
            pointer_size,
        }
    }
    pub fn jalankan_scan_heuristik(&mut self, vmem: &VirtualMemory) {
        info!("Memulai scan heuristik untuk kandidat VTable...");
        let ro_sections: Vec<(u64, &[u8])> = vmem.segments.iter()
            .filter(|s| s.permissions == IzinAkses::Read) 
            .map(|s| (s.start_addr, s.data.as_slice()))
            .collect();
        for (base_addr, data) in ro_sections {
            self.pindai_section_data(vmem, base_addr, data);
        }
        info!("Ditemukan {} kandidat vtable.", self.detected_vtables.len());
    }
    fn pindai_section_data(&mut self, vmem: &VirtualMemory, base_addr: u64, data: &[u8]) {
        let step = self.pointer_size;
        let mut offset = 0;
        while offset + step <= data.len() {
            let current_addr = base_addr + offset as u64;
            if let Some(vtable) = self.verifikasi_sequence_pointer(vmem, current_addr) {
                if vtable.list_fungsi.len() >= 2 {
                    debug!("VTable terdeteksi di 0x{:x} dengan {} entri", current_addr, vtable.list_fungsi.len());
                    let len_bytes = vtable.list_fungsi.len() * step;
                    self.detected_vtables.insert(current_addr, vtable);
                    offset += len_bytes; 
                    continue;
                }
            }
            offset += step;
        }
    }
    fn verifikasi_sequence_pointer(&self, vmem: &VirtualMemory, start_addr: u64) -> Option<VirtualTableInfo> {
        let mut list_fungsi = Vec::new();
        let mut curr = start_addr;
        let step = self.pointer_size as u64;
        for _ in 0..50 { 
            let ptr_val = if self.pointer_size == 8 {
                match vmem.baca_array(curr, 8) {
                    Some(b) => u64::from_le_bytes(b.try_into().unwrap()),
                    None => break,
                }
            } else {
                match vmem.baca_array(curr, 4) {
                    Some(b) => u32::from_le_bytes(b.try_into().unwrap()) as u64,
                    None => break,
                }
            };
            if self.cek_pointer_ke_executable(vmem, ptr_val) {
                list_fungsi.push(ptr_val);
                curr += step;
            } else {
                break; 
            }
        }
        if list_fungsi.is_empty() {
            None
        } else {
            Some(VirtualTableInfo {
                address_awal: start_addr,
                panjang_entry: list_fungsi.len(),
                list_fungsi,
                nama_simbol: vmem.simbol_global.get(&start_addr).cloned(),
            })
        }
    }
    fn cek_pointer_ke_executable(&self, vmem: &VirtualMemory, target: u64) -> bool {
        if target == 0 { return false; }
        for seg in &vmem.segments {
            if target >= seg.start_addr && target < seg.end_addr {
                return matches!(seg.permissions, IzinAkses::Execute | IzinAkses::ReadExecute | IzinAkses::Full);
            }
        }
        false
    }
    pub fn analisis_dan_rekonstruksi_kelas(&self, all_stmts: &HashMap<u64, Vec<StatementIr>>, type_sys: &mut TypeSystem) {
        info!("Memulai rekonstruksi hierarki kelas berdasarkan penggunaan VTable...");
        let mut class_counter = 0;
        for (func_addr, stmts) in all_stmts {
            for stmt in stmts {
                if let OperasiIr::Mov = stmt.operation_code {
                    if let Some(vtable_addr) = self.extract_const_assignment_src(&stmt.operand_dua) {
                        if self.detected_vtables.contains_key(&vtable_addr) {
                            if let Some(base_reg) = self.extract_base_assignment_dest(&stmt.operand_satu) {
                                debug!("Konstruktor potensial ditemukan di 0x{:x}, assign vtable 0x{:x} ke {}", func_addr, vtable_addr, base_reg);
                                let class_name = if let Some(sym) = &self.detected_vtables[&vtable_addr].nama_simbol {
                                    format!("Class_{}", sym)
                                } else {
                                    class_counter += 1;
                                    format!("Class_{}_{:x}", class_counter, vtable_addr)
                                };
                                if !type_sys.class_definitions.contains_key(&class_name) {
                                    let layout = ClassLayout {
                                        name: class_name.clone(),
                                        parent_name: None,
                                        vtable_address: Some(vtable_addr),
                                        fields: std::collections::BTreeMap::new(),
                                        virtual_methods: self.detected_vtables[&vtable_addr].list_fungsi.clone(),
                                    };
                                    type_sys.class_definitions.insert(class_name.clone(), layout);
                                    if let Some(sig) = type_sys.global_signatures.get_mut(func_addr) {
                                        sig.arg_types[0] = TipePrimitif::Pointer(Box::new(TipePrimitif::Class(class_name.clone())));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    fn extract_const_assignment_src(&self, op: &TipeOperand) -> Option<u64> {
        match op {
            TipeOperand::Immediate(val) => Some(*val as u64),
            _ => None,
        }
    }
    fn extract_base_assignment_dest(&self, op: &TipeOperand) -> Option<String> {
        match op {
            TipeOperand::MemoryRef { base, offset } => {
                if *offset == 0 {
                    Some(base.clone())
                } else {
                    None
                }
            },
            _ => None,
        }
    }
}