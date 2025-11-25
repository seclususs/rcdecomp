use std::collections::HashMap;
use crate::ir::types::{StatementIr, TipeOperand};
use crate::arch::Architecture;

#[derive(Debug, Clone)]
pub struct IntervalLiveness {
    pub start_addr: u64,
    pub end_addr: u64,
}

impl IntervalLiveness {
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start_addr && addr <= self.end_addr
    }
}

#[derive(Debug, Clone)]
pub struct StackVariable {
    pub id_unik: usize,
    pub offset: i64,
    pub nama_var: String,
    pub tipe_data: String,
    pub range_aktif: Vec<IntervalLiveness>,
    pub is_address_taken: bool,
}

pub struct StackFrame {
    pub map_offset_variabel: HashMap<i64, Vec<StackVariable>>,
    pub frame_size: i64,
    counter_var: usize,
}

impl StackFrame {
    pub fn new() -> Self {
        Self {
            map_offset_variabel: HashMap::new(),
            frame_size: 0,
            counter_var: 0,
        }
    }
    pub fn analisis_stack_frame(stmts: &[StatementIr], arch: &dyn Architecture) -> Self {
        let mut frame = Self::new();
        let mut akses_stack: HashMap<i64, Vec<(u64, JenisAkses)>> = HashMap::new();
        for stmt in stmts {
            frame.kumpulkan_akses(&stmt.operand_satu, stmt.address_asal, &mut akses_stack, arch, true);
            frame.kumpulkan_akses(&stmt.operand_dua, stmt.address_asal, &mut akses_stack, arch, false);
            if let TipeOperand::Expression { operasi: _operasi, operand_kiri, operand_kanan } = &stmt.operand_dua {
                if let TipeOperand::Register(reg) = &**operand_kiri {
                    if reg == &arch.dapatkan_frame_pointer() {
                        if let TipeOperand::Immediate(off) = &**operand_kanan {
                             akses_stack.entry(*off).or_default().push((stmt.address_asal, JenisAkses::AddressTaken));
                        }
                    }
                }
            }
        }
        for (offset, events) in akses_stack {
            let vars = frame.proses_split_variabel(offset, events);
            frame.map_offset_variabel.insert(offset, vars);
        }
        frame
    }
    fn kumpulkan_akses(
        &self, 
        op: &TipeOperand, 
        addr: u64, 
        peta_akses: &mut HashMap<i64, Vec<(u64, JenisAkses)>>, 
        arch: &dyn Architecture,
        is_dest: bool
    ) {
        match op {
            TipeOperand::MemoryRef { base, offset } => {
                if base == &arch.dapatkan_frame_pointer() {
                    let jenis = if is_dest { JenisAkses::Write } else { JenisAkses::Read };
                    peta_akses.entry(*offset).or_default().push((addr, jenis));
                }
            },
            TipeOperand::Expression { operand_kiri, operand_kanan, .. } => {
                self.kumpulkan_akses(operand_kiri, addr, peta_akses, arch, is_dest);
                self.kumpulkan_akses(operand_kanan, addr, peta_akses, arch, is_dest);
            },
            _ => {}
        }
    }
    fn proses_split_variabel(&mut self, offset: i64, mut events: Vec<(u64, JenisAkses)>) -> Vec<StackVariable> {
        events.sort_by_key(|k| k.0);
        let mut daftar_vars = Vec::new();
        let mut current_var: Option<StackVariable> = None;
        let mut last_access: u64 = 0;
        for (addr, jenis) in events {
            match jenis {
                JenisAkses::Write => {
                    if let Some(mut var) = current_var.take() {
                        if addr > last_access + 100 {
                             var.range_aktif.push(IntervalLiveness { start_addr: var.range_aktif[0].start_addr, end_addr: last_access });
                             daftar_vars.push(var);
                             current_var = Some(self.buat_variabel_baru(offset, addr));
                        } else {
                            current_var = Some(var);
                        }
                    } else {
                        current_var = Some(self.buat_variabel_baru(offset, addr));
                    }
                },
                JenisAkses::Read => {
                    if let Some(var) = current_var.take() {
                        last_access = addr;
                        current_var = Some(var);
                    } else {
                        let var = self.buat_variabel_baru(offset, addr);
                        last_access = addr;
                        current_var = Some(var);
                    }
                },
                JenisAkses::AddressTaken => {
                    if let Some(mut var) = current_var.take() {
                        var.is_address_taken = true;
                        last_access = addr;
                        current_var = Some(var);
                    } else {
                        let mut var = self.buat_variabel_baru(offset, addr);
                        var.is_address_taken = true;
                        last_access = addr;
                        current_var = Some(var);
                    }
                }
            }
        }
        if let Some(mut var) = current_var {
            let start = if !var.range_aktif.is_empty() { var.range_aktif[0].start_addr } else { last_access };
            var.range_aktif = vec![IntervalLiveness { start_addr: start, end_addr: last_access }];
            daftar_vars.push(var);
        }
        if daftar_vars.len() > 1 {
            for (i, var) in daftar_vars.iter_mut().enumerate() {
                let suffix = (b'A' + (i as u8 % 26)) as char;
                if var.offset < 0 {
                    var.nama_var = format!("var_{}_{}", var.offset.abs(), suffix);
                } else {
                    var.nama_var = format!("arg_{}_{}", var.offset, suffix);
                }
            }
        }
        daftar_vars
    }
    fn buat_variabel_baru(&mut self, offset: i64, start: u64) -> StackVariable {
        self.counter_var += 1;
        let nama = if offset < 0 {
            format!("var_{}", offset.abs())
        } else {
            format!("arg_{}", offset)
        };
        StackVariable {
            id_unik: self.counter_var,
            offset,
            nama_var: nama,
            tipe_data: "long".to_string(),
            range_aktif: vec![IntervalLiveness { start_addr: start, end_addr: start }],
            is_address_taken: false,
        }
    }
    pub fn ambil_variabel_kontekstual(&self, offset: i64, current_instr_addr: u64) -> Option<String> {
        if let Some(vars) = self.map_offset_variabel.get(&offset) {
            for var in vars {
                for interval in &var.range_aktif {
                    if current_instr_addr >= interval.start_addr && current_instr_addr <= interval.end_addr + 16 {
                        return Some(var.nama_var.clone());
                    }
                }
                if var.is_address_taken {
                    return Some(var.nama_var.clone());
                }
            }
            if let Some(last) = vars.last() {
                return Some(last.nama_var.clone());
            }
        }
        None
    }
}

#[derive(Debug, PartialEq)]
enum JenisAkses {
    Read,
    Write,
    AddressTaken,
}