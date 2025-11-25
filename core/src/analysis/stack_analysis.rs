use std::collections::{HashMap, HashSet};
use crate::ir::types::{StatementIr, TipeOperand, OperasiIr};
use crate::arch::Architecture;

#[derive(Debug, Clone)]
pub struct IntervalLiveness {
    pub start_addr: u64,
    pub end_addr: u64,
}

#[derive(Debug, Clone)]
pub struct StackVariable {
    pub id_unik: usize,
    pub offset: i64,
    pub nama_var: String,
    pub tipe_data: String,
    pub range_aktif: Vec<IntervalLiveness>,
    pub is_address_taken: bool,
    pub is_array_buffer: bool,
    pub element_size: usize,
    pub array_count: usize,
}

pub struct StackFrame {
    pub map_offset_variabel: HashMap<i64, Vec<StackVariable>>,
    pub frame_size: i64,
    counter_var: usize,
    array_access_offsets: HashSet<i64>, 
}

impl StackFrame {
    pub fn new() -> Self {
        Self {
            map_offset_variabel: HashMap::new(),
            frame_size: 0,
            counter_var: 0,
            array_access_offsets: HashSet::new(),
        }
    }
    pub fn analisis_stack_frame(stmts: &[StatementIr], arch: &dyn Architecture) -> Self {
        let mut frame = Self::new();
        let mut akses_stack: HashMap<i64, Vec<(u64, JenisAkses)>> = HashMap::new();
        let fp = arch.dapatkan_frame_pointer();
        for stmt in stmts {
            frame.deteksi_pola_array_stack(&stmt.operand_satu, &fp);
            frame.deteksi_pola_array_stack(&stmt.operand_dua, &fp);
            frame.kumpulkan_akses(&stmt.operand_satu, stmt.address_asal, &mut akses_stack, &fp, true);
            frame.kumpulkan_akses(&stmt.operand_dua, stmt.address_asal, &mut akses_stack, &fp, false);
            if let OperasiIr::Lea = stmt.operation_code {
                if let TipeOperand::MemoryRef { base, offset } = &stmt.operand_dua {
                    if base == &fp {
                        akses_stack.entry(*offset).or_default().push((stmt.address_asal, JenisAkses::AddressTaken));
                    }
                }
            }
        }
        for (offset, events) in akses_stack {
            let mut vars = frame.proses_split_variabel(offset, events);
            if frame.array_access_offsets.contains(&offset) {
                for var in &mut vars {
                    var.is_array_buffer = true;
                    var.nama_var = format!("buf_{}", var.offset.abs());
                    var.tipe_data = "char".to_string(); 
                    var.array_count = 64;
                }
            }
            frame.map_offset_variabel.insert(offset, vars);
        }
        frame
    }
    fn deteksi_pola_array_stack(&mut self, op: &TipeOperand, fp: &str) {
        if let TipeOperand::Expression { operasi: OperasiIr::Add, operand_kiri, operand_kanan } = op {
             self.deteksi_pola_array_stack(operand_kiri, fp);
             self.deteksi_pola_array_stack(operand_kanan, fp);
             if let Some((offset, has_dynamic_index)) = self.parse_stack_address_expression(op, fp) {
                 if has_dynamic_index {
                     self.array_access_offsets.insert(offset);
                 }
             }
        }
    }
    fn parse_stack_address_expression(&self, expr: &TipeOperand, fp: &str) -> Option<(i64, bool)> {
        match expr {
            TipeOperand::Register(r) if r == fp => Some((0, false)),
            TipeOperand::Immediate(val) => Some((*val, false)), // Offset murni
            TipeOperand::Expression { operasi: OperasiIr::Add, operand_kiri, operand_kanan } => {
                let res1 = self.parse_stack_address_expression(operand_kiri, fp);
                let res2 = self.parse_stack_address_expression(operand_kanan, fp);
                match (res1, res2) {
                    (Some((off1, dyn1)), Some((off2, dyn2))) => {
                        Some((off1 + off2, dyn1 || dyn2))
                    },
                    (Some((off, _)), None) | (None, Some((off, _))) => {
                        Some((off, true)) 
                    },
                    _ => None
                }
            },
            TipeOperand::Expression { operasi: OperasiIr::Imul, .. } => {
                None 
            },
            TipeOperand::Register(_) => None,
            _ => None,
        }
    }
    fn kumpulkan_akses(
        &self, 
        op: &TipeOperand, 
        addr: u64, 
        peta_akses: &mut HashMap<i64, Vec<(u64, JenisAkses)>>, 
        fp: &str,
        is_dest: bool
    ) {
        match op {
            TipeOperand::MemoryRef { base, offset } => {
                if base == fp {
                    let jenis = if is_dest { JenisAkses::Write } else { JenisAkses::Read };
                    peta_akses.entry(*offset).or_default().push((addr, jenis));
                }
            },
            TipeOperand::Expression { operand_kiri, operand_kanan, .. } => {
                self.kumpulkan_akses(operand_kiri, addr, peta_akses, fp, is_dest);
                self.kumpulkan_akses(operand_kanan, addr, peta_akses, fp, is_dest);
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
            if let Some(mut var) = current_var.take() {
                if addr > last_access + 200 && !var.is_address_taken && !var.is_array_buffer {
                    var.range_aktif.push(IntervalLiveness { start_addr: var.range_aktif[0].start_addr, end_addr: last_access });
                    daftar_vars.push(var);
                    current_var = Some(self.buat_variabel_baru(offset, addr));
                } else {
                    if jenis == JenisAkses::AddressTaken {
                        var.is_address_taken = true;
                    }
                    current_var = Some(var);
                }
            } else {
                let mut var = self.buat_variabel_baru(offset, addr);
                if jenis == JenisAkses::AddressTaken {
                    var.is_address_taken = true;
                }
                current_var = Some(var);
            }
            last_access = addr;
        }
        if let Some(mut var) = current_var {
            let start = if !var.range_aktif.is_empty() { var.range_aktif[0].start_addr } else { last_access };
            var.range_aktif = vec![IntervalLiveness { start_addr: start, end_addr: last_access }];
            daftar_vars.push(var);
        }
        if daftar_vars.len() > 1 {
            for (i, var) in daftar_vars.iter_mut().enumerate() {
                let suffix = (b'A' + (i as u8 % 26)) as char;
                var.nama_var = format!("{}_{}", var.nama_var, suffix);
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
            is_array_buffer: false,
            element_size: 1,
            array_count: 1,
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
                if var.is_address_taken || var.is_array_buffer {
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