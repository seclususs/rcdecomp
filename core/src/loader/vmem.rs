use std::collections::BTreeMap;
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IzinAkses {
    Read = 1,
    Write = 2,
    Execute = 4,
    ReadExecute = 5,
    ReadWrite = 3,
    Full = 7,
    None = 0,
}

impl IzinAkses {
    pub fn from_u32(val: u32) -> Self {
        match val {
            1 => Self::Read,
            2 => Self::Write,
            3 => Self::ReadWrite,
            4 => Self::Execute,
            5 => Self::ReadExecute,
            7 => Self::Full,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SegmentMemori {
    pub start_addr: u64,
    pub end_addr: u64,
    pub data: Vec<u8>,
    pub permissions: IzinAkses,
    pub nama_section: String,
}

pub struct VirtualMemory {
    pub segments: Vec<SegmentMemori>,
    pub entry_point: u64,
    pub arsitektur: String,
    pub format_biner: String,
    pub simbol_global: BTreeMap<u64, String>,
}

impl VirtualMemory {
    pub fn baru(entry: u64, arch: &str, format: &str) -> Self {
        Self {
            segments: Vec::new(),
            entry_point: entry,
            arsitektur: arch.to_string(),
            format_biner: format.to_string(),
            simbol_global: BTreeMap::new(),
        }
    }
    pub fn tambah_segment(&mut self, start: u64, data: Vec<u8>, perm: IzinAkses, nama: String) {
        let end = start + data.len() as u64;
        self.segments.push(SegmentMemori {
            start_addr: start,
            end_addr: end,
            data,
            permissions: perm,
            nama_section: nama,
        });
        self.segments.sort_by(|a, b| a.start_addr.cmp(&b.start_addr));
    }
    fn temukan_segment_target(&self, addr: u64) -> Option<&SegmentMemori> {
        let hasil_pencarian = self.segments.binary_search_by(|seg| {
            if addr >= seg.end_addr {
                Ordering::Less
            } else if addr < seg.start_addr {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        });
        match hasil_pencarian {
            Ok(index) => Some(&self.segments[index]),
            Err(_) => None,
        }
    }
    pub fn baca_byte(&self, addr: u64) -> Option<u8> {
        if let Some(seg) = self.temukan_segment_target(addr) {
            let offset = (addr - seg.start_addr) as usize;
            return seg.data.get(offset).cloned();
        }
        None
    }
    pub fn baca_array(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        if let Some(seg) = self.temukan_segment_target(addr) {
            let offset = (addr - seg.start_addr) as usize;
            if offset + len <= seg.data.len() {
                return Some(seg.data[offset..offset + len].to_vec());
            }
        }
        None
    }
    pub fn ambil_executable_regions(&self) -> Vec<(u64, &[u8])> {
        self.segments.iter()
            .filter(|s| match s.permissions {
                IzinAkses::Execute | IzinAkses::ReadExecute | IzinAkses::Full => true,
                _ => false,
            })
            .map(|s| (s.start_addr, s.data.as_slice()))
            .collect()
    }
}