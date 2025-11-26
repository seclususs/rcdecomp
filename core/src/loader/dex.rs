use std::fs;
use std::path::Path;
use std::convert::TryInto;
use crate::loader::vmem::{VirtualMemory, IzinAkses};
use crate::loader::LoaderError;
use log::{info, warn, debug, error};

const ACC_PUBLIC: u32 = 0x1;
const ACC_PRIVATE: u32 = 0x2;
const ACC_PROTECTED: u32 = 0x4;
const ACC_STATIC: u32 = 0x8;
const ACC_FINAL: u32 = 0x10;
const ACC_SYNCHRONIZED: u32 = 0x20;
const ACC_NATIVE: u32 = 0x100;
const ACC_INTERFACE: u32 = 0x200;
const ACC_ABSTRACT: u32 = 0x400;
const ACC_CONSTRUCTOR: u32 = 0x10000;

#[derive(Debug, Clone, Copy)]
pub struct DexHeader {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

#[derive(Debug)]
struct ClassDefItem {
    pub _class_idx: u32,
    pub class_data_off: u32,
}

pub struct DexLoader {
    file_path: String,
    raw_data: Vec<u8>,
    header: Option<DexHeader>,
}

impl DexLoader {
    pub fn new(path: &str) -> Self {
        Self {
            file_path: path.to_string(),
            raw_data: Vec::new(),
            header: None,
        }
    }
    pub fn muat_virtual_memory(&mut self) -> Result<VirtualMemory, LoaderError> {
        let path = Path::new(&self.file_path);
        self.raw_data = fs::read(path).map_err(|e| LoaderError::IoError(e.to_string()))?;
        self.parse_header_dex_aman()?;
        let header_valid = self.header.as_ref().unwrap(); 
        let mut vmem = VirtualMemory::baru(0, "dalvik");
        vmem.tambah_segment(0, self.raw_data.clone(), IzinAkses::Read, "dex_full_image".to_string());
        info!("Memproses {} definisi class...", header_valid.class_defs_size);
        for i in 0..header_valid.class_defs_size {
            let offset_def = (header_valid.class_defs_off as usize)
                .checked_add((i as usize).checked_mul(32).ok_or(LoaderError::OutOfBoundsError)?)
                .ok_or(LoaderError::OutOfBoundsError)?;
            if offset_def.checked_add(32).ok_or(LoaderError::OutOfBoundsError)? > self.raw_data.len() { 
                warn!("Class definition index {} OOB", i);
                break; 
            }
            let class_def = self.baca_class_def(offset_def);
            if class_def.class_data_off > 0 {
                if let Err(e) = self.proses_class_data_item(&mut vmem, class_def.class_data_off as usize) {
                    debug!("Skip class data di 0x{:x}: {:?}", class_def.class_data_off, e);
                }
            }
        }
        Ok(vmem)
    }
    fn parse_header_dex_aman(&mut self) -> Result<(), LoaderError> {
        if self.raw_data.len() < 112 {
            return Err(LoaderError::InvalidFormat);
        }
        let magic: [u8; 8] = self.raw_data[0..8].try_into().map_err(|_| LoaderError::ParseError("Magic fail".into()))?;
        if !self.validasi_magic_number(&magic) {
            return Err(LoaderError::InvalidFormat);
        }
        let header = DexHeader {
            magic,
            checksum: self.baca_uint32_safe(8)?,
            signature: self.raw_data[12..32].try_into().unwrap_or([0u8; 20]),
            file_size: self.baca_uint32_safe(32)?,
            header_size: self.baca_uint32_safe(36)?,
            endian_tag: self.baca_uint32_safe(40)?,
            link_size: self.baca_uint32_safe(44)?,
            link_off: self.baca_uint32_safe(48)?,
            map_off: self.baca_uint32_safe(52)?,
            string_ids_size: self.baca_uint32_safe(56)?,
            string_ids_off: self.baca_uint32_safe(60)?,
            type_ids_size: self.baca_uint32_safe(64)?,
            type_ids_off: self.baca_uint32_safe(68)?,
            proto_ids_size: self.baca_uint32_safe(72)?,
            proto_ids_off: self.baca_uint32_safe(76)?,
            field_ids_size: self.baca_uint32_safe(80)?,
            field_ids_off: self.baca_uint32_safe(84)?,
            method_ids_size: self.baca_uint32_safe(88)?,
            method_ids_off: self.baca_uint32_safe(92)?,
            class_defs_size: self.baca_uint32_safe(96)?,
            class_defs_off: self.baca_uint32_safe(100)?,
            data_size: self.baca_uint32_safe(104)?,
            data_off: self.baca_uint32_safe(108)?,
        };
        if header.file_size as usize > self.raw_data.len() {
            error!("Header file size mismatch");
            return Err(LoaderError::InvalidFormat);
        }
        self.header = Some(header);
        Ok(())
    }
    fn validasi_magic_number(&self, magic: &[u8; 8]) -> bool {
        magic[0] == 0x64 && magic[1] == 0x65 && magic[2] == 0x78 && magic[3] == 0x0A 
    }
    fn baca_uint32_safe(&self, offset: usize) -> Result<u32, LoaderError> {
        if offset + 4 <= self.raw_data.len() {
            let bytes: [u8; 4] = self.raw_data[offset..offset+4].try_into().map_err(|_| LoaderError::ParseError("Slice conv fail".into()))?;
            Ok(u32::from_le_bytes(bytes))
        } else {
            Err(LoaderError::OutOfBoundsError)
        }
    }
    fn baca_class_def(&self, offset: usize) -> ClassDefItem {
        ClassDefItem {
            _class_idx: self.baca_uint32_safe(offset).unwrap_or(0),
            class_data_off: self.baca_uint32_safe(offset + 24).unwrap_or(0),
        }
    }
    fn proses_class_data_item(&self, vmem: &mut VirtualMemory, offset: usize) -> Result<(), LoaderError> {
        let mut cursor_pos = offset;
        let (static_fields_size, len_sf) = self.baca_uleb128_aman(cursor_pos)?; cursor_pos += len_sf;
        let (instance_fields_size, len_if) = self.baca_uleb128_aman(cursor_pos)?; cursor_pos += len_if;
        let (direct_methods_size, len_dm) = self.baca_uleb128_aman(cursor_pos)?; cursor_pos += len_dm;
        let (virtual_methods_size, len_vm) = self.baca_uleb128_aman(cursor_pos)?; cursor_pos += len_vm;
        for _ in 0..static_fields_size {
            let (_, len1) = self.baca_uleb128_aman(cursor_pos)?; cursor_pos += len1;
            let (_, len2) = self.baca_uleb128_aman(cursor_pos)?; cursor_pos += len2;
        }
        for _ in 0..instance_fields_size {
            let (_, len1) = self.baca_uleb128_aman(cursor_pos)?; cursor_pos += len1;
            let (_, len2) = self.baca_uleb128_aman(cursor_pos)?; cursor_pos += len2;
        }
        let mut process_methods = |count: u32, cursor: &mut usize, tracker: &mut u32| -> Result<(), LoaderError> {
            for _ in 0..count {
                let (idx_diff, len1) = self.baca_uleb128_aman(*cursor)?; *cursor += len1;
                *tracker += idx_diff;
                let (access_flags, len2) = self.baca_uleb128_aman(*cursor)?; *cursor += len2;
                let (code_off, len3) = self.baca_uleb128_aman(*cursor)?; *cursor += len3;
                if code_off > 0 {
                    self.ekstrak_bytecode_method(vmem, code_off as usize, *tracker, access_flags)?;
                } else if (access_flags & ACC_NATIVE) != 0 {
                    let suffix = self.urai_access_flags(access_flags);
                    let nama_method = format!("sub_dex_native_{:x}{}", *tracker, suffix);
                    debug!("Native method detected (no dex code): {}", nama_method);
                }
            }
            Ok(())
        };
        let mut method_idx_tracker = 0;
        process_methods(direct_methods_size, &mut cursor_pos, &mut method_idx_tracker)?;
        method_idx_tracker = 0;
        process_methods(virtual_methods_size, &mut cursor_pos, &mut method_idx_tracker)?;
        Ok(())
    }
    fn ekstrak_bytecode_method(&self, vmem: &mut VirtualMemory, code_off: usize, method_idx: u32, access_flags: u32) -> Result<(), LoaderError> {
        if code_off.checked_add(16).ok_or(LoaderError::OutOfBoundsError)? > self.raw_data.len() {
            return Err(LoaderError::OutOfBoundsError);
        }
        let insns_size = self.baca_uint32_safe(code_off + 12)?;
        if insns_size == 0 { return Ok(()); }
        let insns_byte_len = (insns_size as usize).checked_mul(2).ok_or(LoaderError::OutOfBoundsError)?;
        let insns_start = code_off + 16;
        let insns_end = insns_start.checked_add(insns_byte_len).ok_or(LoaderError::OutOfBoundsError)?;
        if insns_end > self.raw_data.len() {
            return Err(LoaderError::OutOfBoundsError);
        }
        let bytecode_data = self.raw_data[insns_start..insns_end].to_vec();
        let suffix_info = self.urai_access_flags(access_flags);
        let segment_name = format!("method_{:x}{}", method_idx, suffix_info);
        vmem.tambah_segment(code_off as u64, bytecode_data, IzinAkses::Execute, segment_name);
        let nama_method = format!("sub_dex_{:x}{}", method_idx, suffix_info);
        vmem.simbol_global.insert(code_off as u64, nama_method);
        Ok(())
    }
    fn urai_access_flags(&self, flags: u32) -> String {
        let mut list_status = Vec::new();
        if flags & ACC_PUBLIC != 0 { list_status.push("pub"); }
        if flags & ACC_PRIVATE != 0 { list_status.push("priv"); }
        if flags & ACC_PROTECTED != 0 { list_status.push("prot"); }
        if flags & ACC_STATIC != 0 { list_status.push("static"); }
        if flags & ACC_FINAL != 0 { list_status.push("final"); }
        if flags & ACC_SYNCHRONIZED != 0 { list_status.push("sync"); }
        if flags & ACC_NATIVE != 0 { list_status.push("native"); }
        if flags & ACC_INTERFACE != 0 { list_status.push("iface"); }
        if flags & ACC_ABSTRACT != 0 { list_status.push("abstract"); }
        if flags & ACC_CONSTRUCTOR != 0 { list_status.push("ctor"); }
        if list_status.is_empty() {
            String::new()
        } else {
            format!("_{}", list_status.join("_"))
        }
    }
    fn baca_uleb128_aman(&self, offset: usize) -> Result<(u32, usize), LoaderError> {
        let mut result_val = 0;
        let mut shift_val = 0;
        let mut count_byte = 0;
        let mut cursor_pos = offset;
        loop {
            if cursor_pos >= self.raw_data.len() {
                return Err(LoaderError::OutOfBoundsError);
            }
            let byte = self.raw_data[cursor_pos];
            cursor_pos += 1;
            count_byte += 1;
            result_val |= ((byte & 0x7f) as u32) << shift_val;
            if (byte & 0x80) == 0 { break; }
            shift_val += 7;
            if shift_val > 35 { 
                return Err(LoaderError::ParseError("ULEB128 overflow".into()));
            } 
        }
        Ok((result_val, count_byte))
    }
}