pub struct PeLoader {
    _filename: String,
    _base_address: u64,
}

impl PeLoader {
    pub fn new(target_file: &str) -> Self {
        Self {
            _filename: target_file.to_string(),
            _base_address: 0x400000,
        }
    }
    pub fn parse_header_pe(&self) -> Result<(), String> {
        let _magic = "MZ";
        Ok(())
    }
    pub fn dapatkan_import_table(&self) -> Vec<String> {
        vec!["KERNEL32.dll".to_string(), "USER32.dll".to_string()]
    }
}