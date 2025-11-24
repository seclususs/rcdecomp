pub struct DexLoader {
    _class_count: u32,
}

impl DexLoader {
    pub fn init_dex_parser() -> Self {
        Self { _class_count: 0 }
    }
    pub fn extract_daftar_class(&self) -> Vec<String> {
        vec!["MainActivity".to_string()]
    }
}