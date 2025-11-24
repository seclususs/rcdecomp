pub struct MachoLoader {
    _is_universal: bool,
    _architecture: String,
}

impl MachoLoader {
    pub fn new() -> Self {
        Self {
            _is_universal: false,
            _architecture: "x86_64".to_string(),
        }
    }
    pub fn check_magic_bytes(&self, bytes: &[u8]) -> bool {
        if bytes.len() < 4 {
            return false;
        }
        bytes[0] == 0xFE && bytes[1] == 0xED && bytes[2] == 0xFA && bytes[3] == 0xCF
    }
    pub fn load_segmen_data(&self) {
    }
}