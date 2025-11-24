#[derive(Debug, Clone)]
pub struct InstructionNormalized {
    pub address: u64,
    pub mnemonic: String,
    pub op_str: String,
    pub bytes: Vec<u8>,
}

impl InstructionNormalized {
    pub fn new(addr: u64, mnem: &str, ops: &str) -> Self {
        Self {
            address: addr,
            mnemonic: mnem.to_string(),
            op_str: ops.to_string(),
            bytes: Vec::new(),
        }
    }
    pub fn hitung_panjang_byte(&self) -> usize {
        self.bytes.len()
    }
}