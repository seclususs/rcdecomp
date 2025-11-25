#[derive(Debug, Clone, PartialEq)]
pub enum JenisOperandDisasm {
    Register(String),
    Immediate(i64),
    Memory {
        base: Option<String>,
        index: Option<String>,
        scale: i32,
        disp: i64,
    },
    Unknown,
}

#[derive(Debug, Clone)]
pub struct InstructionNormalized {
    pub address: u64,
    pub mnemonic: String,
    pub op_str: String,
    pub bytes: Vec<u8>,
    pub operands_detail: Vec<JenisOperandDisasm>,
}

impl InstructionNormalized {
    pub fn new(addr: u64, mnem: &str, ops: &str) -> Self {
        Self {
            address: addr,
            mnemonic: mnem.to_string(),
            op_str: ops.to_string(),
            bytes: Vec::new(),
            operands_detail: Vec::new(),
        }
    }
    pub fn hitung_panjang_byte(&self) -> usize {
        self.bytes.len()
    }
}