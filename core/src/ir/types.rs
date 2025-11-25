#[derive(Debug, Clone, PartialEq)]
pub enum TipeOperand {
    Register(String),
    SsaVariable(String, usize), 
    Immediate(i64),
    Memory(u64),
    MemoryRef { base: String, offset: i64 },
    Expression {
        operasi: OperasiIr,
        operand_kiri: Box<TipeOperand>,
        operand_kanan: Box<TipeOperand>,
    },
    None,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OperasiIr {
    Mov,
    Add,
    Sub,
    Imul,
    Jmp,
    Je,
    Jne,
    Jg,
    Jge,
    Jl,
    Jle,
    Cmp,
    Test,
    Call,
    Ret,
    Nop,
    Phi,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct StatementIr {
    pub address_asal: u64,
    pub operation_code: OperasiIr,
    pub operand_satu: TipeOperand,
    pub operand_dua: TipeOperand,
    pub operand_tambahan: Vec<TipeOperand>, 
}

impl StatementIr {
    pub fn new(addr: u64, op: OperasiIr, op1: TipeOperand, op2: TipeOperand) -> Self {
        Self {
            address_asal: addr,
            operation_code: op,
            operand_satu: op1,
            operand_dua: op2,
            operand_tambahan: Vec::new(),
        }
    }
    pub fn convert_ke_string(&self) -> String {
        format!(
            "Addr: 0x{:x} | Op: {:?} | Ops: {:?}, {:?}",
            self.address_asal, self.operation_code, self.operand_satu, self.operand_dua
        )
    }
}