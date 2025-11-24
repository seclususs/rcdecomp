#[derive(Debug, Clone, PartialEq)]
pub enum TipeOperand {
    Register(String),
    Immediate(i64),
    Memory(u64),
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
    Call,
    Ret,
    Nop,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct StatementIr {
    pub address_asal: u64,
    pub operation_code: OperasiIr,
    pub operand_satu: TipeOperand,
    pub operand_dua: TipeOperand,
}

impl StatementIr {
    pub fn new(addr: u64, op: OperasiIr, op1: TipeOperand, op2: TipeOperand) -> Self {
        Self {
            address_asal: addr,
            operation_code: op,
            operand_satu: op1,
            operand_dua: op2,
        }
    }
    pub fn convert_ke_string(&self) -> String {
        format!(
            "Addr: 0x{:x} | Op: {:?} | Ops: {:?}, {:?}",
            self.address_asal, self.operation_code, self.operand_satu, self.operand_dua
        )
    }
}