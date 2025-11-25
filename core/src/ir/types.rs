#[derive(Debug, Clone, PartialEq)]
pub enum TipeOperand {
    Register(String),
    SsaVariable(String, usize), 
    Immediate(i64),
    FloatImmediate(f64),
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
    Mov, Lea, 
    Add, Sub, Imul, Div,
    And, Or, Xor, Shl, Shr,
    Jmp, Je, Jne, Jg, Jge, Jl, Jle,
    Cmp, Test, Call, Ret,
    FAdd, FSub, FMul, FDiv,
    FSqrt, FCmp,
    VecAdd, VecSub, VecMul, VecDiv,
    VecAnd, VecOr, VecXor,
    VecMov, 
    IntToFloat, FloatToInt,
    Nop, Phi, Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TipeDataIr {
    Unknown,
    I8, I16, I32, I64,
    F32, F64,
    V128, V256,
}

#[derive(Debug, Clone)]
pub struct StatementIr {
    pub address_asal: u64,
    pub operation_code: OperasiIr,
    pub operand_satu: TipeOperand,
    pub operand_dua: TipeOperand,
    pub operand_tambahan: Vec<TipeOperand>,
    pub tipe_hasil: TipeDataIr,
}

impl StatementIr {
    pub fn new(addr: u64, op: OperasiIr, op1: TipeOperand, op2: TipeOperand) -> Self {
        Self {
            address_asal: addr,
            operation_code: op,
            operand_satu: op1,
            operand_dua: op2,
            operand_tambahan: Vec::new(),
            tipe_hasil: TipeDataIr::Unknown,
        }
    }
    pub fn with_type(mut self, t: TipeDataIr) -> Self {
        self.tipe_hasil = t;
        self
    }
    pub fn convert_ke_string(&self) -> String {
        format!(
            "Addr: 0x{:x} | Op: {:?} | Ops: {:?}, {:?}",
            self.address_asal, self.operation_code, self.operand_satu, self.operand_dua
        )
    }
}