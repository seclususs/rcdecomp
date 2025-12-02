use super::Architecture;

pub const EFLAGS_CF_MASK: u64 = 0x0001;
pub const EFLAGS_PF_MASK: u64 = 0x0004;
pub const EFLAGS_AF_MASK: u64 = 0x0010;
pub const EFLAGS_ZF_MASK: u64 = 0x0040;
pub const EFLAGS_SF_MASK: u64 = 0x0080;
pub const EFLAGS_TF_MASK: u64 = 0x0100;
pub const EFLAGS_IF_MASK: u64 = 0x0200;
pub const EFLAGS_DF_MASK: u64 = 0x0400;
pub const EFLAGS_OF_MASK: u64 = 0x0800;

pub struct X86Arsitektur64;

impl X86Arsitektur64 {
    pub fn ambil_flag_penting() -> u64 {
        EFLAGS_CF_MASK | EFLAGS_PF_MASK | EFLAGS_ZF_MASK | EFLAGS_SF_MASK | EFLAGS_OF_MASK
    }
}

impl Architecture for X86Arsitektur64 {
    fn dapatkan_stack_pointer(&self) -> String {
        "rsp".to_string()
    }
    fn dapatkan_frame_pointer(&self) -> String {
        "rbp".to_string()
    }
    fn dapatkan_instruction_pointer(&self) -> String {
        "rip".to_string()
    }
    fn dapatkan_register_argumen(&self) -> Vec<String> {
        vec![
            "rdi".to_string(), "rsi".to_string(), "rdx".to_string(), 
            "rcx".to_string(), "r8".to_string(), "r9".to_string()
        ]
    }
    fn dapatkan_register_return(&self) -> String {
        "rax".to_string()
    }
}