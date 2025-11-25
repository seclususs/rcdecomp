use super::Architecture;

pub struct X86Arsitektur64;

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