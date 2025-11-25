use super::Architecture;

pub struct Arm64Arsitektur;

impl Architecture for Arm64Arsitektur {
    fn dapatkan_stack_pointer(&self) -> String {
        "sp".to_string()
    }
    fn dapatkan_frame_pointer(&self) -> String {
        "x29".to_string()
    }
    fn dapatkan_instruction_pointer(&self) -> String {
        "pc".to_string()
    }
    fn dapatkan_register_argumen(&self) -> Vec<String> {
        vec![
            "x0".to_string(), "x1".to_string(), "x2".to_string(), 
            "x3".to_string(), "x4".to_string(), "x5".to_string(),
            "x6".to_string(), "x7".to_string()
        ]
    }
    fn dapatkan_register_return(&self) -> String {
        "x0".to_string()
    }
}