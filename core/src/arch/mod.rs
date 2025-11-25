pub mod x86;

pub trait Architecture {
    fn dapatkan_stack_pointer(&self) -> String;
    fn dapatkan_frame_pointer(&self) -> String;
    fn dapatkan_instruction_pointer(&self) -> String;
    fn dapatkan_register_argumen(&self) -> Vec<String>;
    fn dapatkan_register_return(&self) -> String;
}