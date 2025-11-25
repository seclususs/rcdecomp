use std::collections::HashMap;
use crate::ir::types::{TipeOperand, OperasiIr, StatementIr};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MemoryRegion {
    Global(u64),      
    Stack(i64),       
    Heap,             
    Unknown,          
}

pub struct AliasAnalyzer {
    pointer_analysis: HashMap<String, MemoryRegion>,
    heap_sources: HashMap<String, bool>, 
}

impl AliasAnalyzer {
    pub fn new() -> Self {
        Self {
            pointer_analysis: HashMap::new(),
            heap_sources: HashMap::new(),
        }
    }
    pub fn analisis_pointer(&mut self, stmts: &[StatementIr], frame_pointer: &str) {
        for stmt in stmts {
            match stmt.operation_code {
                OperasiIr::Call => {
                    let is_malloc = if let TipeOperand::Immediate(_addr) = stmt.operand_satu {
                        true 
                    } else {
                        false
                    };
                    if is_malloc {
                        self.heap_sources.insert("rax".to_string(), true);
                        self.heap_sources.insert("x0".to_string(), true);
                    }
                },
                OperasiIr::Mov | OperasiIr::Lea | OperasiIr::Add => {
                    if let TipeOperand::SsaVariable(dest, _) = &stmt.operand_satu {
                        let region = self.infer_region(&stmt.operand_dua, frame_pointer);
                        if region != MemoryRegion::Unknown {
                            self.pointer_analysis.insert(dest.clone(), region);
                        }
                    } else if let TipeOperand::Register(dest) = &stmt.operand_satu {
                         let region = self.infer_region(&stmt.operand_dua, frame_pointer);
                         if region != MemoryRegion::Unknown {
                             self.pointer_analysis.insert(dest.clone(), region);
                         }
                    }
                },
                _ => {}
            }
        }
    }
    pub fn infer_region(&self, op: &TipeOperand, frame_pointer: &str) -> MemoryRegion {
        match op {
            TipeOperand::Memory(addr) => MemoryRegion::Global(*addr),
            TipeOperand::MemoryRef { base, offset } => {
                if base == frame_pointer {
                    MemoryRegion::Stack(*offset)
                } else if self.is_heap_base(base) {
                    MemoryRegion::Heap
                } else {
                    MemoryRegion::Unknown
                }
            },
            TipeOperand::Immediate(val) => MemoryRegion::Global(*val as u64),
            TipeOperand::SsaVariable(name, _) => {
                self.pointer_analysis.get(name).cloned().unwrap_or(MemoryRegion::Unknown)
            },
            TipeOperand::Register(name) => {
                if self.heap_sources.contains_key(name) {
                    return MemoryRegion::Heap;
                }
                self.pointer_analysis.get(name).cloned().unwrap_or(MemoryRegion::Unknown)
            }
            _ => MemoryRegion::Unknown,
        }
    }
    fn is_heap_base(&self, base: &str) -> bool {
        self.heap_sources.contains_key(base) || 
        self.pointer_analysis.get(base) == Some(&MemoryRegion::Heap)
    }
    pub fn may_alias(&self, op1: &TipeOperand, op2: &TipeOperand, frame_pointer: &str) -> bool {
        let r1 = self.infer_region(op1, frame_pointer);
        let r2 = self.infer_region(op2, frame_pointer);
        match (r1, r2) {
            (MemoryRegion::Stack(off1), MemoryRegion::Stack(off2)) => off1 == off2,
            (MemoryRegion::Global(addr1), MemoryRegion::Global(addr2)) => addr1 == addr2,
            (MemoryRegion::Stack(_), MemoryRegion::Global(_)) => false,
            (MemoryRegion::Global(_), MemoryRegion::Stack(_)) => false,
            (MemoryRegion::Heap, MemoryRegion::Stack(_)) => false,
            (MemoryRegion::Stack(_), MemoryRegion::Heap) => false,
            (MemoryRegion::Global(_), MemoryRegion::Heap) => false,
            (MemoryRegion::Heap, MemoryRegion::Global(_)) => false,
            (MemoryRegion::Unknown, _) => true,
            (_, MemoryRegion::Unknown) => true,
            (MemoryRegion::Heap, MemoryRegion::Heap) => true,
        }
    }
}