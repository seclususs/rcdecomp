use std::collections::{HashMap, BTreeMap};
use crate::analysis::type_inference::{TypeSystem, SignatureFungsi, TipePrimitif};

pub struct StdLibManager {
    database_signature: HashMap<String, SignatureFungsi>,
}

impl StdLibManager {
    pub fn new() -> Self {
        let mut db = HashMap::new();
        db.insert("malloc".to_string(), SignatureFungsi {
            return_type: TipePrimitif::Pointer(Box::new(TipePrimitif::Void)),
            arg_types: vec![TipePrimitif::Integer(8)], 
        });
        db.insert("free".to_string(), SignatureFungsi {
            return_type: TipePrimitif::Void,
            arg_types: vec![TipePrimitif::Pointer(Box::new(TipePrimitif::Void))],
        });
        db.insert("printf".to_string(), SignatureFungsi {
            return_type: TipePrimitif::Integer(4),
            arg_types: vec![TipePrimitif::Pointer(Box::new(TipePrimitif::Integer(1)))], 
        });
        db.insert("memcpy".to_string(), SignatureFungsi {
            return_type: TipePrimitif::Pointer(Box::new(TipePrimitif::Void)),
            arg_types: vec![
                TipePrimitif::Pointer(Box::new(TipePrimitif::Void)),
                TipePrimitif::Pointer(Box::new(TipePrimitif::Void)),
                TipePrimitif::Integer(8)
            ],
        });
        db.insert("strlen".to_string(), SignatureFungsi {
            return_type: TipePrimitif::Integer(8),
            arg_types: vec![TipePrimitif::Pointer(Box::new(TipePrimitif::Integer(1)))],
        });
        Self { database_signature: db }
    }
    pub fn terapkan_signature_standar(&self, simbol_global: &BTreeMap<u64, String>, type_sys: &mut TypeSystem) {
        for (addr, nama_raw) in simbol_global {
            let nama_bersih = self.bersihkan_nama_simbol(nama_raw);
            if let Some(sig) = self.database_signature.get(&nama_bersih) {
                type_sys.global_signatures.insert(*addr, sig.clone());
            }
        }
    }
    fn bersihkan_nama_simbol(&self, raw: &str) -> String {
        let tanpa_underscore = raw.strip_prefix("_").unwrap_or(raw);
        let base_name = tanpa_underscore.split('@').next().unwrap_or(tanpa_underscore);
        base_name.to_string()
    }
}