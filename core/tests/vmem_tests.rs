use rcdecomp_core::loader::vmem::{VirtualMemory, IzinAkses};

fn create_dummy_vmem() -> VirtualMemory {
    VirtualMemory::baru(0x1000, "x86_64", "raw")
}

#[test]
fn test_izin_akses_conversion() {
    assert_eq!(IzinAkses::from_u32(1), IzinAkses::Read, "1 harus map ke Read");
    assert_eq!(IzinAkses::from_u32(2), IzinAkses::Write, "2 harus map ke Write");
    assert_eq!(IzinAkses::from_u32(4), IzinAkses::Execute, "4 harus map ke Execute");
    assert_eq!(IzinAkses::from_u32(5), IzinAkses::ReadExecute, "5 harus map ke ReadExecute");
    assert_eq!(IzinAkses::from_u32(7), IzinAkses::Full, "7 harus map ke Full");
    assert_eq!(IzinAkses::from_u32(0), IzinAkses::None, "0 harus map ke None");
    assert_eq!(IzinAkses::from_u32(99), IzinAkses::None, "Nilai random harus fallback ke None");
}

#[test]
fn test_segment_management_ordering() {
    let mut vmem = create_dummy_vmem();
    let data_dummy = vec![0x90; 16];
    vmem.tambah_segment(0x3000, data_dummy.clone(), IzinAkses::Read, ".rodata".to_string());
    vmem.tambah_segment(0x1000, data_dummy.clone(), IzinAkses::Execute, ".text".to_string());
    vmem.tambah_segment(0x5000, data_dummy.clone(), IzinAkses::ReadWrite, ".data".to_string());
    vmem.tambah_segment(0x2000, data_dummy.clone(), IzinAkses::None, ".padding".to_string());
    assert_eq!(vmem.segments.len(), 4);
    assert_eq!(vmem.segments[0].start_addr, 0x1000);
    assert_eq!(vmem.segments[0].nama_section, ".text");
    assert_eq!(vmem.segments[1].start_addr, 0x2000);
    assert_eq!(vmem.segments[2].start_addr, 0x3000);
    assert_eq!(vmem.segments[3].start_addr, 0x5000);
}

#[test]
fn test_reading_byte() {
    let mut vmem = create_dummy_vmem();
    let data = vec![0x00, 0x01, 0x02, 0x03]; 
    vmem.tambah_segment(0x1000, data, IzinAkses::Read, "test_seg".to_string());
    assert_eq!(vmem.baca_byte(0x1000), Some(0x00));
    assert_eq!(vmem.baca_byte(0x1002), Some(0x02));
    assert_eq!(vmem.baca_byte(0x1003), Some(0x03));
    assert_eq!(vmem.baca_byte(0xFFF), None);
    assert_eq!(vmem.baca_byte(0x1004), None);
    assert_eq!(vmem.baca_byte(0x999999), None);
}

#[test]
fn test_reading_array() {
    let mut vmem = create_dummy_vmem();
    vmem.tambah_segment(0x1000, vec![0xA, 0xB, 0xC, 0xD], IzinAkses::Read, "seg1".to_string());
    vmem.tambah_segment(0x1004, vec![0xE, 0xF, 0x1, 0x2], IzinAkses::Read, "seg2".to_string());
    assert_eq!(vmem.baca_array(0x1000, 2), Some(vec![0xA, 0xB]));
    assert_eq!(vmem.baca_array(0x1002, 2), Some(vec![0xC, 0xD]));
    assert_eq!(vmem.baca_array(0x1000, 4), Some(vec![0xA, 0xB, 0xC, 0xD]));
    assert_eq!(vmem.baca_array(0x1002, 4), None, "Harus fail (None) jika array menyeberang batas segmen fisik");
    assert_eq!(vmem.baca_array(0x1000, 5), None);
}

#[test]
fn test_permissions_filtering() {
    let mut vmem = create_dummy_vmem();
    let code = vec![0x90, 0x90];
    vmem.tambah_segment(0x1000, code.clone(), IzinAkses::Read, "rodata".to_string());
    vmem.tambah_segment(0x2000, code.clone(), IzinAkses::Write, "bss".to_string());
    vmem.tambah_segment(0x3000, code.clone(), IzinAkses::Execute, "text_exec_only".to_string());
    vmem.tambah_segment(0x4000, code.clone(), IzinAkses::ReadExecute, "text_rx".to_string());
    vmem.tambah_segment(0x5000, code.clone(), IzinAkses::Full, "rwx_shellcode".to_string());
    vmem.tambah_segment(0x6000, code.clone(), IzinAkses::ReadWrite, "data".to_string());
    let exec_regions = vmem.ambil_executable_regions();
    assert_eq!(exec_regions.len(), 3);
    let addresses: Vec<u64> = exec_regions.iter().map(|(addr, _)| *addr).collect();
    assert!(addresses.contains(&0x3000));
    assert!(addresses.contains(&0x4000));
    assert!(addresses.contains(&0x5000));
    assert!(!addresses.contains(&0x1000));
    assert!(!addresses.contains(&0x2000));
    assert!(!addresses.contains(&0x6000));
}

#[test]
fn test_boundary_search_logic() {
    let mut vmem = create_dummy_vmem();
    vmem.tambah_segment(0x1000, vec![0; 16], IzinAkses::Read, "A".to_string());
    vmem.tambah_segment(0x2000, vec![0; 16], IzinAkses::Read, "B".to_string());
    assert!(vmem.baca_byte(0x1000).is_some());
    assert!(vmem.baca_byte(0x100F).is_some());
    assert!(vmem.baca_byte(0x1010).is_none());
    assert!(vmem.baca_byte(0x1500).is_none());
    assert!(vmem.baca_byte(0x2000).is_some());
}