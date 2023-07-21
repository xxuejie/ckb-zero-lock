use super::{proof_reader::ProofVisitor, ERROR_CODE_WITNESS_READER};
use blake2b_ref::Blake2b;
use ckb_std::{ckb_constants::Source, debug};
use core::{ffi::c_void, slice::from_raw_parts};

pub type DataAccessor = unsafe extern "C" fn(*const u8, usize, *mut c_void) -> i32;
pub type MetaAccessor = unsafe extern "C" fn(i32, u32, *mut c_void) -> i32;

#[repr(C)]
pub struct Accessors {
    context: *mut c_void,
    lock_meta_accessor: MetaAccessor,
    lock_data_accessor: DataAccessor,
    input_type_meta_accessor: MetaAccessor,
    input_type_data_accessor: DataAccessor,
    output_type_meta_accessor: MetaAccessor,
    output_type_data_accessor: DataAccessor,
}

extern "C" {
    fn cwhr_rust_read_witness(index: usize, source: usize, accessors: *const Accessors) -> i32;
}

struct WitnessVisitor {
    proof: ProofVisitor,
    remainder_hasher: Blake2b,
}

impl WitnessVisitor {
    pub fn new(remainder_hasher: Blake2b) -> Self {
        Self {
            proof: ProofVisitor::default(),
            remainder_hasher,
        }
    }

    pub fn destruct(self) -> (ProofVisitor, Blake2b) {
        (self.proof, self.remainder_hasher)
    }
}

#[no_mangle]
unsafe extern "C" fn visit_lock_meta(present: i32, _length: u32, _context: *mut c_void) -> i32 {
    if present == 0 {
        debug!("Required witness lock is missing!");
        return ERROR_CODE_WITNESS_READER;
    }
    0
}

#[no_mangle]
unsafe extern "C" fn visit_lock_data(data: *const u8, length: usize, context: *mut c_void) -> i32 {
    let data = from_raw_parts(data, length);
    let visitor = &mut *(context as *mut WitnessVisitor);
    visitor.proof.process(data)
}

#[no_mangle]
unsafe extern "C" fn visit_remainder_meta(present: i32, length: u32, context: *mut c_void) -> i32 {
    let visitor = &mut *(context as *mut WitnessVisitor);
    if present != 0 {
        visitor.remainder_hasher.update(&[1u8]);
        visitor.remainder_hasher.update(&length.to_le_bytes());
    } else {
        visitor.remainder_hasher.update(&[0u8]);
    }
    0
}

#[no_mangle]
unsafe extern "C" fn visit_remainder_data(
    data: *const u8,
    length: usize,
    context: *mut c_void,
) -> i32 {
    let data = from_raw_parts(data, length);
    let visitor = &mut *(context as *mut WitnessVisitor);
    visitor.remainder_hasher.update(data);
    0
}

pub fn read_witness(
    index: usize,
    source: Source,
    remainder_hasher: Blake2b,
) -> Option<(ProofVisitor, Blake2b)> {
    let mut visitor = WitnessVisitor::new(remainder_hasher);
    let accessors = Accessors {
        context: &mut visitor as *mut WitnessVisitor as *mut _,
        lock_meta_accessor: visit_lock_meta,
        lock_data_accessor: visit_lock_data,
        input_type_meta_accessor: visit_remainder_meta,
        input_type_data_accessor: visit_remainder_data,
        output_type_meta_accessor: visit_remainder_meta,
        output_type_data_accessor: visit_remainder_data,
    };

    let result =
        unsafe { cwhr_rust_read_witness(index, source as usize, &accessors as *const Accessors) };
    if result != 0 {
        debug!("Error reading witness! Return code: {}", result);
        return None;
    }
    Some(visitor.destruct())
}
