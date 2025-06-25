#![no_std]

extern crate alloc;

use ckb_std::{
    ckb_constants::Source, ckb_types::prelude::Entity, debug, error::SysError, high_level, syscalls,
};

use blake2b_ref::Blake2bBuilder;
use merkle_cbt::merkle_tree::Merge;

mod proof_reader;
mod witness_reader;

pub const ERROR_CODE_WITNESS_READER: i32 = -70;
pub const ERROR_CODE_PROOF_READER: i32 = -71;

#[derive(Debug, Default, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct Data([u8; 32]);

impl Data {
    fn from_slice(data: &[u8]) -> Self {
        assert_eq!(data.len(), 32);
        let mut d = [0u8; 32];
        d.copy_from_slice(data);
        Self(d)
    }

    fn new(data: [u8; 32]) -> Self {
        Self(data)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

#[derive(Debug)]
struct Blake2bHash;

impl Merge for Blake2bHash {
    type Item = Data;

    fn merge(lhs: &Self::Item, rhs: &Self::Item) -> Self::Item {
        let mut hasher = Blake2bBuilder::new(32)
            .personal(b"ckb-default-hash")
            .build();
        hasher.update(&lhs.as_bytes());
        hasher.update(&rhs.as_bytes());
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash[..]);
        Data::new(hash)
    }
}

pub fn program_entry() -> i8 {
    match run() {
        Ok(()) => 0,
        Err(e) => {
            debug!("System error: {:?}", e);
            let _ = e;
            -61
        }
    }
}

pub fn run() -> Result<(), SysError> {
    // Only one input cell can use zero lock
    if high_level::load_cell_lock_hash(1, Source::GroupInput) != Err(SysError::IndexOutOfBound) {
        debug!("More than one input cell uses zero lock!");
        return Err(SysError::Unknown(1));
    }
    // Only one output cell can use zero lock, since output locks are not
    // considered in script groups for current transaction, we will need to
    // manually iterate over all of them.
    let current_script_hash = high_level::load_script_hash()?;
    let mut i = 0;
    let mut output_index = None;
    loop {
        match high_level::load_cell_lock_hash(i, Source::Output) {
            Ok(hash) => {
                if hash == current_script_hash {
                    if output_index.is_some() {
                        debug!("More than one output cell uses zero lock!");
                        return Err(SysError::Unknown(2));
                    } else {
                        output_index = Some(i);
                    }
                }
            }
            Err(SysError::IndexOutOfBound) => break,
            e => {
                debug!("Lock hash loading error: {:?}", e);
                let _ = e;
                return Err(SysError::Unknown(3));
            }
        }
        i += 1;
    }
    if output_index.is_none() {
        debug!("No output cell uses zero lock!");
        return Err(SysError::Unknown(4));
    }
    let output_index = output_index.unwrap();

    // Generate the leaf we need from concatenation of the following bytes:
    //
    // * Byte 0x01, as version for future changes
    // * Zero lock input cell’s OutPoint
    // * Zero lock output cell’s data hash
    // * Zero lock output cell’s CellOutput structure
    // * Byte 0x01 if witness has input_type field, byte 0x00 otherwise
    // * (If input_type exists) Length of input_type as little-endian u32
    // * (If input_type exists) Content of input_type field
    // * Byte 0x01 if witness has output_type field, byte 0x00 otherwise
    // * (If output_type exists) Length of output_type as little-endian u32
    // * (If output_type exists) Content of output_type field
    let mut hasher = Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    hasher.update(&[1u8]);
    hasher.update(high_level::load_input_out_point(0, Source::GroupInput)?.as_slice());
    hasher.update(&high_level::load_cell_data_hash(
        output_index,
        Source::Output,
    )?);
    let mut loaded = 0;
    let mut buf = [0u8; 4096];
    loop {
        match syscalls::load_cell(&mut buf, loaded, output_index, Source::Output) {
            Ok(actual_loaded_len) => {
                hasher.update(&buf[..actual_loaded_len]);
                break;
            }
            Err(SysError::LengthNotEnough(_total_length)) => {
                hasher.update(&buf);
                loaded += buf.len();
            }
            Err(e) => {
                debug!("Error loading first output cell: {:?}", e);
                let _ = e;
                return Err(SysError::Unknown(7));
            }
        }
    }

    // Read the following data from witness:
    //
    // * Index of header to load merkle root
    // * Merkle proof
    // * Remainder of witness data (input_type, output_type) so we can ensure non-malleability
    let Some((proof_visitor, hasher)) = witness_reader::read_witness(0, Source::GroupInput, hasher)
    else {
        debug!("parsing witness failure!");
        return Err(SysError::Unknown(9));
    };
    let Some((header_index, merkle_proof)) = proof_visitor.build::<Blake2bHash>() else {
        debug!("parsing merkle proof failure!");
        return Err(SysError::Unknown(10));
    };

    // Now we have all the data for the hasher, we can build the actual merkle leaf.
    let mut leaf = [0u8; 32];
    hasher.finalize(&mut leaf[..]);
    let leaf = Data::new(leaf);

    // Find merkle root from extension field at offset 128 in the designated header
    let mut merkle_root = [0u8; 32];
    match syscalls::load_block_extension(
        &mut merkle_root,
        128,
        header_index as usize,
        Source::HeaderDep,
    ) {
        Ok(n) => {
            if n != 32 {
                debug!("Extension does not have enough data for merkle root!");
                return Err(SysError::Unknown(5));
            }
        }
        Err(SysError::LengthNotEnough(_)) => (),
        e => {
            debug!("Error loading merkle root from extension: {:?}", e);
            let _ = e;
            return Err(SysError::Unknown(6));
        }
    }
    let merkle_root = Data::new(merkle_root);

    // Actual merkle proof verification
    let Some(actual_root) = merkle_proof.root(&[leaf]) else {
        debug!("no root");
        return Err(SysError::Unknown(11));
    };
    if actual_root != merkle_root {
        debug!(
            "Merkle proof failure! Actual root: {:?}, expected root: {:?}",
            actual_root, merkle_root
        );
        return Err(SysError::Unknown(8));
    }

    Ok(())
}
