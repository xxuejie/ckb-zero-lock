#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

use ckb_std::{ckb_constants::Source, debug, default_alloc, error::SysError, high_level, syscalls};

ckb_std::entry!(program_entry);
default_alloc!();

use alloc::{vec, vec::Vec};
use blake2b_ref::Blake2bBuilder;
use merkle_cbt::merkle_tree::Merge;

mod proof_reader;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Data(Vec<u8>);

impl Data {
    pub fn from_slice(s: &[u8]) -> Self {
        Data(s.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
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
        Data::from_slice(&hash)
    }
}

pub fn program_entry() -> i8 {
    match run() {
        Ok(()) => 0,
        Err(e) => {
            debug!("System error: {:?}", e);
            -61
        }
    }
}

pub fn run() -> Result<(), SysError> {
    let current_script_hash = high_level::load_script_hash()?;
    // The first input / output cell must use zero lock
    if high_level::load_cell_lock_hash(0, Source::Input)? != current_script_hash {
        debug!("The first input cell does not use zero lock!");
        return Err(SysError::Unknown(1));
    }
    if high_level::load_cell_lock_hash(0, Source::Output)? != current_script_hash {
        debug!("The first output cell does not use zero lock!");
        return Err(SysError::Unknown(2));
    }
    // Only one input / output cell can use zero lock
    if high_level::load_cell_lock_hash(1, Source::GroupInput) != Err(SysError::IndexOutOfBound) {
        debug!("More than one input cell uses zero lock!");
        return Err(SysError::Unknown(3));
    }
    if high_level::load_cell_lock_hash(1, Source::GroupOutput) != Err(SysError::IndexOutOfBound) {
        debug!("More than one output cell uses zero lock!");
        return Err(SysError::Unknown(4));
    }

    // Find merkle root from extension field at offset 128 in the first header
    let mut merkle_root = [0u8; 32];
    if syscalls::load_extension(&mut merkle_root, 128, 0, Source::HeaderDep)? != 32 {
        debug!("Error loading merkle root from extension!");
        return Err(SysError::Unknown(5));
    }
    let merkle_root = Data::from_slice(&merkle_root);

    // Load merkle proof from lock field in witness from the first input cell
    let merkle_proof = proof_reader::parse_merkle_proof::<Blake2bHash>(0, Source::Input)
        .expect("parsing merkle proof failure!");
    debug!(
        "Merkle proof indices len: {}, lemmas len: {}",
        merkle_proof.indices().len(),
        merkle_proof.lemmas().len()
    );

    // Generate the leaf we need:
    //
    // 01 + (the first input cell’s data hash) + (the first output cell’s data hash) +
    // (the first output cell’s CellOutput structure)
    let mut leaf = vec![0x01];
    leaf.extend(high_level::load_cell_data_hash(0, Source::Input)?);
    leaf.extend(high_level::load_cell_data_hash(0, Source::Output)?);
    let mut loaded = 0;
    let mut buf = [0u8; 4096];
    loop {
        match syscalls::load_cell(&mut buf, loaded, 0, Source::Output) {
            Ok(actual_loaded_len) => {
                leaf.extend(&buf[..actual_loaded_len]);
                break;
            }
            Err(SysError::LengthNotEnough(_total_length)) => {
                leaf.extend(&buf);
                loaded += 4096;
            }
            Err(e) => {
                debug!("Error loading first output cell: {:?}", e);
                return Err(SysError::Unknown(6));
            }
        }
    }

    let leaves = vec![Data::from_slice(&leaf)];

    // Actual merkle proof verification
    let actual_root = merkle_proof.root(&leaves).expect("no root");
    if actual_root != merkle_root {
        debug!(
            "Merkle proof failure! Actual root: {:?}, expected root: {:?}",
            actual_root, merkle_root
        );
        return Err(SysError::Unknown(7));
    }

    Ok(())
}
