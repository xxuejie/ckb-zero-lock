#![no_std]
#![cfg_attr(not(test), no_main)]

ckb_std::entry!(entry);
ckb_std::default_alloc!();

pub fn entry() -> i8 {
    ckb_zero_lock::program_entry()
}
