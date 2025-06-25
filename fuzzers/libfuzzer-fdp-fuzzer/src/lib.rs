// To use cargo-fuzz, we have to wrap the fuzzer as a lib crate, and use the fuzzer
// lib crate in one of the fuzzing target.
pub fn run(data: &[u8]) -> i8 {
    fdp_ckb_syscalls::entry(data, ckb_zero_lock::program_entry)
}
