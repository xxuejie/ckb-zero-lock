pub fn run(data: &[u8]) -> i8 {
    fdp_ckb_syscalls::entry(data, ckb_zero_lock::program_entry)
}
