pub fn run(data: &[u8]) -> i8 {
    protobuf_ckb_syscalls::entry(data, ckb_zero_lock::program_entry)
}
