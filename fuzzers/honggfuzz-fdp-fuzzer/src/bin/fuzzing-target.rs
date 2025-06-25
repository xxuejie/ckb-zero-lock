use honggfuzz::fuzz;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            honggfuzz_fdp_fuzzer::run(data);
        });
    }
}
