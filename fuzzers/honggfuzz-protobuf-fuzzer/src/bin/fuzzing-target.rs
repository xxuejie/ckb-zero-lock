use honggfuzz::fuzz;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            honggfuzz_protobuf_fuzzer::run(data);
        });
    }
}
