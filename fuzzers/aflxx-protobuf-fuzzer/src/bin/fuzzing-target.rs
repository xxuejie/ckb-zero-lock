use afl::fuzz;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            aflxx_protobuf_fuzzer::run(data);
        });
    }
}
