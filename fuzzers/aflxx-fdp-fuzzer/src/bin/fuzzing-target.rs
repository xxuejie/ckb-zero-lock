use afl::fuzz;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            aflxx_fdp_fuzzer::run(data);
        });
    }
}
