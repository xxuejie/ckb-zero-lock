#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    libfuzzer_fdp_fuzzer::run(data);
});
