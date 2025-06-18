fn main() {
    println!("cargo:rerun-if-changed=binding.c");

    let clang = match std::env::var_os("TARGET_CC") {
        Some(val) => val,
        None => "clang-18".into(),
    };

    let mut build = cc::Build::new();
    build
        .file("binding.c")
        .include("deps/ckb-witness-args-handwritten-reader/c")
        .include("deps/ckb-c-stdlib")
        .static_flag(true)
        .flag("-O3")
        .flag("-fvisibility=hidden")
        .flag("-fdata-sections")
        .flag("-ffunction-sections")
        .flag("-Wall")
        .flag("-Werror");

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    if target_arch == "riscv64" {
        build
            .include("deps/ckb-c-stdlib/libc")
            .compiler(clang)
            .no_default_flags(true)
            .flag("--target=riscv64")
            .flag("-march=rv64imc_zba_zbb_zbc_zbs")
            .flag("-fno-builtin-printf")
            .flag("-fno-builtin-memcmp")
            .flag("-nostdinc")
            .flag("-nostdlib")
            .flag("-Wno-unused-parameter")
            .define("__SHARED_LIBRARY__", None);
    }

    build.compile("binding");
}
