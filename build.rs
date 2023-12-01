fn main() {
    println!("cargo:rerun-if-changed=binding.c");

    let clang = match std::env::var_os("CLANG") {
        Some(val) => val,
        None => "clang-16".into(),
    };

    cc::Build::new()
        .file("binding.c")
        .static_flag(true)
        .include("deps/ckb-witness-args-handwritten-reader/c")
        .include("deps/ckb-c-stdlib")
        .include("deps/ckb-c-stdlib/libc")
        .compiler(clang.clone())
        .no_default_flags(true)
        .flag("--target=riscv64")
        .flag("-march=rv64imc_zba_zbb_zbc_zbs")
        .flag("-O3")
        .flag("-fno-builtin-printf")
        .flag("-fno-builtin-memcmp")
        .flag("-nostdinc")
        .flag("-nostdlib")
        .flag("-fvisibility=hidden")
        .flag("-fdata-sections")
        .flag("-ffunction-sections")
        .flag("-Wall")
        .flag("-Werror")
        .flag("-Wno-unused-parameter")
        .define("__SHARED_LIBRARY__", None)
        .compile("binding");

    cc::Build::new()
        .file("deps/ckb-stack-reorg-bootloader/bootloader.S")
        .static_flag(true)
        .compiler(clang)
        .no_default_flags(true)
        .flag("--target=riscv64")
        .flag("-march=rv64imc_zba_zbb_zbc_zbs")
        .flag("-O3")
        .compile("bootloader");
}
