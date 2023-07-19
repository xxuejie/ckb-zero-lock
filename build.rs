fn main() {
    println!("cargo:rerun-if-changed=binding.c");

    cc::Build::new()
        .file("binding.c")
        .static_flag(true)
        .include("deps/ckb-witness-args-handwritten-reader/c")
        .include("deps/ckb-c-stdlib")
        .include("deps/ckb-c-stdlib/libc")
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
        .define("__SHARED_LIBRARY__", None)
        .compile("binding");
}
