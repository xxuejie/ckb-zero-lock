# ckb-zero-lock

Zero lock is a newly designed lock script, that relies on hardforks to control the upgradating of smart contracts.

# How to Use

```
$ git clone --recursive https://github.com/xxuejie/ckb-zero-lock
$ cd ckb-zero-lock
$ # Install riscv64 Rust target if you haven't done so already:
$ rustup target add riscv64imac-unknown-none-elf
$ cargo build --target=riscv64imac-unknown-none-elf
```

For release build, use:

```
$ make build
```

If you are using a different clang version:

```
$ make build CLANG=clang-19
```

To run tests, use the following command:

```
$ make test
```

For more usages, refer to [ckb-script-templates](https://github.com/cryptape/ckb-script-templates?tab=readme-ov-file#standalone-contract-crate)
