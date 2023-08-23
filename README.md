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
$ cargo build --target=riscv64imac-unknown-none-elf --release
```

For release build with debug logs, use:

```
$ RUSTFLAGS="--cfg debug_assertions" cargo build --target=riscv64imac-unknown-none-elf --release
```

To run tests, use the following command:

```
$ cd tests; cargo test
```

By default, the tests use the relase build of the smart contract to run. If you noticed `tests::test_zero_lock_exists` fails, it means the test runner fails to find the default release build binary to use. You can either build the release version of the smart contract, or use the following command to use the debug build:

```
$ cd tests; ZERO_LOCK_PATH=../target/riscv64imac-unknown-none-elf/debug/ckb-zero-lock cargo test
```
