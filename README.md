# ckb-zero-lock

Zero lock is a newly designed lock script, that relies on hardforks to control the upgradating of smart contracts.

# How to Use

The contract uses [ckb-contract-toolchain](https://github.com/xxuejie/ckb-contract-toolchains) to build by default. ckb-contract-toolchain is a Rust toolchain customized for Nervos CKB smart contract development.

When you have [rustup](https://rustup.rs/) installed, use the following command to install the correct toolchain:

```
$ curl https://raw.githubusercontent.com/xxuejie/ckb-contract-toolchains/c4b3a52e2f47fcdeb9f7b663f193fec506f7e158/install.sh | bash -s -- 20230710-1
```

Now you can clone and build the contract:

```
$ git clone --recursive https://github.com/xxuejie/ckb-zero-lock
$ cd ckb-zero-lock
$ cargo build --target=riscv64imac_zba_zbb_zbc_zbs-unknown-ckb-elf
```

For release build, use:

```
$ cargo build --target=riscv64imac_zba_zbb_zbc_zbs-unknown-ckb-elf --release
```

For release build with debug logs, use:

```
$ RUSTFLAGS="--cfg debug_assertions" cargo build --target=riscv64imac_zba_zbb_zbc_zbs-unknown-ckb-elf --release
```

To run tests, use the following command:

```
$ cd tests; cargo test
```

By default, the tests use the relase build of the smart contract to run. If you noticed `tests::test_zero_lock_exists` fails, it means the test runner fails to find the default release build binary to use. You can either build the release version of the smart contract, or use the following command to use the debug build:

```
$ cd tests; ZERO_LOCK_PATH=../target/riscv64imac_zba_zbb_zbc_zbs-unknown-ckb-elf/debug/ckb-zero-lock cargo test
```
