cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
TOP := $(cur_dir)/../..
JOBS := 1
FUZZ_ARGS :=

fuzz:
	cargo +nightly fuzz run --jobs $(JOBS) fuzzing_target -- $(FUZZ_ARGS)

prepare:
	rustup toolchain install nightly

clean:
	cargo clean
	cd fuzz; cargo clean
	rm -rf fuzz/artifacts fuzz/corpus

.PHONY: fuzz prepare clean
