cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
TOP := $(cur_dir)/../..
JOBS := 1
FUZZ_ARGS :=

fuzz:
	HFUZZ_RUN_ARGS="-n $(JOBS) $(FUZZ_ARGS)" \
		cargo hfuzz run fuzzing-target

prepare:
	rustup toolchain install nightly

clean:
	cargo clean
	rm -rf corpus
	rm -rf hfuzz_target hfuzz_workspace

.PHONY: fuzz prepare clean
