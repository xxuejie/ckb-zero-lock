cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
TOP := $(cur_dir)/../..
FUZZ_ARGS :=

fuzz:
	cargo afl build
	mkdir -p corpus
	# AFL++ requires at least one corpus, we will use a random file
	head -c 1024 < /dev/urandom > corpus/1
	mkdir -p corpus_out
	cargo afl fuzz $(FUZZ_ARGS) \
		-i $(cur_dir)/corpus -o $(cur_dir)/corpus_out \
		target/debug/fuzzing-target

prepare:
	rustup toolchain install nightly

clean:
	cargo clean
	rm -rf corpus corpus_out

.PHONY: fuzz prepare clean
