cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
TOP := $(cur_dir)/../..
TX_GENERATOR := $(TOP)/tests/target/debug/examples/tx_generator
TRACER := ckb-vm-syscall-tracer
CORPUS_COUNT := 10
FUZZ_ARGS :=

$(TX_GENERATOR):
	make -C $(TOP) build
	cd $(TOP)/tests; cargo build --examples

corpus: $(TX_GENERATOR)
	mkdir -p corpus
	@for i in `seq 1 $(CORPUS_COUNT)`; do \
		OUTPUT=corpus/$$i.json $(TX_GENERATOR); \
		$(TRACER) -t corpus/$$i.json -o corpus/_data$$i --cell-index 0; \
		mv corpus/_data$$i/vm_0_0.traces corpus/$$i.trace; \
	done
	rm -rf corpus/*.json corpus/_data*	

fuzz: corpus
	cargo afl build
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
