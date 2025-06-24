cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
TOP := $(cur_dir)/../..
TX_GENERATOR := $(TOP)/tests/target/debug/examples/tx_generator
TRACER := ckb-vm-syscall-tracer
CORPUS_COUNT := 10
JOBS := 1

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
	cargo +nightly fuzz run --jobs $(JOBS) fuzzing_target $(cur_dir)/corpus --

prepare:
	rustup toolchain install nightly

clean:
	cargo clean
	cd fuzz; cargo clean
	rm -rf corpus

.PHONY: fuzz prepare clean
