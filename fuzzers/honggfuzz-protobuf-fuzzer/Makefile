cur_dir = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
TOP := $(cur_dir)/../..
TX_GENERATOR := $(TOP)/tests/target/debug/examples/tx_generator
TRACER := ckb-vm-syscall-tracer
CORPUS_COUNT := 10
JOBS := 1
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
	HFUZZ_INPUT=$(cur_dir)/corpus \
		HFUZZ_RUN_ARGS="-n $(JOBS) $(FUZZ_ARGS)" \
		cargo hfuzz run fuzzing-target

prepare:
	rustup toolchain install nightly

clean:
	cargo clean
	rm -rf corpus
	rm -rf hfuzz_target hfuzz_workspace

.PHONY: fuzz prepare clean
