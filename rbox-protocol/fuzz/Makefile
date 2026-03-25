# LibFuzzer harness Makefile for rbox-protocol
# Requires: clang++ with LibFuzzer support (e.g., clang 10+)
#
# Usage:
#   make           # Build fuzzer + run quick fuzz test
#   make run-1h    # Run 1-hour fuzz test
#   make replay-crashes CRASHES="crash1 crash2"  # Replay specific crashes
#   make clean     # Remove fuzzer binaries

# Compiler
CXX = clang++
CC = clang

# Flags
SHELL_INCLUDE = -I../../shellsplit/include
CFLAGS = -fsanitize=fuzzer -I../include $(SHELL_INCLUDE) -g -O1 -fno-omit-frame-pointer

# Libraries and Objects
LIB = ../librbox_protocol.a
SHELLSPLIT_OBJ = ../../shellsplit/src/shell_tokenizer.o

# Fuzzer targets
FUZZERS = protocol_fuzzer

# Default target
all: setup-dirs $(FUZZERS)

.PHONY: all clean run run-10m run-1h run-4h minimize replay-crashes replay-all-crashes \
        list-crashes setup-dirs clean-crashes create-seed-corpus help check-prereqs show-options

# Set up required directories
setup-dirs:
	@mkdir -p crashes corpus/interesting
	$(warning Created directories: crashes/ corpus/interesting)

# Build protocol fuzzer - compile as C and link
protocol_fuzzer: protocol_fuzzer.c $(LIB) $(SHELLSPLIT_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB) $(SHELLSPLIT_OBJ) -lm

# Create a seed corpus from a sample input
create-seed-corpus:
	@mkdir -p corpus/seed
	@echo "Sample input" > corpus/seed/sample.txt
	$(warning Created seed corpus: corpus/seed/sample.txt)

# Run fuzzing with memory limits (cgroup, 30 min default)
run-fuzz-cgroup:
	@chmod +x run_fuzzing.sh
	./run_fuzzing.sh

# Run fuzzing with memory limits (custom time)
run-fuzz-cgroup-1h:
	@chmod +x run_fuzzing.sh
	MAX_TIME=3600 ./run_fuzzing.sh

# Run fuzzing with memory limits (custom time)
run-fuzz-cgroup-4h:
	@chmod +x run_fuzzing.sh
	MAX_TIME=14400 ./run_fuzzing.sh

# Quick fuzz (no cgroup, 1 minute)
run-quick:
	./protocol_fuzzer corpus/seed -max_len=4096 -jobs=4 -workers=4 -max_total_time=60

# Run with memory watchdog
run-watchdog:
	@chmod +x memory_watchdog.sh
	./protocol_fuzzer corpus/seed -max_len=4096 -jobs=4 -workers=4 &
	FUZZ_PID=$$!
	WATCHDOG_TARGET_PID=$$FUZZ_PID ./memory_watchdog.sh
	wait $$FUZZ_PID || true

# Run with timeout (10 minutes)
run-10m: protocol_fuzzer
	timeout 600 ./protocol_fuzzer corpus/seed -merge=corpus/interesting -artifact_prefix=crashes/ -max_len=8192 -jobs=4 -workers=4

# Run with timeout (1 hour)
run-1h: protocol_fuzzer
	timeout 3600 ./protocol_fuzzer corpus/seed -merge=corpus/interesting -artifact_prefix=crashes/ -max_len=8192 -jobs=4 -workers=4

# Run with timeout (4 hours)
run-4h: protocol_fuzzer
	timeout 14400 ./protocol_fuzzer corpus/seed -merge=corpus/interesting -artifact_prefix=crashes/ -max_len=8192 -jobs=4 -workers=4

# Minimize corpus
minimize: protocol_fuzzer
	./protocol_fuzzer corpus/interesting -merge=1 -reduce_inputs_to=1000 corpus/minimized

# Clean generated files
clean:
	$(RM) $(FUZZERS)

# Clear crash artifacts
clean-crashes:
	$(RM) -r crashes/*

# Replay crashes - useful for regression testing
replay-crashes: protocol_fuzzer
	@if [ -z "$(CRASHES)" ]; then \
		echo "Error: Please specify CRASHES='file1 file2 ...'"; \
		exit 1; \
	fi
	@for crash in $(CRASHES); do \
		echo "=== Replaying $$crash ==="; \
		./protocol_fuzzer $$crash -runs=1; \
	done

# Replay all crashes found
replay-all-crashes: protocol_fuzzer
	@if ls crashes/protocol_* 1>/dev/null 2>&1; then \
		for crash in crashes/protocol_*; do \
			echo "=== Replaying $$crash ==="; \
			./protocol_fuzzer $$crash -runs=1; \
		done; \
	else \
		echo "No crashes found in crashes/"; \
	fi

# List crashes found
list-crashes:
	@echo "Crash files:"; ls -1 crashes/ 2>/dev/null | wc -l

# Show LibFuzzer options
show-options:
	./protocol_fuzzer -help=1

# Check prerequisites
check-prereqs:
ifneq ($(shell $(CC) --version 2>/dev/null | grep -q "clang" && echo 1 || echo 0),1)
	$(error LibFuzzer requires clang++ with fuzzing support)
endif

# Help target
help:
	@echo "Available targets:"
	@echo "  all             - Build fuzzer + run quick fuzz test (default)"
	@echo "  setup-dirs      - Set up required directories (crashes/, corpus/)"
	@echo "  create-seed-corpus - Create a seed corpus"
	@echo "  run-quick       - Run quick fuzz test (1 minute)"
	@echo "  run-10m         - Run 10-minute fuzz test"
	@echo "  run-1h          - Run 1-hour fuzz test"
	@echo "  run-4h          - Run 4-hour fuzz test"
	@echo "  minimize        - Minimize corpus"
	@echo "  replay-crashes  - Replay specific crashes (CRASHES='file1 file2 ...')"
	@echo "  replay-all-crashes - Replay all crashes found"
	@echo "  list-crashes    - List crashes found"
	@echo "  clean           - Remove fuzzer binaries"
	@echo "  clean-crashes   - Clear crash artifacts"
