# LibFuzzer harness Makefile for c-dfa
# Requires: libfuzzer-21-dev (clang with fuzzing support)

CXX = clang++
CC = clang

CXXFLAGS = -fsanitize=fuzzer,address,undefined -I../include -g -O1 -fno-omit-frame-pointer
CFLAGS = -fsanitize=fuzzer,address,undefined -I../include -g -O1 -fno-omit-frame-pointer

# Library sources (from c-dfa/src and tools)
LIB_SRC = ../src/dfa_eval.c ../src/dfa_loader.c
LIB_OBJS = $(patsubst %.c,%.o,$(LIB_SRC))

# Pattern parser sources (optional - requires linking nfa_builder components)
PATTERN_SRC = ../tools/nfa_builder.c ../tools/multi_target_array.c
PATTERN_OBJS = $(patsubst %.c,%.o,$(PATTERN_SRC))

FUZZERS = dfa_eval_fuzzer pattern_parse_fuzzer nfa_build_fuzzer

# Default target
all: setup-dirs $(FUZZERS)

# Set up required directories
setup-dirs:
	@mkdir -p crashes corpus/interesting/dfa_eval corpus/interesting/pattern_parser corpus/interesting/nfa_build

# DFA evaluation fuzzer (requires wrapper binary)
dfa_eval_fuzzer: dfa_eval_fuzzer.cpp $(LIB_OBJS) ../tools/dfa_eval_wrapper
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIB_OBJS) -lm

# Build the DFA eval wrapper (needed for fuzzing)
../tools/dfa_eval_wrapper: ../tools/dfa_eval_wrapper.c ../src/dfa_eval.c ../src/dfa_loader.c ../include/*.h
	$(MAKE) -C .. tools/dfa_eval_wrapper

# Pattern parser fuzzer - uses external nfa_builder process
pattern_parse_fuzzer: pattern_parse_fuzzer.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< -lm

# NFA build fuzzer - tests actual NFA construction (not just validation)
nfa_build_fuzzer: nfa_build_fuzzer.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< -lm

# Build library objects
../src/dfa_eval.o: ../src/dfa_eval.c ../include/dfa.h ../include/dfa_types.h
	$(CC) $(CFLAGS) -c $< -o $@

../src/dfa_loader.o: ../src/dfa_loader.c ../include/dfa.h ../include/dfa_types.h
	$(CC) $(CFLAGS) -c $< -o $@

../tools/nfa_builder.o: ../tools/nfa_builder.c ../include/nfa.h
	$(CC) $(CFLAGS) -c $< -o $@

../tools/multi_target_array.o: ../tools/multi_target_array.c ../tools/multi_target_array.h
	$(CC) $(CFLAGS) -c $< -o $@

# Run fuzzing with corpus
run-dfa: dfa_eval_fuzzer
	./dfa_eval_fuzzer corpus/seed/dfa_eval -merge=corpus/interesting/dfa_eval -artifact_prefix=crashes/dfa_eval_ -max_len=4096 -jobs=4 -workers=4

# Run with dictionary
run-dfa-dict: dfa_eval_fuzzer
	./dfa_eval_fuzzer corpus/seed/dfa_eval -merge=corpus/interesting/dfa_eval -artifact_prefix=crashes/dfa_eval_ -dict=cmd_dict.txt -max_len=4096 -jobs=4 -workers=4

# Run pattern parser fuzzing
run-pattern: pattern_parse_fuzzer
	./pattern_parse_fuzzer corpus/seed/pattern_parser -merge=corpus/interesting/pattern_parser -artifact_prefix=crashes/pattern_parse_ -max_len=8192 -jobs=4 -workers=4

# Run NFA build fuzzing (tests actual NFA construction, not just validation)
run-nfa-build: nfa_build_fuzzer
	./nfa_build_fuzzer corpus/seed/pattern_parser -merge=corpus/interesting/nfa_build -artifact_prefix=crashes/nfa_build_ -max_len=32768 -jobs=2 -workers=2

# Cgroup-wrapped versions with OS-level memory limits
# Usage: FUZZ_MEMORY_LIMIT=4G make run-dfa-cgroup
run-dfa-cgroup: dfa_eval_fuzzer
	./run_in_cgroup.sh ./dfa_eval_fuzzer corpus/seed/dfa_eval -merge=corpus/interesting/dfa_eval -artifact_prefix=crashes/dfa_eval_ -max_len=4096 -jobs=4 -workers=4

run-pattern-cgroup: pattern_parse_fuzzer
	./run_in_cgroup.sh ./pattern_parse_fuzzer corpus/seed/pattern_parser -merge=corpus/interesting/pattern_parser -artifact_prefix=crashes/pattern_parse_ -max_len=8192 -jobs=4 -workers=4

run-nfa-build-cgroup: nfa_build_fuzzer
	./run_in_cgroup.sh ./nfa_build_fuzzer corpus/seed/pattern_parser -merge=corpus/interesting/nfa_build -artifact_prefix=crashes/nfa_build_ -max_len=32768 -jobs=2 -workers=2

# Merge new corpus inputs
merge: dfa_eval_fuzzer
	./dfa_eval_fuzzer corpus/dfa_eval -merge=1 corpus/dfa_eval_merged -max_len=4096

# Minimize corpus
minimize: dfa_eval_fuzzer
	./dfa_eval_fuzzer corpus/dfa_eval -merge=1 -reduce_inputs_to=1000 corpus/dfa_eval_min

# Clean generated files
clean:
	rm -f $(FUZZERS) $(LIB_OBJS) $(PATTERN_OBJS)

# Clear crash artifacts (useful after bug fixes)
clean-crashes:
	rm -rf crashes/*

# Replay crashes - useful for regression testing
# Usage: make replay-crashes-dfa CRASHES="crashes/dfa_eval_abc123 crashes/dfa_eval_def456"
replay-crashes-dfa: dfa_eval_fuzzer
	@if [ -z "$(CRASHES)" ]; then \
		echo "Error: Please specify CRASHES='file1 file2 ...'"; \
		echo "Example: make replay-crashes-dfa CRASHES='crashes/dfa_eval_*'"; \
		exit 1; \
	fi
	@for crash in $(CRASHES); do \
		echo "=== Replaying $$crash ==="; \
		./dfa_eval_fuzzer $$crash -runs=1; \
	done

# Replay pattern parser crashes (use pattern_parse_fuzzer)
# Usage: make replay-crashes-pattern CRASHES="crashes/pattern_parse_abc123"
replay-crashes-pattern: pattern_parse_fuzzer
	@if [ -z "$(CRASHES)" ]; then \
		echo "Error: Please specify CRASHES='file1 file2 ...'"; \
		echo "Example: make replay-crashes-pattern CRASHES='crashes/pattern_parse_*'"; \
		exit 1; \
	fi
	@for crash in $(CRASHES); do \
		echo "=== Replaying $$crash ==="; \
		./pattern_parse_fuzzer $$crash -runs=1; \
	done

# Replay all DFA fuzzer crashes found
replay-all-dfa-crashes: dfa_eval_fuzzer
	@if ls crashes/dfa_eval_* 1>/dev/null 2>&1; then \
		for crash in crashes/dfa_eval_*; do \
			echo "=== Replaying $$crash ==="; \
			./dfa_eval_fuzzer $$crash -runs=1; \
		done; \
	else \
		echo "No DFA crashes found in crashes/"; \
	fi

# Replay all pattern parser crashes found
replay-all-pattern-crashes: pattern_parse_fuzzer
	@if ls crashes/pattern_parse_* 1>/dev/null 2>&1; then \
		for crash in crashes/pattern_parse_*; do \
			echo "=== Replaying $$crash ==="; \
			./pattern_parse_fuzzer $$crash -runs=1; \
		done; \
	else \
		echo "No pattern parser crashes found in crashes/"; \
	fi

# Replay NFA build crashes found
replay-crashes-nfa-build: nfa_build_fuzzer
	@if [ -z "$(CRASHES)" ]; then \
		echo "Error: Please specify CRASHES='file1 file2 ...'"; \
		echo "Example: make replay-crashes-nfa-build CRASHES='crashes/nfa_build_*'"; \
		exit 1; \
	fi
	@for crash in $(CRASHES); do \
		echo "=== Replaying $$crash ==="; \
		./nfa_build_fuzzer $$crash -runs=1; \
	done

replay-all-nfa-build-crashes: nfa_build_fuzzer
	@if ls crashes/nfa_build_* 1>/dev/null 2>&1; then \
		for crash in crashes/nfa_build_*; do \
			echo "=== Replaying $$crash ==="; \
			./nfa_build_fuzzer $$crash -runs=1; \
		done; \
	else \
		echo "No NFA build crashes found in crashes/"; \
	fi

# Replay all crashes (all fuzzers)
replay-all-crashes: replay-all-dfa-crashes replay-all-pattern-crashes replay-all-nfa-build-crashes

# List crashes found
list-crashes:
	@echo "DFA crashes:"; ls -1 crashes/dfa_eval_* 2>/dev/null | wc -l
	@echo "Pattern parser crashes:"; ls -1 crashes/pattern_parse_* 2>/dev/null | wc -l
	@echo "NFA build crashes:"; ls -1 crashes/nfa_build_* 2>/dev/null | wc -l
	@echo "Total crash files:"; find crashes -type f 2>/dev/null | wc -l

.PHONY: all clean run-dfa run-dfa-dict merge minimize run-pattern run-nfa-build \
        run-dfa-cgroup run-pattern-cgroup run-nfa-build-cgroup \
        replay-crashes-dfa replay-crashes-pattern replay-crashes-nfa-build \
        replay-all-dfa-crashes replay-all-pattern-crashes replay-all-nfa-build-crashes \
        replay-all-crashes list-crashes setup-dirs
