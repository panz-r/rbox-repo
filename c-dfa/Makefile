# ============================================================================
# C-DFA Test Suite Makefile
# ============================================================================
# The test runner (dfa_test) handles all DFA building internally.
# Simply invoke it with --test-set and --minimize-XXX flags.
#
# Directory Structure:
#   include/    - Public headers
#   src/        - Library source (eval, loader, test runner)
#   tools/      - CLI tools and internal libraries
#   tests/      - Test source code
#   patterns/   - Test pattern files
#   docs/       - Documentation
#
# Test Sets:
#   A = Core tests (basic patterns, quantifiers, fragments, alternation)
#   B = Expanded tests (complex patterns with nested quantifiers)
#   C = Command tests (admin, caution, modifying, dangerous, network commands)
#
# Algorithms:
#   Moore       - Simple table-filling minimization
#   Hopcroft    - Efficient O(n log n) minimization
#   Brzozowski  - Double-reversal produces unique minimal DFA
#   SAT         - Provably optimal using CaDiCaL solver
# ============================================================================

CC = gcc
CXX = g++

# -mcmodel=medium is x86-64 only; skip on ARM/other architectures
MCMODEL :=
ifeq ($(shell uname -m),x86_64)
MCMODEL := -mcmodel=medium
endif

CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -Iinclude -O2 $(MCMODEL) -Wno-missing-field-initializers
CXXFLAGS = -Wall -Wextra -Wpedantic -std=c++17 -Iinclude -O2 $(MCMODEL)
LDFLAGS = -lm $(MCMODEL)

BUILD_DIR = build
SRC_DIR = src
TOOLS_DIR = tools
TESTS_DIR = tests
INCLUDE_DIR = include

# CaDiCaL SAT solver
CADICAL_DIR = vendor/cadical
CADICAL_LIB = $(CADICAL_DIR)/build/libcadical.a
CADICAL_INC = -I$(CADICAL_DIR)/src

TOOLS = $(TOOLS_DIR)/nfa_builder $(TOOLS_DIR)/nfa2dfa_advanced $(TOOLS_DIR)/dfa_eval_wrapper $(TOOLS_DIR)/dfa2c_array $(TOOLS_DIR)/dfa_chain_stats
TEST = dfa_test

# NFA builder module objects (for both standalone and nfa2dfa_advanced)
NFA_BUILDER_MODULES = $(TOOLS_DIR)/nfa_construct.o \
                      $(TOOLS_DIR)/nfa_capture.o \
                      $(TOOLS_DIR)/nfa_categories.o \
                      $(TOOLS_DIR)/nfa_parser.o \
                      $(TOOLS_DIR)/nfa_validate.o \
                      $(TOOLS_DIR)/nfa_alphabet.o

# ============================================================================
# Static Library Target
# ============================================================================

# Default target: build everything (MUST be first rule)
all: $(TOOLS) $(TEST) $(LIB) $(EVAL_LIB)
ifneq ($(shell /usr/bin/clang -dumpmachine 2>/dev/null | grep -q "$(shell uname -m)" && echo yes),)
all: fuzz-build
endif

# Allow parallel builds with -j
ifneq ($(MAKECMDGOALS),)
  # Only add -j if not already specified
  ifeq ($(findstring -j,$(MAKEFLAGS)),)
    NPROCS := $(shell nproc 2>/dev/null || echo 1)
    export MAKEFLAGS += -j$(NPROCS)
  endif
endif

LIB = libreadonlybox_dfa.a

LIB_OBJS = lib/pipeline.o \
           lib/build_dfa_state.o \
           lib/nfa2dfa_context.o \
           $(SRC_DIR)/dfa_eval.o \
           $(SRC_DIR)/dfa_loader.o \
           $(SRC_DIR)/dfa_machine.o \
           $(TOOLS_DIR)/nfa_builder_lib.o \
           $(NFA_BUILDER_MODULES) \
           $(TOOLS_DIR)/nfa2dfa.o \
           $(TOOLS_DIR)/dfa_minimize.o \
           $(TOOLS_DIR)/dfa_minimize_brzozowski.o \
           $(TOOLS_DIR)/dfa_minimize_sat_stub.o \
           $(TOOLS_DIR)/dfa_layout.o \
           $(TOOLS_DIR)/dfa_compress.o \
           $(TOOLS_DIR)/dfa_compress_sat_stub.o \
           $(TOOLS_DIR)/nfa_preminimize.o \
           $(TOOLS_DIR)/nfa_preminimize_sat_optimal_stub.o \
           $(TOOLS_DIR)/dfa_layout_sat_stub.o \
           $(TOOLS_DIR)/pattern_order.o \
           $(TOOLS_DIR)/multi_target_array.o

$(LIB): $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)

# Eval-only library - just evaluation, no loader/I/O
EVAL_LIB = libdfa_eval.a
EVAL_LIB_OBJS = $(SRC_DIR)/dfa_eval.o

$(EVAL_LIB): $(EVAL_LIB_OBJS)
	$(AR) rcs $@ $(EVAL_LIB_OBJS)

lib/pipeline.o: lib/pipeline.c $(INCLUDE_DIR)/*.h $(TOOLS_DIR)/nfa_builder.h $(TOOLS_DIR)/nfa2dfa_context.h
	$(CC) $(CFLAGS) -c -o $@ $<

lib/build_dfa_state.o: lib/build_dfa_state.c $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

lib/nfa2dfa_context.o: lib/nfa2dfa_context.c $(INCLUDE_DIR)/*.h $(TOOLS_DIR)/nfa2dfa_context.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(SRC_DIR)/dfa_eval.o: $(SRC_DIR)/dfa_eval.c $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(SRC_DIR)/dfa_loader.o: $(SRC_DIR)/dfa_loader.c $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(SRC_DIR)/dfa_machine.o: $(SRC_DIR)/dfa_machine.c $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Install library and headers
PREFIX ?= /usr/local
install-lib: $(LIB)
	install -d $(DESTDIR)$(PREFIX)/lib
	install -d $(DESTDIR)$(PREFIX)/include
	install -m 644 $(LIB) $(DESTDIR)$(PREFIX)/lib/
	install -m 644 include/pipeline.h $(DESTDIR)$(PREFIX)/include/
	install -m 644 include/dfa_types.h $(DESTDIR)$(PREFIX)/include/

# Build standalone nfa_builder (links against library for all modules)
$(TOOLS_DIR)/nfa_builder: $(TOOLS_DIR)/nfa_builder.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $(TOOLS_DIR)/nfa_builder.c -L. -lreadonlybox_dfa $(LDFLAGS)

# DFA eval wrapper for fuzzing
$(TOOLS_DIR)/dfa_eval_wrapper: $(TOOLS_DIR)/dfa_eval_wrapper.c $(SRC_DIR)/dfa_eval.c $(SRC_DIR)/dfa_loader.c $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -o $@ $(TOOLS_DIR)/dfa_eval_wrapper.c $(SRC_DIR)/dfa_eval.c $(SRC_DIR)/dfa_loader.c $(LDFLAGS)

# DFA binary to C array converter
$(TOOLS_DIR)/dfa2c_array: $(TOOLS_DIR)/dfa2c_array.c $(INCLUDE_DIR)/dfa_errors.h
	$(CC) $(CFLAGS) -o $@ $(TOOLS_DIR)/dfa2c_array.c $(LDFLAGS)

$(TOOLS_DIR)/dfa_chain_stats: $(TOOLS_DIR)/dfa_chain_stats.c $(INCLUDE_DIR)/dfa_types.h $(INCLUDE_DIR)/dfa_format.h
	$(CC) $(CFLAGS) -o $@ $(TOOLS_DIR)/dfa_chain_stats.c $(LDFLAGS)

# CLI version of nfa2dfa.o (includes main)
$(TOOLS_DIR)/nfa2dfa_cli.o: $(TOOLS_DIR)/nfa2dfa.c $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -DNFABUILDER_EXCLUDE_NFA_INIT -c -o $@ $<

# Main tool with compression support (links against library + SAT modules)
$(TOOLS_DIR)/nfa2dfa_advanced: $(TOOLS_DIR)/nfa2dfa_cli.o $(LIB) \
		$(TOOLS_DIR)/dfa_compress_sat.o \
		$(TOOLS_DIR)/dfa_layout_sat.o \
		$(TOOLS_DIR)/nfa_preminimize_sat.o \
		$(TOOLS_DIR)/nfa_preminimize_windowed.o \
		$(TOOLS_DIR)/nfa_preminimize_sat_optimal.o \
		$(CADICAL_LIB)
	$(CXX) -o $@ $(TOOLS_DIR)/nfa2dfa_cli.o \
		-L. -lreadonlybox_dfa \
		$(TOOLS_DIR)/dfa_compress_sat.o \
		$(TOOLS_DIR)/dfa_layout_sat.o \
		$(TOOLS_DIR)/nfa_preminimize_sat.o \
		$(TOOLS_DIR)/nfa_preminimize_windowed.o \
		$(TOOLS_DIR)/nfa_preminimize_sat_optimal.o \
		$(CADICAL_LIB) $(LDFLAGS) -lstdc++

# Object files for nfa2dfa (library version - no main)
$(TOOLS_DIR)/nfa2dfa.o: $(TOOLS_DIR)/nfa2dfa.c $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -DNFABUILDER_NO_MAIN -DNFABUILDER_EXCLUDE_NFA_INIT -DNFA2DFA_BUILDING_LIB -c -o $@ $<

# SAT stubs for library (C-only build)
$(TOOLS_DIR)/dfa_compress_sat_stub.o: $(TOOLS_DIR)/dfa_compress_sat_stub.c $(TOOLS_DIR)/dfa_compress.h $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TOOLS_DIR)/nfa_preminimize_sat_optimal_stub.o: $(TOOLS_DIR)/nfa_preminimize_sat_optimal_stub.c $(TOOLS_DIR)/nfa_preminimize.h $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TOOLS_DIR)/dfa_layout_sat_stub.o: $(TOOLS_DIR)/dfa_layout_sat_stub.c $(TOOLS_DIR)/dfa_layout_sat.h $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TOOLS_DIR)/nfa_builder_lib.o: $(TOOLS_DIR)/nfa_builder_lib.c $(INCLUDE_DIR)/*.h $(TOOLS_DIR)/nfa_builder.h
	$(CC) $(CFLAGS) -DNFABUILDER_NO_MAIN -c -o $@ $<

# NFA builder module objects (compiled with NFABUILDER_NO_MAIN for nfa2dfa_advanced)
$(TOOLS_DIR)/nfa_construct.o: $(TOOLS_DIR)/nfa_construct.c $(INCLUDE_DIR)/*.h $(TOOLS_DIR)/nfa_builder.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TOOLS_DIR)/nfa_capture.o: $(TOOLS_DIR)/nfa_capture.c $(INCLUDE_DIR)/*.h $(TOOLS_DIR)/nfa_builder.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TOOLS_DIR)/nfa_categories.o: $(TOOLS_DIR)/nfa_categories.c $(INCLUDE_DIR)/*.h $(TOOLS_DIR)/nfa_builder.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TOOLS_DIR)/nfa_parser.o: $(TOOLS_DIR)/nfa_parser.c $(INCLUDE_DIR)/*.h $(TOOLS_DIR)/nfa_builder.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TOOLS_DIR)/nfa_validate.o: $(TOOLS_DIR)/nfa_validate.c $(INCLUDE_DIR)/*.h $(TOOLS_DIR)/nfa_builder.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TOOLS_DIR)/nfa_alphabet.o: $(TOOLS_DIR)/nfa_alphabet.c $(INCLUDE_DIR)/*.h $(TOOLS_DIR)/nfa_builder.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TOOLS_DIR)/dfa_minimize.o: $(TOOLS_DIR)/dfa_minimize.c $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TOOLS_DIR)/dfa_minimize_brzozowski.o: $(TOOLS_DIR)/dfa_minimize_brzozowski.c $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TOOLS_DIR)/dfa_minimize_sat_stub.o: $(TOOLS_DIR)/dfa_minimize_sat_stub.c $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TOOLS_DIR)/dfa_layout.o: $(TOOLS_DIR)/dfa_layout.c $(TOOLS_DIR)/dfa_layout.h $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TOOLS_DIR)/dfa_compress.o: $(TOOLS_DIR)/dfa_compress.c $(TOOLS_DIR)/dfa_compress.h $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TOOLS_DIR)/dfa_compress_sat.o: $(TOOLS_DIR)/dfa_compress_sat.cpp $(TOOLS_DIR)/dfa_compress.h $(INCLUDE_DIR)/*.h $(CADICAL_LIB)
	$(CXX) $(CXXFLAGS) $(CADICAL_INC) -DUSE_CADICAL -c -o $@ $<

$(TOOLS_DIR)/nfa_preminimize.o: $(TOOLS_DIR)/nfa_preminimize.c $(TOOLS_DIR)/nfa_preminimize.h $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(TOOLS_DIR)/nfa_preminimize_sat.o: $(TOOLS_DIR)/nfa_preminimize_sat.cpp $(TOOLS_DIR)/nfa_preminimize.h $(INCLUDE_DIR)/*.h $(CADICAL_LIB)
	$(CXX) $(CXXFLAGS) $(CADICAL_INC) -DUSE_CADICAL -c -o $@ $<

$(TOOLS_DIR)/nfa_preminimize_windowed.o: $(TOOLS_DIR)/nfa_preminimize_windowed.cpp $(TOOLS_DIR)/nfa_preminimize.h $(INCLUDE_DIR)/*.h $(CADICAL_LIB)
	$(CXX) $(CXXFLAGS) $(CADICAL_INC) -DUSE_CADICAL -c -o $@ $<

$(TOOLS_DIR)/nfa_preminimize_sat_optimal.o: $(TOOLS_DIR)/nfa_preminimize_sat_optimal.cpp $(TOOLS_DIR)/nfa_preminimize.h $(INCLUDE_DIR)/*.h $(CADICAL_LIB)
	$(CXX) $(CXXFLAGS) $(CADICAL_INC) -DUSE_CADICAL -c -o $@ $<

$(TOOLS_DIR)/dfa_layout_sat.o: $(TOOLS_DIR)/dfa_layout_sat.cpp $(TOOLS_DIR)/dfa_layout_sat.h $(INCLUDE_DIR)/*.h $(CADICAL_LIB)
	$(CXX) $(CXXFLAGS) $(CADICAL_INC) -DUSE_CADICAL -c -o $@ $<

$(TOOLS_DIR)/multi_target_array.o: $(TOOLS_DIR)/multi_target_array.c $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Build with SAT minimization support (requires CaDiCaL)
# Uses dfa_minimize_sat.o instead of dfa_minimize_sat_stub.o
$(TOOLS_DIR)/nfa2dfa_sat: $(TOOLS_DIR)/nfa2dfa.o $(LIB) \
		$(TOOLS_DIR)/dfa_minimize_sat.o \
		$(TOOLS_DIR)/dfa_compress_sat.o \
		$(TOOLS_DIR)/nfa_preminimize_sat.o \
		$(TOOLS_DIR)/nfa_preminimize_windowed.o \
		$(TOOLS_DIR)/nfa_preminimize_sat_optimal.o \
		$(CADICAL_LIB)
	$(CXX) -o $@ $(TOOLS_DIR)/nfa2dfa.o \
		-L. -lreadonlybox_dfa \
		$(TOOLS_DIR)/dfa_minimize_sat.o \
		$(TOOLS_DIR)/dfa_compress_sat.o \
		$(TOOLS_DIR)/nfa_preminimize_sat.o \
		$(TOOLS_DIR)/nfa_preminimize_windowed.o \
		$(TOOLS_DIR)/nfa_preminimize_sat_optimal.o \
		$(CADICAL_LIB) $(LDFLAGS) -lstdc++

$(TOOLS_DIR)/dfa_minimize_sat.o: $(TOOLS_DIR)/dfa_minimize_sat.cpp $(INCLUDE_DIR)/*.h $(CADICAL_LIB)
	$(CXX) $(CXXFLAGS) $(CADICAL_INC) -c -o $@ $<

# Ensure CaDiCaL is built
$(CADICAL_LIB):
	@echo "Building CaDiCaL SAT solver..."
	cd $(CADICAL_DIR) && ./configure && make

# Build test binary (links against library for full pipeline support)
$(TEST): $(SRC_DIR)/dfa_test.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/dfa_test.c -L. -lreadonlybox_dfa $(LDFLAGS)

# Build minimization integrity test
$(TESTS_DIR)/test_minimize_integrity: $(TESTS_DIR)/test_minimize_integrity.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $(TESTS_DIR)/test_minimize_integrity.c \
		-L. -lreadonlybox_dfa $(LDFLAGS)

# Build library API tests (error handling, concurrent evaluators)
$(TESTS_DIR)/test_library_api: $(TESTS_DIR)/test_library_api.c $(LIB) $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -o $@ $(TESTS_DIR)/test_library_api.c -L. -lreadonlybox_dfa $(LDFLAGS)

# Build regression tests (pattern bug regression tests)
$(TESTS_DIR)/regression_test: $(TESTS_DIR)/regression_test.c $(LIB) $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -o $@ $(TESTS_DIR)/regression_test.c -L. -lreadonlybox_dfa $(LDFLAGS)

# Build eval-only test (links against libdfa_eval.a only, no builder deps)
$(TESTS_DIR)/test_eval_only: $(TESTS_DIR)/test_eval_only.c $(EVAL_LIB) $(INCLUDE_DIR)/dfa.h $(INCLUDE_DIR)/dfa_types.h
	$(CC) $(CFLAGS) -o $@ $(TESTS_DIR)/test_eval_only.c -L. -ldfa_eval $(LDFLAGS)

# Run minimization integrity test
test-integrity: $(TESTS_DIR)/test_minimize_integrity
	@echo ""
	@echo "================================================="
	@echo "MINIMIZATION INTEGRITY TEST"
	@echo "================================================="
	@./$(TESTS_DIR)/test_minimize_integrity

# Run library API tests
test-library: $(TESTS_DIR)/test_library_api
	@echo ""
	@echo "================================================="
	@echo "LIBRARY API TESTS"
	@echo "================================================="
	@./$(TESTS_DIR)/test_library_api

test-eval-only: $(TESTS_DIR)/test_eval_only $(EVAL_LIB) $(TOOLS)
	@echo ""
	@echo "================================================="
	@echo "EVAL-ONLY LIBRARY TESTS (libdfa_eval.a)"
	@echo "================================================="
	@./tools/nfa_builder $(TESTS_DIR)/eval_test_patterns.txt /tmp/eval_test_dfa.nfa 2>/dev/null
	@./tools/nfa2dfa_advanced /tmp/eval_test_dfa.nfa /tmp/eval_test_dfa.dfa 2>/dev/null
	@./$(TESTS_DIR)/test_eval_only

# dfa2c_array tests
test-dfa2c: $(TOOLS_DIR)/dfa2c_array
	@echo ""
	@echo "================================================="
	@echo "DFA2C_ARRAY TOOL TESTS"
	@echo "================================================="
	@$(TESTS_DIR)/test_dfa2c_array.sh

# Binary format edge case tests
test-binary-format: $(TOOLS) $(LIB)
	@echo ""
	@echo "================================================="
	@echo "BINARY FORMAT EDGE CASE TESTS"
	@echo "================================================="
	@$(TESTS_DIR)/test_binary_format.sh

test-captures: $(TOOLS) $(LIB)
	@echo ""
	@echo "================================================="
	@echo "CAPTURE SYSTEM TESTS"
	@echo "================================================="
	@$(TESTS_DIR)/test_captures.sh

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(TOOLS_DIR)/nfa_builder $(TOOLS_DIR)/nfa2dfa_advanced \
		$(TOOLS_DIR)/nfa2dfa_sat $(TOOLS_DIR)/dfa2c_array $(TOOLS_DIR)/pattern_order \
	$(TESTS_DIR)/test_minimize_integrity \
	$(TESTS_DIR)/test_library_api \
	$(TESTS_DIR)/test_eval_only \
	$(TESTS_DIR)/test_dfa2c_array \
		$(TEST) $(TEST_SAT) $(LIB) $(EVAL_LIB)
	rm -f $(TOOLS_DIR)/*.o lib/*.o $(SRC_DIR)/*.o
	$(MAKE) -C fuzz clean

# Clean including vendor builds
clean-all: clean
	$(MAKE) -C $(CADICAL_DIR) clean 2>/dev/null || true

# Build tools with SAT support
build-sat: $(TOOLS_DIR)/nfa2dfa_sat

# ============================================================================
# Main Test Targets
# ============================================================================

# Test targets - each invokes the test runner with specific test-set and algorithm
test-moore: $(TOOLS) $(TEST)
	@echo ""
	@echo "================================================="
	@echo "MOORE ALGORITHM (Test-Set A) with SAT compression"
	@echo "================================================="
	@./$(TEST) --test-set A --minimize-moore --compress-sat

test-hopcroft: $(TOOLS) $(TEST)
	@echo ""
	@echo "================================================="
	@echo "HOPCROFT ALGORITHM (Test-Set B) with SAT compression"
	@echo "================================================="
	@./$(TEST) --test-set B --minimize-hopcroft --compress-sat

test-stress: $(TOOLS) $(TEST)
	@echo ""
	@echo "================================================="
	@echo "STRESS TESTS (Test-Set C) with SAT compression"
	@echo "================================================="
	@./$(TEST) --test-set C --minimize-moore --compress-sat

# Full test suite - runs all algorithms with their respective test sets
test: $(TOOLS) $(TEST) $(TESTS_DIR)/test_minimize_integrity $(TESTS_DIR)/test_library_api
	@echo "C-DFA FULL TEST SUITE"
	@TOTAL_SUITES=0; RUN_SUITES=0; TOTAL_PASSED=0; TOTAL_TESTS=0; \
	TOTAL_GROUPS=0; RUN_GROUPS=0; FAILED_GROUPS=0; \
	run_suite() { \
		TOTAL_SUITES=$$((TOTAL_SUITES + 1)); \
		OUTPUT=$$(make "$$1" 2>&1); \
		if echo "$$OUTPUT" | grep -q "SUMMARY:\|Tests:\|completed\|passed"; then \
			RUN_SUITES=$$((RUN_SUITES + 1)); \
			MSG=$$(echo "$$OUTPUT" | grep "SUMMARY:\|Tests:" | tail -1); \
			if [ -n "$$MSG" ]; then \
				P=$$(echo "$$MSG" | grep -o '[0-9]*/[0-9]*' | head -1 | awk -F/ '{print $$1}'); \
				T=$$(echo "$$MSG" | grep -o '[0-9]*/[0-9]*' | head -1 | awk -F/ '{print $$2}'); \
				TOTAL_PASSED=$$((TOTAL_PASSED + P)); \
				TOTAL_TESTS=$$((TOTAL_TESTS + T)); \
				GRP=$$(echo "$$MSG" | grep -o '([0-9]*/[0-9]* groups)' | grep -o '[0-9]*/[0-9]*'); \
				if [ -n "$$GRP" ]; then \
					RG=$$(echo "$$GRP" | awk -F/ '{print $$1}'); \
					TG=$$(echo "$$GRP" | awk -F/ '{print $$2}'); \
					RUN_GROUPS=$$((RUN_GROUPS + RG)); \
					TOTAL_GROUPS=$$((TOTAL_GROUPS + TG)); \
				fi; \
				FG=$$(echo "$$MSG" | grep -o '[0-9]* failed' | awk '{print $$1}'); \
				if [ -n "$$FG" ]; then FAILED_GROUPS=$$((FAILED_GROUPS + FG)); fi; \
			fi; \
		else \
			echo "  FAILED: $$1"; \
		fi; \
	}; \
	run_suite test-moore; \
	run_suite test-hopcroft; \
	run_suite test-stress; \
	run_suite test-integrity; \
	run_suite test-library; \
	run_suite test-eval-only; \
	run_suite test-dfa2c; \
	run_suite test-binary-format; \
	run_suite test-captures; \
	run_suite test-regression; \
	echo ""; \
	if [ $$TOTAL_GROUPS -gt 0 ]; then \
		echo "SUMMARY: ran $$RUN_SUITES/$$TOTAL_SUITES suites, $$RUN_GROUPS/$$TOTAL_GROUPS groups, $$TOTAL_PASSED/$$TOTAL_TESTS passed"; \
	else \
		echo "SUMMARY: ran $$RUN_SUITES/$$TOTAL_SUITES suites, $$TOTAL_PASSED/$$TOTAL_TESTS passed"; \
	fi; \
	if [ $$FAILED_GROUPS -gt 0 ]; then echo "  $$FAILED_GROUPS group(s) failed to load"; fi

# Pattern regression tests - C version (integrated into test suite)
test-regression: $(TESTS_DIR)/regression_test
	@echo ""
	@echo "================================================="
	@echo "PATTERN REGRESSION TESTS"
	@echo "================================================="
	@./$(TESTS_DIR)/regression_test

# Legacy shell-based pattern tests (for manual testing only)
test-patterns: $(TOOLS)
	@FAIL_COUNT=0; \
	echo ""; \
	echo "================================================="; \
	echo "PATTERN REGRESSION TESTS (LEGACY - MANUAL ONLY)"; \
	echo "================================================="; \
	echo ""; \
	echo "Testing = followed by fragment reference bug (Parser bug #6 - FIXED)..."; \
	printf 'ACCEPTANCE_MAPPING [safe] -> 0\n[fragment:safe::x] a\n[safe] ls( =)?((safe::x))\n' > /tmp/bug_eq_simple.txt; \
	./tools/nfa_builder /tmp/bug_eq_simple.txt /tmp/bug_eq_simple.nfa 2>/dev/null; \
	NFA_STATES=$$(grep '^States:' /tmp/bug_eq_simple.nfa | awk '{print $$2}'); \
	if [ "$$NFA_STATES" -gt 1 ]; then \
		echo "    [PASS] NFA has $$NFA_STATES states (was 1 before fix)"; \
	else \
		echo "    [FAIL] NFA has only $$NFA_STATES states - bug NOT fixed!"; \
		FAIL_COUNT=$$((FAIL_COUNT + 1)); \
	fi; \
	./tools/nfa2dfa_advanced /tmp/bug_eq_simple.nfa /tmp/bug_eq_simple.dfa 2>&1; CRASH=$$?; \
	if [ $$CRASH -ne 0 ] || [ ! -f /tmp/bug_eq_simple.dfa ]; then \
		echo "    [FAIL] nfa2dfa_advanced crashed (exit code $$CRASH)"; \
		FAIL_COUNT=$$((FAIL_COUNT + 1)); \
	elif (./tools/dfa_eval_wrapper /tmp/bug_eq_simple.dfa "lsa" 2>&1 | grep -q "matched=1"); then \
		echo "    [PASS] Pattern matches 'lsa'"; \
	else \
		echo "    [FAIL] Pattern does not match 'lsa'"; \
		FAIL_COUNT=$$((FAIL_COUNT + 1)); \
	fi; \
	rm -f /tmp/bug_eq_simple.txt /tmp/bug_eq_simple.nfa /tmp/bug_eq_simple.dfa; \
	echo ""; \
	echo "Testing nfa2dfa_advanced segfault bug (Bug #7 - NOT FIXED)..."; \
	./tools/nfa_builder tests/bug_nfa2dfa_segfault.txt /tmp/bug_nfa2dfa.nfa 2>/dev/null; \
	./tools/nfa2dfa_advanced /tmp/bug_nfa2dfa.nfa /tmp/bug_nfa2dfa.dfa 2>&1; CRASH=$$?; \
	if [ $$CRASH -ne 0 ] || [ ! -f /tmp/bug_nfa2dfa.dfa ]; then \
		echo "    [FAIL] nfa2dfa_advanced crashed (exit code $$CRASH)"; \
	else \
		echo "    [PASS] nfa2dfa_advanced completed"; \
	fi; \
	rm -f /tmp/bug_nfa2dfa.nfa /tmp/bug_nfa2dfa.dfa; \
	echo ""; \
	echo "Testing complex nested optional groups (Bug #8 - NOT FIXED)..."; \
	./tools/nfa_builder tests/bug_complex_optional.txt /tmp/bug_complex.nfa 2>/dev/null; \
	./tools/nfa2dfa_advanced /tmp/bug_complex.nfa /tmp/bug_complex.dfa 2>&1; CRASH=$$?; \
	if [ $$CRASH -ne 0 ] || [ ! -f /tmp/bug_complex.dfa ]; then \
		echo "    [FAIL] nfa2dfa_advanced crashed (exit code $$CRASH)"; \
	else \
		echo "    [PASS] nfa2dfa_advanced completed"; \
	fi; \
	rm -f /tmp/bug_complex.nfa /tmp/bug_complex.dfa

# Fuzzing targets
fuzz: fuzz-build

fuzz-build:
	$(MAKE) -C fuzz all

fuzz-run-dfa:
	@echo "Running DFA evaluation fuzzer..."
	$(MAKE) -C fuzz run-dfa

fuzz-run-pattern:
	@echo "Running pattern parser fuzzer..."
	$(MAKE) -C fuzz run-pattern

fuzz-run: fuzz-run-dfa fuzz-run-pattern

fuzz-clean:
	$(MAKE) -C fuzz clean

fuzz-rebuild: clean-fuzz fuzz-build

.PHONY: all clean clean-all test test-moore test-hopcroft test-brzozowski test-integrity build-sat test-sat test-sat-full
.PHONY: fuzz fuzz-build fuzz-run-dfa fuzz-run-pattern fuzz-run fuzz-clean fuzz-rebuild

# SAT encoding tests
TEST_SAT = tests/test_sat_encoding

$(TEST_SAT): tests/test_sat_encoding.cpp $(TOOLS_DIR)/dfa_minimize_sat.o \
        $(TOOLS_DIR)/dfa_minimize.o $(TOOLS_DIR)/dfa_minimize_brzozowski.o \
        $(INCLUDE_DIR)/*.h $(CADICAL_LIB)
	$(CXX) $(CXXFLAGS) $(CADICAL_INC) -o $@ tests/test_sat_encoding.cpp \
		$(TOOLS_DIR)/dfa_minimize_sat.o $(TOOLS_DIR)/dfa_minimize.o \
		$(TOOLS_DIR)/dfa_minimize_brzozowski.o \
		$(CADICAL_LIB) $(LDFLAGS) -lstdc++

test-sat: $(TEST_SAT)
	@echo ""
	@echo "================================================="
	@echo "SAT ENCODING TESTS"
	@echo "================================================="
	@./$(TEST_SAT)

# Full test suite with SAT minimization (requires CaDiCaL)
test-sat-full: build-sat $(TEST)
	@echo ""
	@echo "================================================="
	@echo "FULL TEST SUITE WITH SAT MINIMIZATION"
	@echo "================================================="
	@./$(TEST) --minimize-sat --test-set A
	@./$(TEST) --minimize-sat --test-set BC
	@echo ""
	@echo "================================================="
	@echo "MINIMIZATION INTEGRITY (SAT)"
	@echo "================================================="
	@./$(TESTS_DIR)/test_minimize_integrity
