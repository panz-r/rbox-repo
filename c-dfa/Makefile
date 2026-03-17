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
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -Iinclude -O2 -mcmodel=medium -Wno-missing-field-initializers
CXXFLAGS = -Wall -Wextra -Wpedantic -std=c++17 -Iinclude -O2 -mcmodel=medium
LDFLAGS = -lm -mcmodel=medium

BUILD_DIR = build
SRC_DIR = src
TOOLS_DIR = tools
TESTS_DIR = tests
INCLUDE_DIR = include

# CaDiCaL SAT solver
CADICAL_DIR = vendor/cadical
CADICAL_LIB = $(CADICAL_DIR)/build/libcadical.a
CADICAL_INC = -I$(CADICAL_DIR)/src

TOOLS = $(TOOLS_DIR)/nfa_builder $(TOOLS_DIR)/nfa2dfa_advanced $(TOOLS_DIR)/dfa_eval_wrapper
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

LIB = libreadonlybox_dfa.a

LIB_OBJS = lib/pipeline.o \
           lib/build_dfa_state.o \
           lib/nfa2dfa_context.o \
           $(SRC_DIR)/dfa_eval.o \
           $(SRC_DIR)/dfa_loader.o \
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

# Install library and headers
PREFIX ?= /usr/local
install-lib: $(LIB)
	install -d $(DESTDIR)$(PREFIX)/lib
	install -d $(DESTDIR)$(PREFIX)/include
	install -m 644 $(LIB) $(DESTDIR)$(PREFIX)/lib/
	install -m 644 include/pipeline.h $(DESTDIR)$(PREFIX)/include/
	install -m 644 include/dfa_types.h $(DESTDIR)$(PREFIX)/include/

# Default target: build everything
all: $(TOOLS) $(TEST) $(LIB)

# Build standalone nfa_builder (links against library for all modules)
$(TOOLS_DIR)/nfa_builder: $(TOOLS_DIR)/nfa_builder.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $(TOOLS_DIR)/nfa_builder.c -L. -lreadonlybox_dfa $(LDFLAGS)

# DFA eval wrapper for fuzzing
$(TOOLS_DIR)/dfa_eval_wrapper: $(TOOLS_DIR)/dfa_eval_wrapper.c $(SRC_DIR)/dfa_eval.c $(SRC_DIR)/dfa_loader.c $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -o $@ $(TOOLS_DIR)/dfa_eval_wrapper.c $(SRC_DIR)/dfa_eval.c $(SRC_DIR)/dfa_loader.c $(LDFLAGS)

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

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(TOOLS_DIR)/nfa_builder $(TOOLS_DIR)/nfa2dfa_advanced \
		$(TOOLS_DIR)/nfa2dfa_sat $(TOOLS_DIR)/pattern_order \
		$(TESTS_DIR)/test_minimize_integrity \
		$(TESTS_DIR)/test_library_api \
		$(TEST) $(TEST_SAT) $(LIB)
	rm -f $(TOOLS_DIR)/*.o lib/*.o $(SRC_DIR)/*.o

# Clean including vendor builds
clean-all: clean
	$(MAKE) -C $(CADICAL_DIR) clean 2>/dev/null || true

# Generate compile_commands.json for LSP
compile_commands.json:
	bear -- make 2>/dev/null

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

# Full test suite - runs all three algorithms with their respective test sets
test: $(TOOLS) $(TEST) $(TESTS_DIR)/test_minimize_integrity $(TESTS_DIR)/test_library_api
	@echo ""
	@echo "================================================="
	@echo "C-DFA FULL TEST SUITE"
	@echo "================================================="
	@echo ""
	@make test-moore 2>&1 | tail -3
	@echo ""
	@make test-hopcroft 2>&1 | tail -3
	@echo ""
	@make test-stress 2>&1 | tail -3
	@make test-integrity 2>&1 | tail -5
	@echo ""
	@make test-library 2>&1 | tail -4
	@make test-patterns 2>&1 | tail -5
	@echo ""
	@echo "================================================="

# Pattern regression tests
test-patterns: $(TOOLS)
	@echo ""
	@echo "================================================="
	@echo "PATTERN REGRESSION TESTS"
	@echo "================================================="
	@echo ""
	@echo "Testing + quantifier empty string bug..."
	@./tools/nfa_builder patterns/quantifiers/test_plus_empty_string_bug.txt /tmp/test_plus_bug.nfa 2>/dev/null
	@./tools/nfa2dfa_advanced /tmp/test_plus_bug.nfa /tmp/test_plus_bug.dfa 2>&1 | grep -v "MINIMIZE" || true
	@echo "  Testing empty string:"
	@# Empty string should match category 1 (safe, the * pattern) but NOT category 6 (build, the + pattern)
	@# Category 1 = safe (bit 0) = 0x01
	@# Category 6 = build (bit 6) = 0x40
	@(echo "" | ./tools/dfa_eval_wrapper /tmp/test_plus_bug.dfa "" 2>&1 | grep -q "category=1" && echo "    [PASS] Empty string matches * pattern (category 1)" || echo "    [FAIL] Empty string does not match * pattern")
	@(echo "" | ./tools/dfa_eval_wrapper /tmp/test_plus_bug.dfa "" 2>&1 | grep -q "category=6" && echo "    [FAIL] Empty string incorrectly matches + pattern (category 6) - BUG!" || echo "    [PASS] Empty string does NOT match + pattern (category 6)")
	@echo "  Testing valid inputs:"
	@(./tools/dfa_eval_wrapper /tmp/test_plus_bug.dfa "W0GK" 2>&1 | grep -q "matched=1" && echo "    [PASS] Valid input matches + pattern" || echo "    [FAIL] Valid input does not match + pattern")
	@(./tools/dfa_eval_wrapper /tmp/test_plus_bug.dfa "mBJV9" 2>&1 | grep -q "matched=1" && echo "    [PASS] Valid input matches * pattern" || echo "    [FAIL] Valid input does not match * pattern")
	@rm -f /tmp/test_plus_bug.nfa /tmp/test_plus_bug.dfa
	@echo ""
	@echo "All pattern tests completed."

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

.PHONY: all clean clean-all test test-moore test-hopcroft test-brzozowski test-integrity build-sat test-sat test-sat-full compile_commands.json
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
