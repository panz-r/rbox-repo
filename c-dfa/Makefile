# ============================================================================
# C-DFA Test Suite Makefile
# ============================================================================
# The test runner (dfa_test) handles all DFA building internally.
# Simply invoke it with --test-set and --minimize-XXX flags.
#
# Test Sets:
#   A = Core tests (basic patterns, quantifiers, fragments, alternation)
#   B = Expanded tests (complex patterns with nested quantifiers)
#   C = Command tests (admin, caution, modifying, dangerous, network commands)
#
# Algorithms:
#   Moore       - Simple table-filling minimization
#   Hopcroft   - Efficient O(n log n) minimization
#   Brzozowski - Double-reversal produces unique minimal DFA
# ============================================================================

CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -Iinclude -O2 -mcmodel=medium
LDFLAGS = -lm -mcmodel=medium

BUILD_DIR = build
SRC_DIR = src
TOOLS_DIR = tools
INCLUDE_DIR = include

TOOLS = $(TOOLS_DIR)/nfa_builder $(TOOLS_DIR)/nfa2dfa_advanced
TEST = dfa_test

# Default target: build everything
all: $(TOOLS) $(TEST)

# Build tools
$(TOOLS_DIR)/nfa_builder: $(TOOLS_DIR)/nfa_builder.c $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -o $@ $(TOOLS_DIR)/nfa_builder.c $(TOOLS_DIR)/multi_target_array.c $(LDFLAGS)

$(TOOLS_DIR)/nfa2dfa_advanced: $(TOOLS_DIR)/nfa2dfa.c $(TOOLS_DIR)/nfa_builder.c \
		$(TOOLS_DIR)/dfa_minimize.c $(TOOLS_DIR)/dfa_minimize_brzozowski.c \
		$(TOOLS_DIR)/multi_target_array.c $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -DNFABUILDER_NO_MAIN -DNFABUILDER_EXCLUDE_NFA_INIT -o $@ $(TOOLS_DIR)/nfa2dfa.c $(TOOLS_DIR)/nfa_builder.c \
		$(TOOLS_DIR)/dfa_minimize.c $(TOOLS_DIR)/dfa_minimize_brzozowski.c \
		$(TOOLS_DIR)/multi_target_array.c $(LDFLAGS)

# Build test binary
$(TEST): $(SRC_DIR)/dfa_eval.c $(SRC_DIR)/dfa_loader.c $(SRC_DIR)/dfa_test.c $(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/dfa_eval.c $(SRC_DIR)/dfa_loader.c $(SRC_DIR)/dfa_test.c $(LDFLAGS)

# Build minimization integrity test
$(TOOLS_DIR)/test_minimize_integrity: $(TOOLS_DIR)/test_minimize_integrity.c \
		$(TOOLS_DIR)/dfa_minimize.c $(TOOLS_DIR)/dfa_minimize_brzozowski.c \
		$(INCLUDE_DIR)/*.h
	$(CC) $(CFLAGS) -o $@ $(TOOLS_DIR)/test_minimize_integrity.c \
		$(TOOLS_DIR)/dfa_minimize.c $(TOOLS_DIR)/dfa_minimize_brzozowski.c $(LDFLAGS)

# Run minimization integrity test
test-integrity: $(TOOLS_DIR)/test_minimize_integrity
	@echo ""
	@echo "================================================="
	@echo "MINIMIZATION INTEGRITY TEST"
	@echo "================================================="
	@./$(TOOLS_DIR)/test_minimize_integrity

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(TOOLS_DIR)/nfa_builder $(TOOLS_DIR)/nfa2dfa_advanced $(TOOLS_DIR)/test_minimize_integrity $(TEST)

# Test targets - each invokes the test runner with specific test-set and algorithm
test-moore: $(TOOLS) $(TEST)
	@echo ""
	@echo "================================================="
	@echo "MOORE ALGORITHM (Test-Set A)"
	@echo "================================================="
	@./$(TEST) --test-set A --minimize-moore

test-hopcroft: $(TOOLS) $(TEST)
	@echo ""
	@echo "================================================="
	@echo "HOPCROFT ALGORITHM (Test-Set B)"  
	@echo "================================================="
	@./$(TEST) --test-set B --minimize-hopcroft

test-brzozowski: $(TOOLS) $(TEST)
	@echo ""
	@echo "================================================="
	@echo "BRZOZOWSKI ALGORITHM (Test-Set C)"
	@echo "================================================="
	@./$(TEST) --test-set C --minimize-brzozowski

# Full test suite - runs all three algorithms with their respective test sets
test: $(TOOLS) $(TEST) $(TOOLS_DIR)/test_minimize_integrity
	@echo ""
	@echo "================================================="
	@echo "C-DFA FULL TEST SUITE"
	@echo "================================================="
	@echo ""
	@make test-moore 2>&1 | tail -3
	@echo ""
	@make test-hopcroft 2>&1 | tail -3
	@echo ""
	@make test-brzozowski 2>&1 | tail -3
	@echo ""
	@make test-integrity 2>&1 | tail -5
	@echo ""
	@echo "================================================="

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

.PHONY: all clean test test-moore test-hopcroft test-brzozowski test-integrity
.PHONY: fuzz fuzz-build fuzz-run-dfa fuzz-run-pattern fuzz-run fuzz-clean fuzz-rebuild
