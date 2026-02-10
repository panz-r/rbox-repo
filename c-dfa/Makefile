# ============================================================================
# ReadOnlyBox DFA Build System
# ============================================================================
# Builds NFA and DFA files from pattern specifications
# Runs comprehensive test suite
# ============================================================================

CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -Iinclude -O2 -mcmodel=medium
LDFLAGS = -lm -mcmodel=medium

SRC_DIR = src
TOOLS_DIR = tools
INCLUDE_DIR = include
BUILD_DIR = build

TARGETS = dfa_test

# ============================================================================
# Build Tools (if source is newer than binary)
# ============================================================================
$(TOOLS_DIR)/nfa_builder: $(TOOLS_DIR)/nfa_builder.c $(TOOLS_DIR)/multi_target_array.c
	$(CC) $(CFLAGS) -o $@ $(TOOLS_DIR)/nfa_builder.c $(TOOLS_DIR)/multi_target_array.c

$(TOOLS_DIR)/nfa2dfa_advanced: $(TOOLS_DIR)/nfa2dfa.c $(TOOLS_DIR)/dfa_minimize.c $(TOOLS_DIR)/dfa_minimize_brzozowski.c $(TOOLS_DIR)/multi_target_array.c
	$(CC) $(CFLAGS) -o $@ $(TOOLS_DIR)/nfa2dfa.c $(TOOLS_DIR)/dfa_minimize.c $(TOOLS_DIR)/dfa_minimize_brzozowski.c $(TOOLS_DIR)/multi_target_array.c

# ============================================================================
# Pattern Files - Group 1: Core tests (Moore algorithm)
# ============================================================================
PATTERN_GROUP1 = \
	patterns_safe_commands.txt

DFA_GROUP1 = $(patsubst %.txt,$(BUILD_DIR)/%.dfa,$(PATTERN_GROUP1))

# ============================================================================
# Pattern Files - Group 2: Quantifier tests (Hopcroft algorithm)
# ============================================================================
PATTERN_GROUP2 = \
	patterns_quantifier_comprehensive.txt \
	patterns_frag_quant.txt \
	patterns_focused.txt \
	patterns_simple.txt \
	patterns_frag_plus.txt \
	patterns_digit_test.txt \
	patterns_space_test.txt \
	patterns_quantifier_test.txt \
	patterns_expanded_quantifier.txt \
	patterns_expanded_alternation.txt \
	patterns_expanded_nested.txt \
	patterns_expanded_fragment.txt \
	patterns_expanded_boundary.txt \
	patterns_expanded_interactions.txt \
	patterns_expanded_mixed.txt \
	patterns_expanded_hard.txt \
	patterns_expanded_perf.txt \
	patterns_quantifier_simple.txt \
	patterns_simple_quant.txt

DFA_GROUP2 = $(patsubst %.txt,$(BUILD_DIR)/%.dfa,$(PATTERN_GROUP2))

# ============================================================================
# Pattern Files - Group 3: Category and capture tests (Brzozowski algorithm)
# ============================================================================
PATTERN_GROUP3 = \
	patterns_acceptance_category_test.txt \
	patterns_admin_commands.txt \
	patterns_caution_commands.txt \
	patterns_modifying_commands.txt \
	patterns_dangerous_commands.txt \
	patterns_network_commands.txt \
	patterns_combined.txt \
	patterns_minimal.txt \
	patterns_step1.txt \
	patterns_step2.txt \
	patterns_step3.txt \
	patterns_test.txt \
	patterns_debug.txt \
	patterns_with_captures.txt \
	patterns_capture_test.txt \
	patterns_capture_simple.txt

DFA_GROUP3 = $(patsubst %.txt,$(BUILD_DIR)/%.dfa,$(PATTERN_GROUP3))

# All pattern files
PATTERN_FILES = $(PATTERN_GROUP1) $(PATTERN_GROUP2) $(PATTERN_GROUP3)

# Pattern file to DFA file mapping
DFA_FILES = $(PATTERN_GROUP1:%=$(BUILD_DIR)/%.dfa) $(PATTERN_GROUP2:%=$(BUILD_DIR)/%.dfa) $(PATTERN_GROUP3:%=$(BUILD_DIR)/%.dfa)
NFA_FILES = $(patsubst %.txt,$(BUILD_DIR)/%.nfa,$(PATTERN_FILES))

# ============================================================================
# Phony Targets
# ============================================================================
.PHONY: all clean test test-moore test-hopcroft test-brzozowski validate help FORCE clean-dfa

# ============================================================================
# Clean DFA files (force rebuild)
# ============================================================================
clean-dfa:
	rm -rf $(BUILD_DIR)/*.nfa $(BUILD_DIR)/*.dfa

# ============================================================================
# All Targets
# ============================================================================
all: dfa_test

# ============================================================================
# Build Directory
# ============================================================================
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# ============================================================================
# Build NFA from pattern file (ALWAYS rebuild - pattern files may change)
# ============================================================================
$(BUILD_DIR)/%.nfa: %.txt $(TOOLS_DIR)/nfa_builder | $(BUILD_DIR)
	@echo "  Building NFA: $< -> $@"
	$(TOOLS_DIR)/nfa_builder $< $@

# ============================================================================
# Build DFA from NFA with specific algorithm - Group 1 (Moore)
# ============================================================================
$(BUILD_DIR)/patterns_safe_commands.dfa: $(BUILD_DIR)/patterns_safe_commands.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-moore $< $@ 2>/dev/null

# ============================================================================
# Build DFA from NFA with specific algorithm - Group 2 (Hopcroft)
# ============================================================================
$(BUILD_DIR)/patterns_quantifier_comprehensive.dfa: $(BUILD_DIR)/patterns_quantifier_comprehensive.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_frag_quant.dfa: $(BUILD_DIR)/patterns_frag_quant.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_focused.dfa: $(BUILD_DIR)/patterns_focused.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_simple.dfa: $(BUILD_DIR)/patterns_simple.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_frag_plus.dfa: $(BUILD_DIR)/patterns_frag_plus.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_digit_test.dfa: $(BUILD_DIR)/patterns_digit_test.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_space_test.dfa: $(BUILD_DIR)/patterns_space_test.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_quantifier_test.dfa: $(BUILD_DIR)/patterns_quantifier_test.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_expanded_quantifier.dfa: $(BUILD_DIR)/patterns_expanded_quantifier.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_expanded_alternation.dfa: $(BUILD_DIR)/patterns_expanded_alternation.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_expanded_nested.dfa: $(BUILD_DIR)/patterns_expanded_nested.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_expanded_fragment.dfa: $(BUILD_DIR)/patterns_expanded_fragment.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_expanded_boundary.dfa: $(BUILD_DIR)/patterns_expanded_boundary.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_expanded_interactions.dfa: $(BUILD_DIR)/patterns_expanded_interactions.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_expanded_mixed.dfa: $(BUILD_DIR)/patterns_expanded_mixed.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_expanded_hard.dfa: $(BUILD_DIR)/patterns_expanded_hard.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_expanded_perf.dfa: $(BUILD_DIR)/patterns_expanded_perf.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_quantifier_simple.dfa: $(BUILD_DIR)/patterns_quantifier_simple.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_simple_quant.dfa: $(BUILD_DIR)/patterns_simple_quant.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-hopcroft $< $@ 2>/dev/null

# ============================================================================
# Build DFA from NFA with specific algorithm - Group 3 (Brzozowski)
# ============================================================================
$(BUILD_DIR)/patterns_acceptance_category_test.dfa: $(BUILD_DIR)/patterns_acceptance_category_test.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_admin_commands.dfa: $(BUILD_DIR)/patterns_admin_commands.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_caution_commands.dfa: $(BUILD_DIR)/patterns_caution_commands.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_modifying_commands.dfa: $(BUILD_DIR)/patterns_modifying_commands.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_dangerous_commands.dfa: $(BUILD_DIR)/patterns_dangerous_commands.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_network_commands.dfa: $(BUILD_DIR)/patterns_network_commands.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_combined.dfa: $(BUILD_DIR)/patterns_combined.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_minimal.dfa: $(BUILD_DIR)/patterns_minimal.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_step1.dfa: $(BUILD_DIR)/patterns_step1.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_step2.dfa: $(BUILD_DIR)/patterns_step2.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_step3.dfa: $(BUILD_DIR)/patterns_step3.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_test.dfa: $(BUILD_DIR)/patterns_test.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_debug.dfa: $(BUILD_DIR)/patterns_debug.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_with_captures.dfa: $(BUILD_DIR)/patterns_with_captures.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_capture_test.dfa: $(BUILD_DIR)/patterns_capture_test.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

$(BUILD_DIR)/patterns_capture_simple.dfa: $(BUILD_DIR)/patterns_capture_simple.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

# ============================================================================
# Build all NFA and DFA files (uses default Hopcroft for backward compatibility)
# ============================================================================
dfa: $(DFA_FILES)
	@echo ""
	@echo "================================================="
	@echo "DFA Build Complete"
	@echo "================================================="
	@echo "Built $(words $(DFA_FILES)) DFA files:"
	@for f in $(DFA_FILES); do echo "  - $$f"; done
	@echo ""

# ============================================================================
# Build DFA Test Runner (single test binary for all tests)
# ============================================================================
dfa_test: src/dfa_eval.c src/dfa_loader.c src/dfa_test.c
	$(CC) $(CFLAGS) -o $@ src/dfa_eval.c src/dfa_loader.c src/dfa_test.c $(LDFLAGS)

# ============================================================================
# Test: Group 1 - Moore Algorithm
# ============================================================================
test-moore: $(DFA_GROUP1) dfa_test
	@echo ""
	@echo "================================================="
	@echo "TEST SUITE: MOORE ALGORITHM (Group 1)"
	@echo "================================================="
	@./dfa_test $(PATTERN_GROUP1)
	@echo ""
	@echo "================================================="

# ============================================================================
# Test: Group 2 - Hopcroft Algorithm
# ============================================================================
test-hopcroft: $(DFA_GROUP2) dfa_test
	@echo ""
	@echo "================================================="
	@echo "TEST SUITE: HOPCROFT ALGORITHM (Group 2)"
	@echo "================================================="
	@./dfa_test $(PATTERN_GROUP2)
	@echo ""
	@echo "================================================="

# ============================================================================
# Test: Group 3 - Brzozowski Algorithm
# ============================================================================
test-brzozowski: $(DFA_GROUP3) dfa_test
	@echo ""
	@echo "================================================="
	@echo "TEST SUITE: BRZOZOWSKI ALGORITHM (Group 3)"
	@echo "================================================="
	@./dfa_test $(PATTERN_GROUP3)
	@echo ""
	@echo "================================================="

# ============================================================================
# Full Test Suite (runs all 3 groups with their respective algorithms)
# ============================================================================
test: clean-dfa dfa_test
	@echo ""
	@echo "================================================="
	@echo "C-DFA FULL TEST SUITE"
	@echo "================================================="
	@echo ""
	@echo "Group 1 (Moore):      $(words $(PATTERN_GROUP1)) pattern files"
	@echo "Group 2 (Hopcroft):  $(words $(PATTERN_GROUP2)) pattern files"
	@echo "Group 3 (Brzozowski): $(words $(PATTERN_GROUP3)) pattern files"
	@echo "Total:                $(words $(PATTERN_FILES)) pattern files"
	@echo ""
	@make test-moore 2>&1 | tail -5
	@echo ""
	@make test-hopcroft 2>&1 | tail -5
	@echo ""
	@make test-brzozowski 2>&1 | tail -5
	@echo ""
	@echo "================================================="
	@echo "ALL TESTS COMPLETE"
	@echo "================================================="

# ============================================================================
# Quick Test (runs test runner, builds DFAs on demand)
# ============================================================================
quick: dfa_test
	@echo ""
	@echo "================================================="
	@echo "Running DFA Quick Test..."
	@echo "================================================="
	@./dfa_test

# ============================================================================
# Validate All Patterns
# ============================================================================
validate:
	@echo "================================================="
	@echo "Validating All Pattern Files"
	@echo "================================================="
	@for f in $(PATTERN_FILES); do \
		echo -n "Validating $$f... "; \
		if $(TOOLS_DIR)/nfa_builder --validate-only $$f 2>/dev/null; then \
			echo "OK"; \
		else \
			echo "FAILED"; \
		fi; \
	done
	@echo ""
	@echo "All patterns validated."

# ============================================================================
# Build Summary
# ============================================================================
summary: dfa
	@echo ""
	@echo "================================================="
	@echo "C-DFA Build Summary"
	@echo "================================================="
	@echo ""
	@echo "Pattern Files ($(words $(PATTERN_FILES))):"
	@for f in $(PATTERN_FILES); do echo "  - $$f"; done
	@echo ""
	@echo "Built DFA Files (in $(BUILD_DIR)/):"
	@for f in $(DFA_FILES); do echo "  - $$f"; done
	@echo ""
	@echo "To run tests: make test"
	@echo "To validate patterns: make validate"
	@echo "================================================="

# ============================================================================
# Help
# ============================================================================
help:
	@echo ""
	@echo "================================================="
	@echo "ReadOnlyBox C-DFA Build System"
	@echo "================================================="
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build dfa_test (default)"
	@echo "  dfa              - Build all DFA files from patterns"
	@echo "  test             - Run full test suite (all 3 algorithms)"
	@echo "  quick            - Run tests (builds DFAs on demand)"
	@echo "  test-moore       - Run Group 1 tests (Moore algorithm)"
	@echo "  test-hopcroft    - Run Group 2 tests (Hopcroft algorithm)"
	@echo "  test-brzozowski  - Run Group 3 tests (Brzozowski algorithm)"
	@echo "  validate         - Validate all pattern files"
	@echo "  summary          - Show build summary"
	@echo "  clean            - Remove build artifacts"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Pattern Groups:"
	@echo "  Group 1 (Moore):      $(words $(PATTERN_GROUP1)) files - Core safe/caution commands"
	@echo "  Group 2 (Hopcroft):   $(words $(PATTERN_GROUP2)) files - Quantifiers and fragments"
	@echo "  Group 3 (Brzozowski): $(words $(PATTERN_GROUP3)) files - Categories and captures"
	@echo ""
	@echo "Examples:"
	@echo "  make test             # Run all tests with all algorithms"
	@echo "  make test-moore      # Run only Group 1 with Moore"
	@echo "  make test-hopcroft   # Run only Group 2 with Hopcroft"
	@echo "  make test-brzozowski # Run only Group 3 with Brzozowski"
	@echo "  make validate        # Check all patterns are valid"
	@echo "================================================="

# ============================================================================
# Clean
# ============================================================================
clean:
	rm -f $(TARGETS) $(BUILD_DIR)/*.o $(BUILD_DIR)/*.dfa $(BUILD_DIR)/*.nfa
	rm -rf $(BUILD_DIR)
	@echo "Cleaned build artifacts."
