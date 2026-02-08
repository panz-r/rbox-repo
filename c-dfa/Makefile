# ============================================================================
# ReadOnlyBox DFA Build System
# ============================================================================
# Builds NFA and DFA files from pattern specifications
# Runs comprehensive test suite
# ============================================================================

CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -Iinclude -O2
LDFLAGS = -lm

SRC_DIR = src
TOOLS_DIR = tools
INCLUDE_DIR = include
BUILD_DIR = build

TARGETS = dfa_test

# ============================================================================
# Build Tools (if source is newer than binary)
# ============================================================================
$(TOOLS_DIR)/nfa_builder: $(TOOLS_DIR)/nfa_builder.c
	$(CC) $(CFLAGS) -o $@ $<

$(TOOLS_DIR)/nfa2dfa_advanced: $(TOOLS_DIR)/nfa2dfa.c $(TOOLS_DIR)/dfa_minimize.c $(TOOLS_DIR)/dfa_minimize_brzozowski.c
	$(CC) $(CFLAGS) -o $@ $(TOOLS_DIR)/nfa2dfa.c $(TOOLS_DIR)/dfa_minimize.c $(TOOLS_DIR)/dfa_minimize_brzozowski.c

# ============================================================================
# All Pattern Files (used by test runner)
# ============================================================================
PATTERN_FILES = \
	patterns_safe_commands.txt \
	patterns_quantifier_comprehensive.txt \
	patterns_frag_quant.txt \
	patterns_focused.txt \
	patterns_simple.txt \
	patterns_acceptance_category_test.txt \
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
	patterns_admin_commands.txt \
	patterns_caution_commands.txt \
	patterns_modifying_commands.txt \
	patterns_dangerous_commands.txt \
	patterns_network_commands.txt \
	patterns_combined.txt \
	patterns_minimal.txt \
	patterns_quantifier_simple.txt \
	patterns_simple_quant.txt \
	patterns_step1.txt \
	patterns_step2.txt \
	patterns_step3.txt \
	patterns_test.txt \
	patterns_debug.txt \
	patterns_with_captures.txt \
	patterns_capture_test.txt \
	patterns_capture_simple.txt

# Pattern file to DFA file mapping
# Each pattern file builds a DFA in build/ directory
DFA_FILES = $(patsubst %.txt,$(BUILD_DIR)/%.dfa,$(PATTERN_FILES))
NFA_FILES = $(patsubst %.txt,$(BUILD_DIR)/%.nfa,$(PATTERN_FILES))

# ============================================================================
# Phony Targets
# ============================================================================
.PHONY: all clean test test-full validate help FORCE clean-dfa

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
	@$(TOOLS_DIR)/nfa_builder $< $@ 2>/dev/null

# ============================================================================
# Build DFA from NFA (ALWAYS rebuild - NFA may change)
# ============================================================================
$(BUILD_DIR)/%.dfa: $(BUILD_DIR)/%.nfa $(TOOLS_DIR)/nfa2dfa_advanced
	@echo "  Building DFA: $< -> $@"
	@$(TOOLS_DIR)/nfa2dfa_advanced --minimize-brzozowski $< $@ 2>/dev/null

# ============================================================================
# Build all NFA and DFA files
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
# Quick Test (runs test runner, builds DFAs on demand)
# ============================================================================
quick: dfa_test
	@echo ""
	@echo "================================================="
	@echo "Running DFA Quick Test..."
	@echo "================================================="
	@./dfa_test

# ============================================================================
# Full Test Suite (always rebuilds DFAs from patterns, then runs tests)
# ============================================================================
test: clean-dfa dfa dfa_test
	@echo ""
	@echo "================================================="
	@echo "C-DFA TEST SUITE"
	@echo "================================================="
	@echo "Pattern Files: $(words $(PATTERN_FILES))"
	@echo "DFA Files: $(words $(DFA_FILES))"
	@echo ""
	@./dfa_test
	@echo ""
	@echo "================================================="
	@echo "Test files are in: $(BUILD_DIR)/"
	@echo "================================================="

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
	@echo "  all           - Build dfa_test (default)"
	@echo "  dfa           - Build all DFA files from patterns"
	@echo "  test          - Build DFAs and run full test suite"
	@echo "  quick         - Run tests (builds DFAs on demand)"
	@echo "  validate      - Validate all pattern files"
	@echo "  summary       - Show build summary"
	@echo "  clean         - Remove build artifacts"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "Pattern Files: $(words $(PATTERN_FILES))"
	@echo ""
	@echo "Examples:"
	@echo "  make test          # Build and run all tests"
	@echo "  make validate      # Check all patterns are valid"
	@echo "  make summary       # Show what's been built"
	@echo "================================================="

# ============================================================================
# Clean
# ============================================================================
clean:
	rm -f $(TARGETS) $(BUILD_DIR)/*.o $(BUILD_DIR)/*.dfa $(BUILD_DIR)/*.nfa
	rm -rf $(BUILD_DIR)
	@echo "Cleaned build artifacts."
