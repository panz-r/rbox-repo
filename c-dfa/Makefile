# Simple Makefile for ReadOnlyBox DFA

CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -Iinclude -O2
LDFLAGS = -lm

# Source files
SRC_DIR = src
TOOLS_DIR = tools
INCLUDE_DIR = include

# Build directory
BUILD_DIR = build

# Targets
TARGETS = dfa_test

.PHONY: all clean test

# Pattern file
PATTERN_FILE = patterns_safe_commands.txt

# ============================================================================
# Pattern Validation
# ============================================================================

# Validate patterns before building
validate-patterns:
	@echo "================================================="
	@echo "Validating patterns in $(PATTERN_FILE)..."
	@echo "================================================="
	@$(TOOLS_DIR)/validate_patterns.sh $(PATTERN_FILE) || (echo "ERROR: Pattern validation failed!"; exit 1)
	@echo ""

# ============================================================================
# Build Targets
# ============================================================================

all: dfa_test

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build DFA test
dfa_test: src/dfa_eval.c src/dfa_loader.c src/dfa_test.c
	$(CC) $(CFLAGS) -o $@ src/dfa_eval.c src/dfa_loader.c src/dfa_test.c $(LDFLAGS)

# Build comprehensive test
comprehensive_test: $(BUILD_DIR) src/shell_tokenizer.c src/shell_tokenizer_ext.c src/shell_processor.c src/shell_transform.c src/readonlybox.c src/dfa_eval.c src/dfa_loader.c src/comprehensive_test.c
	$(CC) $(CFLAGS) -o $@ src/shell_tokenizer.c src/shell_tokenizer_ext.c src/shell_processor.c src/shell_transform.c src/readonlybox.c src/dfa_eval.c src/dfa_loader.c src/comprehensive_test.c

# Clean
clean:
	rm -f $(TARGETS) $(BUILD_DIR)/*.o $(BUILD_DIR)/*.dfa $(BUILD_DIR)/*.nfa
	rm -rf $(BUILD_DIR)

# Test
test: dfa_test validate-patterns
	@echo ""
	@echo "================================================="
	@echo "Running DFA test..."
	@echo "================================================="
	@./dfa_test

# Build DFA (if tools are available)
dfa: validate-patterns $(BUILD_DIR)
	@echo "Building DFA..."
	@cd $(BUILD_DIR) && ../tools/nfa_builder ../alphabet.map ../$(PATTERN_FILE) readonlybox.nfa
	@cd $(BUILD_DIR) && ../tools/nfa2dfa_advanced readonlybox.nfa readonlybox.dfa
	@echo ""
	@echo "DFA built successfully: $(PATTERN_FILE) -> build/readonlybox.dfa"

# Build DFA with alphabet optimization
dfa-alphabet: validate-patterns $(BUILD_DIR)
	@echo "Building DFA with alphabet optimization..."
	@cd $(BUILD_DIR) && ../tools/alphabet_constructor ../$(PATTERN_FILE) alphabet.map
	@cd $(BUILD_DIR) && ../tools/nfa_builder_with_alphabet alphabet.map ../$(PATTERN_FILE) readonlybox_alphabet.nfa
	@cd $(BUILD_DIR) && ../tools/nfa2dfa_with_alphabet readonlybox_alphabet.nfa readonlybox_alphabet.dfa

# Quick test (with validation)
quick: dfa_test validate-patterns
	@echo ""
	@echo "================================================="
	@echo "Running quick DFA test..."
	@echo "================================================="
	@./dfa_test