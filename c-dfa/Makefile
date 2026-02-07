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
	@$(TOOLS_DIR)/nfa_builder --validate-only $(PATTERN_FILE) || (echo "ERROR: Pattern validation failed!"; exit 1)
	@echo ""

# ============================================================================
# Build Targets
# ============================================================================

all: dfa_test

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build DFA test
dfa_test: src/dfa_eval.c src/dfa_loader.c src/dfa_test.c src/dfa_test_tripled.c
	$(CC) $(CFLAGS) -o $@ src/dfa_eval.c src/dfa_loader.c src/dfa_test.c src/dfa_test_tripled.c $(LDFLAGS)

# Build comprehensive test
comprehensive_test: $(BUILD_DIR) src/shell_tokenizer.c src/shell_tokenizer_ext.c src/shell_processor.c src/shell_transform.c src/readonlybox.c src/dfa_eval.c src/dfa_loader.c src/comprehensive_test.c
	$(CC) $(CFLAGS) -o $@ src/shell_tokenizer.c src/shell_tokenizer_ext.c src/shell_processor.c src/shell_transform.c src/readonlybox.c src/dfa_eval.c src/dfa_loader.c src/comprehensive_test.c

# Clean
clean:
	rm -f $(TARGETS) $(BUILD_DIR)/*.o $(BUILD_DIR)/*.dfa $(BUILD_DIR)/*.nfa
	rm -rf $(BUILD_DIR)

# Test
test: dfa dfa_test
	@echo ""
	@echo "================================================="
	@echo "Running DFA test..."
	@echo "================================================="
	@cp build/readonlybox.dfa .
	@./dfa_test --quantifier-test
	@rm -f readonlybox.dfa

# Build DFA (if tools are available)
dfa: $(BUILD_DIR)
	@echo "Building DFA..."
	@cd $(BUILD_DIR) && ../tools/nfa_builder ../$(PATTERN_FILE) readonlybox.nfa
	@cd $(BUILD_DIR) && ../tools/nfa2dfa_advanced readonlybox.nfa readonlybox.dfa
	@echo ""
	@echo "DFA built successfully: $(PATTERN_FILE) -> build/readonlybox.dfa"

# Quick test (with validation)
quick: dfa_test
	@echo ""
	@echo "================================================="
	@echo "Running quick DFA test..."
	@echo "================================================="
	@./dfa_test