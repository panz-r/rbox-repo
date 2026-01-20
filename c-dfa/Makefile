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
TARGETS = tokenizer_test comprehensive_test

.PHONY: all clean test

all: $(TARGETS)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build tokenizer test
tokenizer_test: $(BUILD_DIR) src/shell_tokenizer.c src/tokenizer_test.c
	$(CC) $(CFLAGS) -o $@ src/shell_tokenizer.c src/tokenizer_test.c

# Build comprehensive test
comprehensive_test: $(BUILD_DIR) src/shell_tokenizer.c src/shell_tokenizer_ext.c src/shell_processor.c src/shell_transform.c src/readonlybox.c src/dfa_eval.c src/dfa_loader.c src/comprehensive_test.c
	$(CC) $(CFLAGS) -o $@ src/shell_tokenizer.c src/shell_tokenizer_ext.c src/shell_processor.c src/shell_transform.c src/readonlybox.c src/dfa_eval.c src/dfa_loader.c src/comprehensive_test.c

# Clean
clean:
	rm -f $(TARGETS) $(BUILD_DIR)/*.o $(BUILD_DIR)/*.dfa $(BUILD_DIR)/*.nfa
	rm -rf $(BUILD_DIR)

# Test
test: $(TARGETS)
	@echo "Running tokenizer test..."
	@./tokenizer_test "cat xx | less -G > rsr"
	@echo ""
	@echo "Running comprehensive test..."
	@./comprehensive_test

# Build DFA (if tools are available)
dfa: $(BUILD_DIR)
	@echo "Building DFA..."
	@cd $(BUILD_DIR) && ../tools/nfa_builder ../tools/commands.txt
	@cd $(BUILD_DIR) && ../tools/nfa2dfa_advanced readonlybox.nfa readonlybox.dfa

# Build DFA with alphabet optimization
dfa-alphabet: $(BUILD_DIR)
	@echo "Building DFA with alphabet optimization..."
	@cd $(BUILD_DIR) && ../tools/alphabet_constructor ../test_commands.txt alphabet.map
	@cd $(BUILD_DIR) && ../tools/nfa_builder_with_alphabet alphabet.map ../test_commands.txt readonlybox_alphabet.nfa
	@cd $(BUILD_DIR) && ../tools/nfa2dfa_with_alphabet readonlybox_alphabet.nfa readonlybox_alphabet.dfa

# Quick test
quick: tokenizer_test
	@./tokenizer_test "cat xx | less -G > rsr"

# Specific example test
specific: specific_test
	@./specific_test

# Separation test
separation: separation_test
	@./separation_test

# Extended tokenizer test
extended: extended_test
	@./extended_test

# Transformation test
transform: transform_test
	@./transform_test

# Pipeline test
pipeline: pipeline_test
	@./pipeline_test