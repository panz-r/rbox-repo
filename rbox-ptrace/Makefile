# Makefile for readonlybox-ptrace
# Builds the readonlybox-ptrace binary and its DFA data from pattern files.
# Usage:
#   make          # Build readonlybox-ptrace (default)
#   make debug    # Build with debug symbols
#   make clean    # Remove all build artifacts
#   make test     # Run all tests
#   make coverage # Generate coverage report

.DELETE_ON_ERROR:
.SECONDARY:

# Compiler
CC = gcc
CFLAGS = -Wall -Wextra -std=gnu11 -O2 -I. -I../c-dfa/include -I../rbox-preload -I../shellsplit/include -I../rbox-protocol/include -DRELATIVE_ENTROPY_NO_MAIN
LDFLAGS = -lpthread -lm

# Libraries (use shared library - rbox-protocol includes shellsplit in .so)
LDFLAGS += -L../rbox-protocol -lrbox_protocol
LDFLAGS += ../c-dfa/libdfa_eval.a

# DFA Tools
NFA_BUILDER = ../c-dfa/tools/nfa_builder
NFA2DFA = ../c-dfa/tools/nfa2dfa_advanced
DFA2C = ../c-dfa/tools/dfa2c_array

# Build directory for generated files
BUILD_DIR = build

# Pattern and DFA files
PATTERN_FILE = rbox_ptrace_embedded_commands.txt
NFA_FILE = $(BUILD_DIR)/rbox_ptrace.nfa
DFA_FILE = $(BUILD_DIR)/rbox_ptrace.dfa
DFA_DATA_C = $(BUILD_DIR)/rbox_ptrace_dfa_data.c

# Source files
SRCS = main.c \
       progname.c \
       syscall_handler.c \
       memory.c \
       validation.c \
       dfa.c \
       privilege.c \
       sandbox.c \
       env.c \
       pkexec.c \
       judge.c \
       soft_policy.c \
       trampoline_allowance.c \
       $(DFA_DATA_C) \
       ../shellsplit/src/env_screener.c \
       ../shellsplit/src/relative_permutation_entropy.c

# Object files
OBJS = $(SRCS:.c=.o)

# Target binary
TARGET = readonlybox-ptrace

.PHONY: all clean debug test test-e2e test-memory test-syscall test-validation test-integration test-verbose list coverage cppcheck valgrind dfa help check-prereqs

# Allow parallel builds with -j
ifeq ($(filter -j%,$(MAKEFLAGS)),)
MAKEFLAGS += -j$(shell nproc 2>/dev/null || echo 1)
endif

all: check-prereqs dfa
	$(MAKE) $(TARGET)

# Validate prerequisites
check-prereqs:
	@which $(CC) > /dev/null 2>&1 || (echo "ERROR: $(CC) not found"; exit 1)
	@test -x $(NFA_BUILDER) || (echo "ERROR: nfa_builder not found (run 'make deps' in ../c-dfa first)"; exit 1)
	@test -x $(NFA2DFA) || (echo "ERROR: nfa2dfa_advanced not found (run 'make deps' in ../c-dfa first)"; exit 1)
	@test -x $(DFA2C) || (echo "ERROR: dfa2c_array not found (run 'make deps' in ../c-dfa first)"; exit 1)
	@which valgrind > /dev/null 2>&1 || echo "WARNING: valgrind not installed (valgrind target will be skipped)"
	@which cppcheck > /dev/null 2>&1 || echo "WARNING: cppcheck not installed (cppcheck target will be skipped)"

# Build DFA from pattern file
dfa: $(BUILD_DIR) $(NFA_FILE) $(DFA_FILE) $(DFA_DATA_C)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(NFA_FILE): $(PATTERN_FILE) | $(BUILD_DIR)
	$(NFA_BUILDER) $(PATTERN_FILE) $(NFA_FILE)

$(DFA_FILE): $(NFA_FILE)
	$(NFA2DFA) $(NFA_FILE) $(DFA_FILE)

$(DFA_DATA_C): $(DFA_FILE) $(DFA2C)
	$(DFA2C) $(DFA_FILE) $(DFA_DATA_C) rbox_ptrace_dfa

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Special rule for c-dfa sources
../c-dfa/src/%.o: ../c-dfa/src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Debug build
debug: CFLAGS += -g -O0 -DDEBUG
debug: $(TARGET)

clean:
	rm -f $(TARGET) $(OBJS) *.o
	rm -rf $(BUILD_DIR)
	rm -f ../c-dfa/src/dfa_eval.o ../shellsplit/src/env_screener.o ../shellsplit/src/relative_permutation_entropy.o ../shellsplit/src/shell_tokenizer.o

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build readonlybox-ptrace (default)"
	@echo "  debug        - Build with debug symbols"
	@echo "  clean        - Remove all build artifacts"
	@echo "  test         - Run all tests (excludes e2e)"
	@echo "  test-e2e     - Run end-to-end tests"
	@echo "  test-with-caps - Run e2e tests (requires setcap first)"
	@echo "  test-memory  - Run memory tests"
	@echo "  test-syscall - Run syscall tests"
	@echo "  test-validation - Run validation tests"
	@echo "  test-integration - Run integration tests"
	@echo "  test-verbose - Run verbose tests"
	@echo "  list         - List test cases"
	@echo "  coverage     - Generate coverage report"
	@echo "  cppcheck     - Run cppcheck static analysis"
	@echo "  valgrind     - Run valgrind memory checker"
	@echo "  dfa          - Build DFA data"
	@echo "  check-prereqs - Verify required tools exist"

# Test targets - delegate to tests subdirectory
test: $(TARGET)
	$(MAKE) -C tests test

test-e2e: $(TARGET)
	$(MAKE) -C tests test-e2e

test-with-caps: $(TARGET)
	$(MAKE) -C tests test-with-caps

test-memory: $(TARGET)
	$(MAKE) -C tests test-memory

test-syscall: $(TARGET)
	$(MAKE) -C tests test-syscall

test-validation: $(TARGET)
	$(MAKE) -C tests test-validation

test-integration: $(TARGET)
	$(MAKE) -C tests test-integration

test-verbose: $(TARGET)
	$(MAKE) -C tests test-verbose

list: $(TARGET)
	$(MAKE) -C tests list

# Advanced test targets
coverage: $(TARGET)
	$(MAKE) -C tests coverage

cppcheck: $(TARGET)
	$(MAKE) -C tests cppcheck

valgrind: $(TARGET)
	$(MAKE) -C tests valgrind
