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
CFLAGS = -Wall -Wextra -std=gnu11 -O2 -I. -I../c-dfa/include -I../rbox-preload -I../shellsplit/include -I../rbox-protocol/include -I../rbox-ruleset/include -DRELATIVE_ENTROPY_NO_MAIN
LDFLAGS = -lpthread -lm

# Libraries (use shared library - rbox-protocol includes shellsplit in .so)
LDFLAGS += -L../rbox-protocol -lrbox_protocol
LDFLAGS += ../rbox-ruleset/build/lib/liblandlock-builder.a
LDFLAGS += ../c-dfa/build/lib/libreadonlybox_dfa.a
LDFLAGS += ../c-dfa/build/lib_eval/libreadonlybox_dfa_eval.a

# Unified CLI tool
CDFATOOL = ../c-dfa/build/tools/cdfatool

# Build directory for generated files
BUILD_DIR = build

# Pattern and DFA files
PATTERN_FILE = rbox_ptrace_embedded_commands.txt
DFA_FILE = $(BUILD_DIR)/rbox_ptrace.dfa
DFA_DATA_C = $(BUILD_DIR)/rbox_ptrace_dfa.c

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
       trampoline_allowance.c \
       soft_ruleset_access.c \
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

# Ensure c-dfa is built via CMake
C_DFA_BUILD := ../c-dfa/build
$(C_DFA_BUILD):
	cd ../c-dfa && cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build

# Validate prerequisites
check-prereqs: | $(C_DFA_BUILD)
	@which $(CC) > /dev/null 2>&1 || (echo "ERROR: $(CC) not found"; exit 1)
	@test -x $(CDFATOOL) || (echo "ERROR: cdfatool not found (run 'make deps' in ../c-dfa first)"; exit 1)
	@which valgrind > /dev/null 2>&1 || echo "WARNING: valgrind not installed (valgrind target will be skipped)"
	@which cppcheck > /dev/null 2>&1 || echo "WARNING: cppcheck not installed (cppcheck target will be skipped)"

# Build DFA from pattern file using cdfatool (direct: pattern -> DFA -> C array)
dfa: $(BUILD_DIR) $(DFA_FILE) $(DFA_DATA_C)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(DFA_FILE): $(CDFATOOL) $(PATTERN_FILE) | $(BUILD_DIR)
	$(CDFATOOL) compile $(PATTERN_FILE) -o $(DFA_FILE)

$(DFA_DATA_C): $(DFA_FILE)
	$(CDFATOOL) embedd $(DFA_FILE) -o $(DFA_DATA_C)

$(TARGET): $(OBJS) ../c-dfa/build/lib_eval/libreadonlybox_dfa_eval.a ../rbox-ruleset/build/lib/liblandlock-builder.a
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
