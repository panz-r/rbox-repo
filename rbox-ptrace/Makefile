# Makefile for readonlybox-ptrace

CC = gcc
CFLAGS = -Wall -Wextra -std=gnu11 -O2 -I. -I../c-dfa/include -I../internal/client -I../shellsplit/include -I../rbox-protocol/include -DRELATIVE_ENTROPY_NO_MAIN
LDFLAGS = -lpthread -lm

# Add rbox-protocol library
LDFLAGS += ../rbox-protocol/librbox_protocol.a

# DFA build tools
NFA_BUILDER = ../c-dfa/tools/nfa_builder
NFA2DFA = ../c-dfa/tools/nfa2dfa_advanced
DFA2C = ../c-dfa/tools/dfa2c_array

# Pattern file and output files
PATTERN_FILE = rbox_ptrace_embedded_commands.txt
NFA_FILE = rbox_ptrace.nfa
DFA_FILE = rbox_ptrace.dfa
DFA_DATA_C = rbox_ptrace_dfa_data.c

# Source files
SRCS = main.c \
       syscall_handler.c \
       memory.c \
       validation.c \
       dfa.c \
       privilege.c \
       env.c \
       pkexec.c \
       judge.c \
       $(DFA_DATA_C) \
       ../c-dfa/src/dfa_eval.c \
       ../shellsplit/src/env_screener.c \
       ../shellsplit/src/relative_permutation_entropy.c \
       ../shellsplit/src/shell_tokenizer.c

# Object files
OBJS = $(SRCS:.c=.o)

# Target binary
TARGET = readonlybox-ptrace

.PHONY: all clean test test-e2e test-memory test-syscall test-validation test-integration test-verbose list debug coverage cppcheck valgrind compile_commands dfa

all: dfa $(TARGET)

# Build DFA from pattern file
dfa: $(DFA_DATA_C)

$(NFA_FILE): $(PATTERN_FILE)
	$(NFA_BUILDER) $(PATTERN_FILE) $(NFA_FILE)

$(DFA_FILE): $(NFA_FILE)
	$(NFA2DFA) $(NFA_FILE) $(DFA_FILE)

$(DFA_DATA_C): $(DFA_FILE) $(DFA2C)
	$(DFA2C) $(DFA_FILE) $(DFA_DATA_C) rbox_ptrace_dfa_data

# Generate compile_commands.json using bear
compile_commands:
	bear -- $(MAKE) clean all 2>/dev/null || true

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Special rule for c-dfa sources
../c-dfa/src/%.o: ../c-dfa/src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS) *.o $(NFA_FILE) $(DFA_FILE) $(DFA_DATA_C)

# Debug build
debug: CFLAGS = -Wall -Wextra -std=gnu11 -g -O0 -I. -I../c-dfa/include -I../internal/client -I../shellsplit/include -DDEBUG
debug: $(TARGET)

# Test targets - delegate to tests subdirectory
test: $(TARGET)
	$(MAKE) -C tests test

test-e2e: $(TARGET)
	$(MAKE) -C tests test-e2e

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
