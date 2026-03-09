# Makefile for readonlybox-ptrace

CC = gcc
CFLAGS = -Wall -Wextra -std=gnu11 -O2 -I. -I../../c-dfa/include -I../../internal/client -I../../shellsplit/include -DRELATIVE_ENTROPY_NO_MAIN
LDFLAGS = -lpthread -lm

# Source files
SRCS = main.c \
       syscall_handler.c \
       memory.c \
       validation.c \
       dfa.c \
       readonlybox_dfa_data.c \
       ../../c-dfa/src/dfa_eval.c \
       ../../c-dfa/src/dfa_loader.c \
       ../../shellsplit/src/env_screener.c \
       ../../shellsplit/src/relative_permutation_entropy.c \
       ../../shellsplit/src/shell_tokenizer.c

# Object files
OBJS = $(SRCS:.c=.o)

# Target binary
TARGET = readonlybox-ptrace

.PHONY: all clean test test-e2e test-memory test-syscall test-validation test-integration test-verbose list debug coverage cppcheck valgrind

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Special rule for c-dfa sources
../../c-dfa/src/%.o: ../../c-dfa/src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS) *.o

# Debug build
debug: CFLAGS = -Wall -Wextra -std=gnu11 -g -O0 -I. -I../../c-dfa/include -I../../internal/client -I../../shellsplit/include -DDEBUG
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
