# Makefile for ptrace client unit tests

.DELETE_ON_ERROR:
.SECONDARY:

# Compiler and Flags
CC = gcc
CFLAGS = -Wall -Wextra -std=gnu11 -O2 -I.. -I../../c-dfa/include -I../../rbox-preload -I../../shellsplit/include -I../../rbox-protocol/include -DRELATIVE_ENTROPY_NO_MAIN
LDFLAGS = -lpthread -lm

# Pre-built libraries
LIBS = ../../c-dfa/libdfa_eval.a \
       ../../rbox-protocol/librbox_protocol.a

# Test source files
TEST_SRCS = test_main.c \
            test_memory.c \
            test_syscall_handler.c \
            test_validation.c \
            test_integration.c \
            test_e2e.c \
            test_sandbox.c \
            debug.c

# Source files from parent directory (excluding main.c)
SRCS = ../memory.c \
       ../syscall_handler.c \
       ../validation.c \
       ../dfa.c \
       ../privilege.c \
       ../sandbox.c \
       ../env.c \
       ../pkexec.c \
       ../judge.c \
       ../build/rbox_ptrace_dfa_data.c \
       ../../shellsplit/src/env_screener.c \
       ../../shellsplit/src/relative_permutation_entropy.c \
       ../../shellsplit/src/shell_tokenizer.c

# Object files
TEST_OBJS = $(TEST_SRCS:.c=.o)
OBJS = $(SRCS:.c=.o)

# Target binary
TARGET = test_runner

.PHONY: all clean test test-verbose test-memory test-syscall test-validation test-integration test-e2e list help check-prereqs validate-test-runner debug coverage cppcheck valgrind

# Default target
all: check-prereqs validate-test-runner $(TARGET)

# Check prerequisites
check-prereqs:
	@test -f ../memory.c || (echo "ERROR: ../memory.c not found"; exit 1)
	@test -f ../syscall_handler.c || (echo "ERROR: ../syscall_handler.c not found"; exit 1)
	@test -f ../../c-dfa/libdfa_eval.a || (echo "ERROR: libdfa_eval.a not found (run 'make' in ../../c-dfa first)"; exit 1)
	@test -f ../../shellsplit/libshellsplit.a || (echo "ERROR: libshellsplit.a not found (run 'make' in ../../shellsplit first)"; exit 1)
	@which $(CC) > /dev/null 2>&1 || (echo "ERROR: $(CC) not found"; exit 1)
	@which valgrind > /dev/null 2>&1 || echo "WARNING: valgrind not installed (valgrind target will be skipped)"
	@which cppcheck > /dev/null 2>&1 || echo "WARNING: cppcheck not installed (cppcheck target will be skipped)"

# Build test runner
$(TARGET): $(TEST_OBJS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

# Compile test source files
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile parent directory source files
../%.o: ../%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# dfa.o depends on rbox_ptrace_dfa_data.c
../dfa.o: ../dfa.c ../build/rbox_ptrace_dfa_data.c

# Compile shellsplit source files
../../shellsplit/src/%.o: ../../shellsplit/src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Run all unit tests (excluding e2e)
test: $(TARGET)
	./$(TARGET)

# Run tests with verbose output
test-verbose: $(TARGET)
	./$(TARGET) -v

# Run only memory tests
test-memory: $(TARGET)
	./$(TARGET) memory

# Run only syscall handler tests
test-syscall: $(TARGET)
	./$(TARGET) syscall

# Run only validation tests
test-validation: $(TARGET)
	./$(TARGET) validation

# Run only integration tests
test-integration: $(TARGET)
	./$(TARGET) integration

# Run end-to-end tests (requires server binary)
test-e2e: $(TARGET)
	./$(TARGET) e2e

# List available test suites
list: $(TARGET)
	./$(TARGET) -l

# Validate test runner supports required arguments
validate-test-runner: $(TARGET)
	@./$(TARGET) -h > /dev/null 2>&1 || (echo "ERROR: test_runner does not support -h"; exit 1)

# Show help
help:
	@echo "ReadOnlyBox Ptrace Client Unit Tests"
	@echo ""
	@echo "Targets:"
	@echo "  all              Build the test runner (default)"
	@echo "  test             Run unit tests (excludes e2e)"
	@echo "  test-verbose     Run all tests with verbose output"
	@echo "  test-memory      Run only memory tests"
	@echo "  test-syscall     Run only syscall handler tests"
	@echo "  test-validation  Run only validation tests"
	@echo "  test-integration Run only integration tests"
	@echo "  test-e2e         Run end-to-end tests (requires server)"
	@echo "  list             List available test suites"
	@echo "  debug            Build with debug flags"
	@echo "  coverage         Build with coverage and run tests"
	@echo "  cppcheck         Run static analysis (if cppcheck installed)"
	@echo "  valgrind         Run memory check (if valgrind installed)"
	@echo "  clean            Remove built files"
	@echo "  help             Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make test                    Run unit tests"
	@echo "  make test-e2e                Run end-to-end tests"
	@echo "  make test-memory syscall      Run memory and syscall tests"
	@echo "  make debug                   Build with debug symbols"

# Clean build files
clean:
	$(RM) $(TARGET) $(TEST_OBJS) $(OBJS) ../*.o

# Debug build (inherits base CFLAGS and adds debug flags)
debug: CFLAGS += -g -O0 -DDEBUG
debug: $(TARGET)

# Coverage build (inherits base CFLAGS and adds coverage flags)
coverage: CFLAGS += -g -O0 --coverage
coverage: LDFLAGS += --coverage
coverage: clean $(TARGET)
	./$(TARGET)
	gcov $(TEST_SRCS) $(SRCS) 2>/dev/null || echo "Note: gcov output not available"

# Static analysis with cppcheck (if available)
cppcheck:
	@which cppcheck > /dev/null 2>&1 && cppcheck --enable=all --suppress=missingIncludeSystem \
		-I.. -I../../c-dfa/include -I../../rbox-preload \
		$(TEST_SRCS) $(SRCS) || echo "cppcheck not installed (skipping)"

# Valgrind memory check (if available)
valgrind: $(TARGET)
	@which valgrind > /dev/null 2>&1 && valgrind --leak-check=full --show-leak-kinds=all \
		--track-origins=yes ./$(TARGET) || echo "valgrind not installed (skipping)"
