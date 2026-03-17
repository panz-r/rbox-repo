# Makefile for ptrace client unit tests

CC = gcc
CFLAGS = -Wall -Wextra -std=gnu11 -O2 -I.. -I../../../c-dfa/include -I../../../internal/client -I../../../shellsplit/include -I../../../rbox-protocol/include
LDFLAGS = -lpthread -lm

# Test source files
TEST_SRCS = test_main.c \
            test_memory.c \
            test_syscall_handler.c \
            test_validation.c \
            test_integration.c \
            test_e2e.c

# Source files from parent directory (excluding main.c)
SRCS = ../memory.c \
       ../syscall_handler.c \
       ../validation.c \
       ../dfa.c \
       ../main.c \
       ../readonlybox_dfa_data.c \
       ../../../c-dfa/src/dfa_eval.c \
       ../../../c-dfa/src/dfa_loader.c \
       ../../../shellsplit/src/shell_tokenizer.c

# Object files
TEST_OBJS = $(TEST_SRCS:.c=.o)
OBJS = $(SRCS:.c=.o)

# Target binary
TARGET = test_runner

.PHONY: all clean test test-verbose test-memory test-syscall test-validation test-integration test-e2e list help

# Default target
all: $(TARGET)

# Build test runner
$(TARGET): $(TEST_OBJS) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile test source files
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile parent directory source files
../%.o: ../%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile c-dfa source files
../../../c-dfa/src/%.o: ../../../c-dfa/src/%.c
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
	@echo "  clean            Remove built files"
	@echo "  help             Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make test                    Run unit tests"
	@echo "  make test-e2e                Run end-to-end tests"
	@echo "  ./test_runner memory syscall Run memory and syscall tests"
	@echo "  ./test_runner e2e            Run end-to-end tests"

# Clean build files
clean:
	rm -f $(TARGET) $(TEST_OBJS) $(OBJS) ../*.o ../../../c-dfa/src/*.o

# Debug build
debug: CFLAGS = -Wall -Wextra -std=gnu11 -g -O0 -I.. -I../../../c-dfa/include -I../../../internal/client -DDEBUG
debug: $(TARGET)

# Coverage build (requires gcov)
coverage: CFLAGS = -Wall -Wextra -std=gnu11 -g -O0 -I.. -I../../../c-dfa/include -I../../../internal/client --coverage
coverage: LDFLAGS = -lpthread -lm --coverage
coverage: clean $(TARGET)
	./$(TARGET)
	gcov $(TEST_SRCS) $(SRCS)

# Static analysis with cppcheck (if available)
cppcheck:
	@which cppcheck > /dev/null 2>&1 && cppcheck --enable=all --suppress=missingIncludeSystem \
		-I.. -I../../../c-dfa/include -I../../../internal/client \
		$(TEST_SRCS) $(SRCS) || echo "cppcheck not installed"

# Valgrind memory check (if available)
valgrind: $(TARGET)
	@which valgrind > /dev/null 2>&1 && valgrind --leak-check=full --show-leak-kinds=all \
		--track-origins=yes ./$(TARGET) || echo "valgrind not installed"
