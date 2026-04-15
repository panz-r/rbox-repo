# Makefile for ptrace client unit tests

.DELETE_ON_ERROR:
.SECONDARY:

# Compiler and Flags
CC = gcc
CFLAGS = -Wall -Wextra -std=gnu11 -O2 -I.. -I../../c-dfa/include -I../../rbox-preload -I../../shellsplit/include -I../../rbox-protocol/include -I../../rbox-ruleset/include -DRELATIVE_ENTROPY_NO_MAIN
LDFLAGS = -lpthread -lm -Wl,-rpath,'$$ORIGIN/../../lib'

# Pre-built libraries
LIBS = ../../c-dfa/libdfa_eval.a \
       ../../rbox-protocol/librbox_protocol.so \
       ../../rbox-ruleset/build/lib/liblandlock-builder.a

# Test source files
TEST_SRCS = test_main.c \
            test_memory.c \
            test_syscall_handler.c \
            test_validation.c \
            test_integration.c \
            test_e2e.c \
            test_sandbox.c \
            test_trampoline_allowance.c \
            test_utils.c \
            debug.c

# Source files from parent directory (excluding main.c)
SRCS = ../progname.c \
       ../memory.c \
       ../syscall_handler.c \
       ../validation.c \
       ../dfa.c \
       ../privilege.c \
       ../sandbox.c \
       ../env.c \
       ../pkexec.c \
       ../judge.c \
       ../trampoline_allowance.c \
       ../soft_ruleset_access.c \
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
all: check-prereqs check-dfa validate-test-runner $(TARGET)

# Check prerequisites
check-prereqs:
	@test -f ../memory.c || (echo "ERROR: ../memory.c not found"; exit 1)
	@test -f ../syscall_handler.c || (echo "ERROR: ../syscall_handler.c not found"; exit 1)
	@test -f ../../c-dfa/build/tools/libreadonlybox_dfa.a || (echo "ERROR: libreadonlybox_dfa.a not found (run 'make' in ../../c-dfa first)"; exit 1)
	@which $(CC) > /dev/null 2>&1 || (echo "ERROR: $(CC) not found"; exit 1)
	@which valgrind > /dev/null 2>&1 || echo "WARNING: valgrind not installed (valgrind target will be skipped)"
	@which cppcheck > /dev/null 2>&1 || echo "WARNING: cppcheck not installed (cppcheck target will be skipped)"

# Ensure DFA data is built before running tests
check-dfa:
	$(MAKE) -C .. dfa

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
test-e2e: check-dfa $(TARGET)
	./$(TARGET) e2e

# Run e2e tests with capabilities set
# Checks if CAP_SYS_PTRACE, CAP_SETUID, CAP_SETGID, CAP_SYS_ADMIN are set on required binaries
test-with-caps: check-dfa $(TARGET)
	@echo "Checking capabilities on required binaries..." && \
	echo "" && \
	echo "Required capabilities: cap_sys_ptrace, cap_setuid, cap_setgid, cap_sys_admin" && \
	echo "" && \
	echo "  Checking readonlybox-ptrace (../../bin/readonlybox-ptrace)..." && \
	caps=$$(getcap "../../bin/readonlybox-ptrace" 2>/dev/null) && \
	if [ -z "$$caps" ]; then \
		echo "    MISSING - no capabilities set"; \
	else \
		echo "    cap_sys_ptrace: [ $$(echo "$$caps" | grep -c "cap_sys_ptrace") ]" && \
		echo "    cap_setuid: [ $$(echo "$$caps" | grep -c "cap_setuid") ]" && \
		echo "    cap_setgid: [ $$(echo "$$caps" | grep -c "cap_setgid") ]" && \
		echo "    cap_sys_admin: [ $$(echo "$$caps" | grep -c "cap_sys_admin") ]"; \
	fi && \
	echo "  Checking test_runner (./test_runner)..." && \
	caps=$$(getcap "./test_runner" 2>/dev/null) && \
	if [ -z "$$caps" ]; then \
		echo "    MISSING - no capabilities set"; \
	else \
		echo "    cap_sys_ptrace: [ $$(echo "$$caps" | grep -c "cap_sys_ptrace") ]" && \
		echo "    cap_setuid: [ $$(echo "$$caps" | grep -c "cap_setuid") ]" && \
		echo "    cap_setgid: [ $$(echo "$$caps" | grep -c "cap_setgid") ]" && \
		echo "    cap_sys_admin: [ $$(echo "$$caps" | grep -c "cap_sys_admin") ]"; \
	fi && \
	echo "" && \
	caps1=$$(getcap "../../bin/readonlybox-ptrace" 2>/dev/null) && \
	caps2=$$(getcap "./test_runner" 2>/dev/null) && \
	if [ -z "$$caps1" ] || [ -z "$$caps2" ]; then \
		echo "ERROR: Required capabilities not set." && \
		echo "" && \
		echo "To set capabilities, run these commands from rbox-ptrace/:" && \
		echo "" && \
		echo "  sudo setcap cap_sys_ptrace,cap_setuid,cap_setgid,cap_sys_admin+ep ./bin/readonlybox-ptrace" && \
		echo "  sudo setcap cap_sys_ptrace,cap_setuid,cap_setgid,cap_sys_admin+ep ./tests/test_runner" && \
		echo "" && \
		echo "Then re-run: make test-with-caps"; \
		exit 1; \
	fi && \
	p1=$$(echo "$$caps1" | grep -c "cap_sys_ptrace") && \
	u1=$$(echo "$$caps1" | grep -c "cap_setuid") && \
	g1=$$(echo "$$caps1" | grep -c "cap_setgid") && \
	a1=$$(echo "$$caps1" | grep -c "cap_sys_admin") && \
	p2=$$(echo "$$caps2" | grep -c "cap_sys_ptrace") && \
	u2=$$(echo "$$caps2" | grep -c "cap_setuid") && \
	g2=$$(echo "$$caps2" | grep -c "cap_setgid") && \
	a2=$$(echo "$$caps2" | grep -c "cap_sys_admin") && \
	if [ "$$p1" != "1" ] || [ "$$u1" != "1" ] || [ "$$g1" != "1" ] || [ "$$a1" != "1" ] || \
	   [ "$$p2" != "1" ] || [ "$$u2" != "1" ] || [ "$$g2" != "1" ] || [ "$$a2" != "1" ]; then \
		echo "ERROR: Required capabilities not set." && \
		echo "" && \
		echo "To set capabilities, run these commands from rbox-ptrace/:" && \
		echo "" && \
		echo "  sudo setcap cap_sys_ptrace,cap_setuid,cap_setgid,cap_sys_admin+ep ./bin/readonlybox-ptrace" && \
		echo "  sudo setcap cap_sys_ptrace,cap_setuid,cap_setgid,cap_sys_admin+ep ./tests/test_runner" && \
		echo "" && \
		echo "Then re-run: make test-with-caps"; \
		exit 1; \
	fi && \
	echo "" && \
	echo "All capabilities set correctly. Running e2e tests..." && \
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
