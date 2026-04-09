# Makefile for rbox-protocol
# Builds the rbox-protocol shared library (with shellsplit statically linked), and runs tests.
# Usage:
#   make           # Build shared library + run tests (default)
#   make build-all # Build shared library only
#   make test      # Run all tests
#   make clean     # Remove all build artifacts

# Compiler
CC = gcc
# -fPIC is required because socket.c uses thread-local storage (g_rand_seed)
# and the objects are used in the shared library
CFLAGS = -Wall -Wextra -std=gnu11 -O2 -g -pthread -fPIC \
         -I./include \
         -I../shellsplit/include
LDFLAGS = -lpthread -lm -z noexecstack

# ASAN (AddressSanitizer) support
# Use ASAN=1 make test to run tests with ASAN enabled
ifdef ASAN
ASAN_CFLAGS = -fsanitize=address -g -O1
ASAN_LDFLAGS = -fsanitize=address
CFLAGS += $(ASAN_CFLAGS)
LDFLAGS += $(ASAN_LDFLAGS)
endif
# Libraries
SHLIB = librbox_protocol.so
SHLIB_LDFLAGS = -shared -fPIC -lpthread -lm

# Shellsplit (statically linked into shared library)
SHELLSPLIT_SRC = ../shellsplit/src/shell_tokenizer.c
SHELLSPLIT_OBJ = ../shellsplit/src/shell_tokenizer.o

# Source files - reorganized layers
SRCS = src/socket_io.c \
       src/protocol.c \
       src/runtime.c \
       src/session.c \
       src/server_client.c \
       src/server_response.c \
       src/server_cache.c \
       src/socket.c \
       src/packet.c \
       src/parser.c \
       src/server.c
OBJS = $(SRCS:.c=.o)

# Tests
TEST_BASIC_SRC = tests/test_protocol.c
TEST_BASIC_BIN = test_protocol
TEST_FULL_SRC = tests/test_protocol_full.c
TEST_FULL_BIN = test_protocol_full
TEST_INTEG_SRC = tests/test_integration.c
TEST_INTEG_BIN = test_integration
TEST_BLOCK_SRC = tests/test_blocking_server.c
TEST_BLOCK_BIN = test_blocking_server
TEST_PERSIST_SRC = tests/test_persistent.c
TEST_PERSIST_BIN = test_persistent
TEST_ENV_SRC = tests/test_env_decisions.c
TEST_ENV_BIN = test_env_decisions
TEST_STRESS_SRC = tests/test_stress.c
TEST_STRESS_BIN = test_stress

.PHONY: all clean test test-unit test-full test-integration test-blocking test-persistent test-env test-stress test-fuzz test-fuzz-1h test-fuzz-4h

all: $(SHLIB) $(TEST_BASIC_BIN) $(TEST_INTEG_BIN) $(TEST_FULL_BIN) $(TEST_BLOCK_BIN) $(TEST_PERSIST_BIN) $(TEST_STREAM_BIN) $(TEST_ENV_BIN) $(TEST_STRESS_BIN)

build-all: $(SHLIB)
	@echo "Shared library built."

# Parallel build setup
ifneq ($(filter -j%,$(MAKEFLAGS)),)
$(warning Parallel build enabled: $(shell nproc 2>/dev/null || echo 1) jobs)
else
MAKEFLAGS += -j$(shell nproc 2>/dev/null || echo 1)
endif

# Shared library for Go cgo (includes shellsplit statically)
$(SHLIB): $(OBJS) $(SHELLSPLIT_OBJ)
	$(CC) $(SHLIB_LDFLAGS) -o $@ $(OBJS) $(SHELLSPLIT_OBJ)

# Object files (pattern rule)
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Shellsplit object
$(SHELLSPLIT_OBJ):
	$(CC) $(CFLAGS) -c -o $@ $(SHELLSPLIT_SRC)

# Run both unit tests and integration tests
test: $(TEST_BASIC_BIN) $(TEST_FULL_BIN) $(TEST_INTEG_BIN) $(TEST_BLOCK_BIN) $(TEST_PERSIST_BIN) $(TEST_STREAM_BIN) $(TEST_ENV_BIN) $(TEST_STRESS_BIN)
	@echo ""
	@echo "=== Running unit tests ==="
	LD_LIBRARY_PATH=. ./$(TEST_BASIC_BIN)
	@echo ""
	@echo "=== Running full protocol tests ==="
	LD_LIBRARY_PATH=. ./$(TEST_FULL_BIN)
	@echo ""
	@echo "=== Running integration tests ==="
	LD_LIBRARY_PATH=. ./$(TEST_INTEG_BIN)
	@echo ""
	@echo "=== Running blocking server tests ==="
	LD_LIBRARY_PATH=. ./$(TEST_BLOCK_BIN)
	@echo ""
	@echo "=== Running persistent connection tests ==="
	LD_LIBRARY_PATH=. ./$(TEST_PERSIST_BIN)
	@echo ""
	@echo "=== Running env decision tests ==="
	LD_LIBRARY_PATH=. ./$(TEST_ENV_BIN)
	@echo ""
	@echo "=== Running stress tests ==="
	LD_LIBRARY_PATH=. ./$(TEST_STRESS_BIN)

test-fuzz:
	cd fuzz && make run-10m

test-fuzz-1h:
	cd fuzz && make run-1h

test-fuzz-4h:
	cd fuzz && make run-4h

# Targets for tests (ensure rebuilds when sources change)
$(TEST_BASIC_BIN): $(TEST_BASIC_SRC) $(SHLIB) $(SHELLSPLIT_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(SHELLSPLIT_OBJ) $(LDFLAGS)

$(TEST_FULL_BIN): $(TEST_FULL_SRC) $(SHLIB) $(SHELLSPLIT_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(SHELLSPLIT_OBJ) $(LDFLAGS)

$(TEST_INTEG_BIN): $(TEST_INTEG_SRC) $(SHLIB) $(SHELLSPLIT_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(SHELLSPLIT_OBJ) $(LDFLAGS)

$(TEST_BLOCK_BIN): $(TEST_BLOCK_SRC) $(SHLIB) $(SHELLSPLIT_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(SHELLSPLIT_OBJ) $(LDFLAGS)

$(TEST_PERSIST_BIN): $(TEST_PERSIST_SRC) $(SHLIB) $(SHELLSPLIT_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(SHELLSPLIT_OBJ) $(LDFLAGS)

$(TEST_STREAM_BIN): $(TEST_STREAM_SRC) $(SHLIB) $(SHELLSPLIT_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(SHELLSPLIT_OBJ) $(LDFLAGS)

$(TEST_ENV_BIN): $(TEST_ENV_SRC) $(SHLIB) $(SHELLSPLIT_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(SHELLSPLIT_OBJ) $(LDFLAGS)

$(TEST_STRESS_BIN): $(TEST_STRESS_SRC) $(SHLIB) $(SHELLSPLIT_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(SHELLSPLIT_OBJ) $(LDFLAGS)

clean:
	$(RM) $(OBJS) $(SHLIB) $(TEST_BASIC_BIN) $(TEST_FULL_BIN) $(TEST_INTEG_BIN) $(TEST_BLOCK_BIN) $(TEST_PERSIST_BIN) $(TEST_STREAM_BIN) $(TEST_ENV_BIN) $(TEST_STRESS_BIN)
	-$(RM) fuzz/*.log

help:
	@echo "Available targets:"
	@echo "  all         - Build shared library + run tests (default)"
	@echo "  build-all   - Build shared library only"
	@echo "  test        - Run all tests"
	@echo "  test-unit   - Run unit tests only"
	@echo "  test-full   - Run full protocol tests"
	@echo "  test-integration - Run integration tests"
	@echo "  test-blocking - Run blocking server tests"
	@echo "  clean       - Remove all build artifacts"
