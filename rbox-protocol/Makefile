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
LDFLAGS = -lpthread -lm -latomic -z noexecstack

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
SHLIB_LDFLAGS = -shared -fPIC -lpthread -lm -latomic

# Shellsplit (statically linked into shared library)
SHELLSPLIT_SRC = ../shellsplit/src/shell_tokenizer.c
SHELLSPLIT_OBJ = ../shellsplit/src/shell_tokenizer.o

# Source files - reorganized layers
SRCS = src/socket_io.c \
       src/protocol.c \
       src/runtime.c \
       src/session.c \
       src/server_client.c \
       src/rbox_cache.c \
       src/socket.c \
       src/packet.c \
       src/parser.c \
       src/server.c \
       src/protocol_encoding.c \
       src/protocol_decoding.c \
       src/timer_heap.c
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
TEST_CACHE_SRC = tests/test_cache.c
TEST_CACHE_BIN = test_cache
TEST_ENCODING_SRC = tests/test_protocol_encoding.c
TEST_ENCODING_BIN = test_protocol_encoding
TEST_DECODING_SRC = tests/test_protocol_decoding.c
TEST_DECODING_BIN = test_protocol_decoding
TEST_TIMER_SRC = tests/test_timer_heap.c
TEST_TIMER_BIN = test_timer_heap

FUZZ_BIN = fuzz/protocol_fuzzer

.PHONY: all clean test test-unit test-full test-integration test-blocking test-persistent test-env test-stress test-cache test-timer test-fuzz test-fuzz-1h test-fuzz-4h fuzz

all: $(SHLIB) $(TEST_BASIC_BIN) $(TEST_INTEG_BIN) $(TEST_FULL_BIN) $(TEST_BLOCK_BIN) $(TEST_PERSIST_BIN) $(TEST_ENV_BIN) $(TEST_STRESS_BIN) $(TEST_CACHE_BIN) $(TEST_ENCODING_BIN) $(TEST_DECODING_BIN) $(TEST_TIMER_BIN) fuzz

build-all: $(SHLIB)
	@echo "Shared library built."

fuzz: $(FUZZ_BIN)
	@echo "Fuzzer built."

$(FUZZ_BIN): $(SHLIB)
	cd fuzz && $(MAKE)

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
test: $(TEST_BASIC_BIN) $(TEST_FULL_BIN) $(TEST_INTEG_BIN) $(TEST_BLOCK_BIN) $(TEST_PERSIST_BIN) $(TEST_ENV_BIN) $(TEST_STRESS_BIN) $(TEST_CACHE_BIN) $(TEST_ENCODING_BIN) $(TEST_DECODING_BIN) $(TEST_TIMER_BIN)
	@echo ""
	@echo "=== Running unit tests ==="
	LD_LIBRARY_PATH=. ./$(TEST_BASIC_BIN)
	@echo ""
	@echo "=== Running encoding unit tests ==="
	LD_LIBRARY_PATH=. ./$(TEST_ENCODING_BIN)
	@echo ""
	@echo "=== Running decoding unit tests ==="
	LD_LIBRARY_PATH=. ./$(TEST_DECODING_BIN)
	@echo ""
	@echo "=== Running timer heap tests ==="
	LD_LIBRARY_PATH=. ./$(TEST_TIMER_BIN)
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
	@echo ""
	@echo "=== Running cache tests ==="
	LD_LIBRARY_PATH=. ./$(TEST_CACHE_BIN)

test-cache: $(TEST_CACHE_BIN)
	LD_LIBRARY_PATH=. ./$(TEST_CACHE_BIN)

test-timer: $(TEST_TIMER_BIN)
	LD_LIBRARY_PATH=. ./$(TEST_TIMER_BIN)

test-fuzz: $(FUZZ_BIN)
	cd fuzz && make run-10m

test-fuzz-1h:
	cd fuzz && make run-1h

test-fuzz-4h:
	cd fuzz && make run-4h

# Targets for tests (ensure rebuilds when sources change)
$(TEST_BASIC_BIN): $(TEST_BASIC_SRC) $(SHLIB)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(LDFLAGS)

$(TEST_FULL_BIN): $(TEST_FULL_SRC) $(SHLIB)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(LDFLAGS)

$(TEST_INTEG_BIN): $(TEST_INTEG_SRC) $(SHLIB)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(LDFLAGS)

$(TEST_BLOCK_BIN): $(TEST_BLOCK_SRC) $(SHLIB)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(LDFLAGS)

$(TEST_PERSIST_BIN): $(TEST_PERSIST_SRC) $(SHLIB)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(LDFLAGS)

$(TEST_ENV_BIN): $(TEST_ENV_SRC) $(SHLIB)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(LDFLAGS)

$(TEST_STRESS_BIN): $(TEST_STRESS_SRC) $(SHLIB)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(LDFLAGS)

$(TEST_CACHE_BIN): $(TEST_CACHE_SRC) $(SHLIB)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(LDFLAGS)

$(TEST_ENCODING_BIN): $(TEST_ENCODING_SRC) $(SHLIB)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(LDFLAGS)

$(TEST_DECODING_BIN): $(TEST_DECODING_SRC) $(SHLIB)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(LDFLAGS)

$(TEST_TIMER_BIN): $(TEST_TIMER_SRC) $(SHLIB)
	$(CC) $(CFLAGS) -o $@ $< $(SHLIB) $(LDFLAGS)

clean:
	$(RM) $(OBJS) $(SHLIB) $(TEST_BASIC_BIN) $(TEST_FULL_BIN) $(TEST_INTEG_BIN) $(TEST_BLOCK_BIN) $(TEST_PERSIST_BIN) $(TEST_ENV_BIN) $(TEST_STRESS_BIN) $(TEST_CACHE_BIN) $(TEST_ENCODING_BIN) $(TEST_DECODING_BIN) $(TEST_TIMER_BIN)
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
