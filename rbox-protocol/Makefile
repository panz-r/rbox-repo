# Makefile for rbox-protocol

CC = gcc
CFLAGS = -Wall -Wextra -std=gnu11 -O2 -g \
         -I./include \
         -I../shellsplit/include
LDFLAGS = -lpthread -lm

# Shellsplit
SHELLSPLIT_SRC = ../shellsplit/src/shell_tokenizer.c
SHELLSPLIT_OBJ = ../shellsplit/src/shell_tokenizer.o

# Source files
SRCS = src/socket.c \
       src/packet.c \
       src/parser.c

# Object files
OBJS = $(SRCS:.c=.o)

# Static library
LIB = librbox_protocol.a

# Tests
TEST_BASIC_SRC = tests/test_protocol.c
TEST_BASIC_BIN = test_protocol
TEST_FULL_SRC = tests/test_protocol_full.c
TEST_FULL_BIN = test_protocol_full
TEST_INTEG_SRC = tests/test_integration.c
TEST_INTEG_BIN = test_integration

.PHONY: all clean test test-unit test-full test-integration test-fuzz test-fuzz-1h test-fuzz-4h

all: $(LIB) $(TEST_BASIC_BIN) $(TEST_INTEG_BIN)

$(LIB): $(OBJS)
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(SHELLSPLIT_OBJ):
	$(CC) $(CFLAGS) -c -o $@ $(SHELLSPLIT_SRC)

# Run both unit tests and integration tests
test: $(TEST_BASIC_BIN) $(TEST_INTEG_BIN)
	@echo ""
	@echo "=== Running unit tests ==="
	./$(TEST_BASIC_BIN)
	@echo ""
	@echo "=== Running integration tests ==="
	./$(TEST_INTEG_BIN)

# Run only unit tests
test-unit: $(TEST_BASIC_BIN)
	./$(TEST_BASIC_BIN)

# Run only integration tests
test-integration: $(TEST_INTEG_BIN)
	./$(TEST_INTEG_BIN)

# Build and run fuzz tests
test-fuzz:
	cd fuzz && make run-10m

test-fuzz-1h:
	cd fuzz && make run-1h

test-fuzz-4h:
	cd fuzz && make run-4h

test-full: $(TEST_FULL_BIN)
	./$(TEST_FULL_BIN)

$(TEST_BASIC_BIN): $(TEST_BASIC_SRC) $(LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB) $(LDFLAGS)

$(TEST_FULL_BIN): $(TEST_FULL_SRC) $(LIB) $(SHELLSPLIT_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB) $(SHELLSPLIT_OBJ) $(LDFLAGS)

$(TEST_INTEG_BIN): $(TEST_INTEG_SRC) $(LIB) $(SHELLSPLIT_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB) $(SHELLSPLIT_OBJ) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(LIB) $(TEST_BASIC_BIN) $(TEST_FULL_BIN) $(TEST_INTEG_BIN)
