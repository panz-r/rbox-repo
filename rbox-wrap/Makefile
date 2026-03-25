# Makefile for rbox-wrap

CC ?= gcc
CFLAGS ?= -Wall -Wextra -std=gnu11 -O2 -g
CFLAGS += -I../rbox-protocol/include -I../shellsplit/include -I../c-dfa/include
CFLAGS += -DDEFAULT_SOCKET=\"/run/readonlybox/readonlybox.sock\"
LDFLAGS ?= -lpthread -lm

# Paths to libraries
RBOX_PROTOCOL = ../rbox-protocol
SHELLSPLIT = ../shellsplit
C_DFA = ../c-dfa

# Static library from rbox-protocol
RBOX_LIB = $(RBOX_PROTOCOL)/librbox_protocol.a
SHELLSPLIT_LIB = $(SHELLSPLIT)/libshellsplit.a

# DFA eval library (new API - just evaluation, no loader)
DFA_EVAL_LIB = $(C_DFA)/libdfa_eval.a

# DFA build tools
NFA_BUILDER = $(C_DFA)/tools/nfa_builder
NFA2DFA = $(C_DFA)/tools/nfa2dfa_advanced
DFA2C = $(C_DFA)/tools/dfa2c_array

# Pattern file and output files for embedded DFA
PATTERN_FILE = rbox_wrap_commands.txt
NFA_FILE = rbox_wrap.nfa
DFA_FILE = rbox_wrap.dfa
DFA_DATA_C = rbox_wrap_dfa_data.c
DFA_DATA_OBJ = rbox_wrap_dfa_data.o

# Target
TARGET = rbox-wrap
SRC = main.c

# Test
TEST_BIN = test_wrap
TEST_SRC = tests/test.c

.PHONY: all clean test dfa

all: dfa $(TARGET)

# Allow parallel builds with -j
ifneq ($(MAKECMDGOALS),)
  ifeq ($(findstring -j,$(MAKEFLAGS)),)
    NPROCS := $(shell nproc 2>/dev/null || echo 1)
    export MAKEFLAGS += -j$(NPROCS)
  endif
endif

# Build DFA from pattern file
dfa: $(DFA_DATA_C)

$(NFA_FILE): $(PATTERN_FILE)
	$(NFA_BUILDER) $(PATTERN_FILE) $(NFA_FILE)

$(DFA_FILE): $(NFA_FILE)
	$(NFA2DFA) $(NFA_FILE) $(DFA_FILE)

$(DFA_DATA_C): $(DFA_FILE) $(DFA2C)
	$(DFA2C) $(DFA_FILE) $(DFA_DATA_C) rbox_wrap_dfa_data

$(DFA_DATA_OBJ): $(DFA_DATA_C)
	$(CC) $(CFLAGS) -c -o $@ $(DFA_DATA_C)

$(TARGET): $(SRC) $(RBOX_LIB) $(DFA_EVAL_LIB) $(SHELLSPLIT_LIB) $(DFA_DATA_OBJ)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(RBOX_LIB) $(DFA_EVAL_LIB) $(SHELLSPLIT_LIB) $(DFA_DATA_OBJ) $(LDFLAGS)

$(RBOX_LIB):
	$(MAKE) -C $(RBOX_PROTOCOL)

$(DFA_EVAL_LIB):
	$(MAKE) -C $(C_DFA) libdfa_eval.a

$(SHELLSPLIT_LIB):
	$(MAKE) -C $(SHELLSPLIT) libshellsplit.a

# Test targets
DECODE_PACKET = tests/decode_packet
test: dfa $(TARGET) $(TEST_BIN) $(DECODE_PACKET)
	./$(TEST_BIN)
	@echo ""
	@echo "Running shell integration tests..."
	@cd tests && bash run_tests.sh

$(TEST_BIN): $(TEST_SRC) $(RBOX_LIB)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC) $(RBOX_LIB) $(LDFLAGS)

$(DECODE_PACKET): tests/decode_packet.c $(RBOX_LIB) $(SHELLSPLIT_LIB)
	$(CC) $(CFLAGS) -o $@ tests/decode_packet.c $(RBOX_LIB) $(SHELLSPLIT_LIB) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TEST_BIN) tests/decode_packet
	rm -f $(NFA_FILE) $(DFA_FILE) $(DFA_DATA_C) $(DFA_DATA_OBJ)
