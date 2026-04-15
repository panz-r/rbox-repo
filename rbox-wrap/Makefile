# Makefile for rbox-wrap

# Variables
CC ?= gcc
CFLAGS ?= -Wall -Wextra -std=gnu11 -O2 -g
CFLAGS += -I../rbox-protocol/include -I../shellsplit/include -I../c-dfa/include
CFLAGS += -DDEFAULT_SOCKET=\"/run/readonlybox/readonlybox.sock\"
LDFLAGS ?= -lpthread -lm

# Paths
RBOX_PROTOCOL = ../rbox-protocol
C_DFA = ../c-dfa
C_DFA_BUILD = $(C_DFA)/build

# Libraries (protocol.so includes shellsplit statically)
RBOX_LIB = $(RBOX_PROTOCOL)/librbox_protocol.so
DFA_EVAL_LIB = $(C_DFA_BUILD)/tools/libreadonlybox_dfa.a

# Unified CLI tool
CDFATOOL = $(C_DFA_BUILD)/tools/cdfatool

# Pattern file and outputs
PATTERN_FILE ?= rbox_wrap_commands.txt
DFA_FILE = rbox_wrap.dfa
DFA_DATA_C = rbox_wrap_dfa_data.c
DFA_DATA_OBJ = rbox_wrap_dfa_data.o

# Targets
TARGET = rbox-wrap
SRC = main.c
TEST_BIN = test_wrap
TEST_SRC = tests/test.c
DECODE_PACKET = tests/decode_packet

.PHONY: all clean test dfa \
        $(TARGET) $(TEST_BIN) $(DECODE_PACKET) \
        $(RBOX_LIB) $(DFA_EVAL_LIB)

# Enable parallel builds
ifneq ($(filter-out --%,$(MAKECMDGOALS)),)
    NPROCS := $(shell nproc 2>/dev/null || echo 1)
    MAKEFLAGS += -j$(NPROCS) -k
endif

# Default target
all: dfa $(TARGET)

# Build c-dfa using CMake
$(C_DFA_BUILD):
	cd $(C_DFA) && cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build

# Build DFA from pattern file using cdfatool (direct: pattern -> DFA -> C array)
dfa: $(CDFATOOL) $(DFA_DATA_C)

$(DFA_DATA_C): $(DFA_FILE)
	$(CDFATOOL) embedd $(DFA_FILE) -o $(DFA_DATA_C)

$(DFA_FILE): $(CDFATOOL) $(PATTERN_FILE)
	$(CDFATOOL) compile $(PATTERN_FILE) -o $(DFA_FILE)

$(DFA_DATA_OBJ): $(DFA_DATA_C)
	$(CC) $(CFLAGS) -c -o $@ $(DFA_DATA_C)

$(TARGET): $(SRC) $(RBOX_LIB) $(DFA_EVAL_LIB) $(DFA_DATA_OBJ)
	$(CC) $(CFLAGS) -Wl,-rpath,'$$ORIGIN/../lib' -o $@ $(SRC) -L../lib -lrbox_protocol $(DFA_EVAL_LIB) $(DFA_DATA_OBJ) $(LDFLAGS)

$(RBOX_LIB):
	$(MAKE) -C $(RBOX_PROTOCOL)

$(DFA_EVAL_LIB): | $(C_DFA_BUILD)

# Test targets
$(TEST_BIN): $(TEST_SRC) $(RBOX_LIB)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC) $(RBOX_LIB) $(LDFLAGS)

$(DECODE_PACKET): tests/decode_packet.c $(RBOX_LIB)
	$(CC) $(CFLAGS) -o $@ tests/decode_packet.c $(RBOX_LIB) $(LDFLAGS)

test: dfa $(TARGET) $(TEST_BIN) $(DECODE_PACKET)
	@echo "Running C unit tests and shell integration tests..."
	bash tests/run_tests.sh

clean:
	rm -f $(TARGET) $(TEST_BIN) tests/decode_packet
	rm -f $(DFA_FILE) $(DFA_DATA_C) $(DFA_DATA_OBJ)
