# Makefile for rbox-wrap

CC = gcc
CFLAGS = -Wall -Wextra -std=gnu11 -O2 -g \
         -I../rbox-protocol/include \
         -I../shellsplit/include \
         -I../c-dfa/include
LDFLAGS = -lpthread -lm

# Paths to libraries
RBOX_PROTOCOL = ../rbox-protocol
SHELLSPLIT = ../shellsplit
C_DFA = ../c-dfa

# Static library from rbox-protocol
RBOX_LIB = $(RBOX_PROTOCOL)/librbox_protocol.a
SHELLSPLIT_OBJ = $(SHELLSPLIT)/src/shell_tokenizer.o
C_DFA_OBJ = $(C_DFA)/src/dfa_eval.o $(C_DFA)/src/dfa_loader.o

# Target
TARGET = rbox-wrap
SRC = main.c

# Test
TEST_BIN = test_wrap
TEST_SRC = tests/test.c

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SRC) $(RBOX_LIB) $(C_DFA_OBJ) $(SHELLSPLIT_OBJ)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(RBOX_LIB) $(C_DFA_OBJ) $(SHELLSPLIT_OBJ) $(LDFLAGS)

$(RBOX_LIB):
	$(MAKE) -C $(RBOX_PROTOCOL)

$(C_DFA_OBJ):
	$(MAKE) -C $(C_DFA) lib

# Test target
test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_SRC) $(RBOX_LIB)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC) $(RBOX_LIB) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TEST_BIN)
