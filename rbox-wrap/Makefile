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
SHELLSPLIT_OBJ = $(SHELLSPLIT)/src/shell_tokenizer.o

# Target
TARGET = rbox-wrap
SRC = main.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) $(RBOX_LIB) $(C_DFA_OBJ) $(SHELLSPLIT_OBJ)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(RBOX_LIB) $(C_DFA_OBJ) $(SHELLSPLIT_OBJ) $(LDFLAGS)

$(RBOX_LIB):
	$(MAKE) -C $(RBOX_PROTOCOL)

$(C_DFA_OBJ):
	$(MAKE) -C $(C_DFA)

clean:
	rm -f $(TARGET)
