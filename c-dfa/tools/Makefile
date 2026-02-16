CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -I../include -DNFA_BUILDER_DEBUG=0 -DNFA_BUILDER_VERBOSE=0 -DNFA2DFA_DEBUG=1 -DNFA2DFA_VERBOSE=1 -DDFA_EVAL_DEBUG=0 -mcmodel=medium

TARGETS = nfa_builder nfa2dfa_advanced

all: $(TARGETS)

nfa_builder: nfa_builder.c multi_target_array.c
	$(CC) $(CFLAGS) -o $@ $< multi_target_array.c

nfa2dfa_advanced: nfa2dfa.c multi_target_array.c dfa_minimize.c dfa_minimize.h
	$(CC) $(CFLAGS) -o $@ $< multi_target_array.c dfa_minimize.c -lm

clean:
	rm -f $(TARGETS)

.PHONY: all clean