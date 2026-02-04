CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -DNFA_BUILDER_DEBUG=0 -DNFA_BUILDER_VERBOSE=0 -DNFA2DFA_DEBUG=0 -DNFA2DFA_VERBOSE=0 -DDFA_EVAL_DEBUG=0

TARGETS = nfa_builder nfa2dfa_advanced

all: $(TARGETS)

nfa_builder: nfa_builder.c
	$(CC) $(CFLAGS) -o $@ $<

nfa2dfa_advanced: nfa2dfa.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

.PHONY: all clean