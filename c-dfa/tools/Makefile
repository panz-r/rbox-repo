CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2

TARGETS = nfa_builder nfa2dfa_advanced nfa2dfa_debug_large

all: $(TARGETS)

nfa_builder: nfa_builder.c
	$(CC) $(CFLAGS) -o $@ $<

nfa2dfa_advanced: nfa2dfa.c
	$(CC) $(CFLAGS) -o $@ $<

nfa2dfa_debug_large: nfa2dfa_debug_large.c
	$(CC) $(CFLAGS) -DMAX_STATES=65536 -o $@ $<

clean:
	rm -f $(TARGETS)

.PHONY: all clean