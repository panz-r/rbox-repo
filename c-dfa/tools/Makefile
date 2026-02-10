CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -DNFA_BUILDER_DEBUG=0 -DNFA_BUILDER_VERBOSE=0 -DNFA2DFA_DEBUG=0 -DNFA2DFA_VERBOSE=0 -DDFA_EVAL_DEBUG=0

TARGETS = nfa_builder nfa2dfa_advanced

all: $(TARGETS)

nfa_builder: nfa_builder.c multi_target_array.c multi_target_array.h
	$(CC) $(CFLAGS) -o $@ $< multi_target_array.c

nfa2dfa_advanced: nfa2dfa.c multi_target_array.c multi_target_array.h dfa_minimize.c dfa_minimize_brzozowski.c dfa_minimize.h
	$(CC) $(CFLAGS) -o $@ $< multi_target_array.c dfa_minimize.c dfa_minimize_brzozowski.c -lm

clean:
	rm -f $(TARGETS)

.PHONY: all clean