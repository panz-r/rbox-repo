# LibFuzzer harness Makefile for c-dfa
# Requires: libfuzzer-21-dev (clang with fuzzing support)

CXX = clang++
CC = clang

CXXFLAGS = -fsanitize=fuzzer,address,undefined -I../include -g -O1 -fno-omit-frame-pointer
CFLAGS = -fsanitize=fuzzer,address,undefined -I../include -g -O1 -fno-omit-frame-pointer

# Library sources (from c-dfa/src and tools)
LIB_SRC = ../src/dfa_eval.c ../src/dfa_loader.c
LIB_OBJS = $(patsubst %.c,%.o,$(LIB_SRC))

# Pattern parser sources (optional - requires linking nfa_builder components)
PATTERN_SRC = ../tools/nfa_builder.c ../tools/multi_target_array.c
PATTERN_OBJS = $(patsubst %.c,%.o,$(PATTERN_SRC))

FUZZERS = dfa_eval_fuzzer pattern_parse_fuzzer

# Default target
all: $(FUZZERS)

# DFA evaluation fuzzer
dfa_eval_fuzzer: dfa_eval_fuzzer.cpp $(LIB_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIB_OBJS) -lm

# Pattern parser fuzzer - uses external nfa_builder process
pattern_parse_fuzzer: pattern_parse_fuzzer.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< -lm

# Build library objects
../src/dfa_eval.o: ../src/dfa_eval.c ../include/dfa.h ../include/dfa_types.h
	$(CC) $(CFLAGS) -c $< -o $@

../src/dfa_loader.o: ../src/dfa_loader.c ../include/dfa.h ../include/dfa_types.h
	$(CC) $(CFLAGS) -c $< -o $@

../tools/nfa_builder.o: ../tools/nfa_builder.c ../include/nfa.h
	$(CC) $(CFLAGS) -c $< -o $@

../tools/multi_target_array.o: ../tools/multi_target_array.c ../tools/multi_target_array.h
	$(CC) $(CFLAGS) -c $< -o $@

# Run fuzzing with corpus
run-dfa: dfa_eval_fuzzer
	./dfa_eval_fuzzer corpus/seed/dfa_eval -max_len=4096 -jobs=4 -workers=4 -rss_mb=2048

# Run with dictionary
run-dfa-dict: dfa_eval_fuzzer
	./dfa_eval_fuzzer corpus/seed/dfa_eval -max_len=4096 -jobs=4 -dict=cmd_dict.txt -rss_mb=2048

# Run pattern parser fuzzing
run-pattern: pattern_parse_fuzzer
	./pattern_parse_fuzzer corpus/seed/pattern_parser -max_len=4096 -jobs=4 -workers=4 -rss_mb=2048

# Merge new corpus inputs
merge: dfa_eval_fuzzer
	./dfa_eval_fuzzer corpus/dfa_eval -merge=1 corpus/dfa_eval_merged -max_len=4096

# Minimize corpus
minimize: dfa_eval_fuzzer
	./dfa_eval_fuzzer corpus/dfa_eval -merge=1 -reduce_inputs_to=1000 corpus/dfa_eval_min

# Clean generated files
clean:
	rm -f $(FUZZERS) $(LIB_OBJS) $(PATTERN_OBJS)

.PHONY: all clean run-dfa run-dfa-dict merge minimize
