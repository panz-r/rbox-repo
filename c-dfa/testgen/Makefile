# Makefile for testgen

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -I..
TARGET = testgen
TEST_TARGET = testgen_test

# Source files - split into multiple compilation units
SRCS = main.cpp testgen.cpp pattern_strategies.cpp expectation_gen.cpp inductive_builder.cpp pattern_factorization.cpp validation_helpers.cpp pattern_serializer.cpp command_utils.cpp
OBJS = $(SRCS:.cpp=.o)

# For testing (includes all unit tests)
TEST_SRCS = testgen_test.cpp testgen_factorization_test.cpp testgen_validation_test.cpp testgen_strategies_test.cpp testgen_expectation_test.cpp testgen_inductive_builder_test.cpp testgen_serializer_test.cpp testgen.cpp pattern_strategies.cpp expectation_gen.cpp inductive_builder.cpp pattern_factorization.cpp validation_helpers.cpp pattern_serializer.cpp command_utils.cpp
TEST_OBJS = $(TEST_SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp testgen.h pattern_strategies.h expectation_gen.h inductive_builder.h validation_helpers.h pattern_serializer.h command_utils.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TEST_OBJS) $(TARGET) $(TEST_TARGET) output/*.txt output/*.json output/*.nfa output/*.dfa

# Generate compile_commands.json for LSP
compile_commands.json:
	bear -- make all test 2>/dev/null

.PHONY: all clean test
