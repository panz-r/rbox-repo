# Makefile for testgen

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -I..
TARGET = testgen
TEST_TARGET = testgen_test

# Source files - implementations split between testgen.cpp and pattern_strategies.cpp
SRCS = main.cpp testgen.cpp pattern_strategies.cpp
OBJS = $(SRCS:.cpp=.o)

# For testing
TEST_SRCS = testgen_test.cpp testgen.cpp pattern_strategies.cpp
TEST_OBJS = $(TEST_SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp testgen.h pattern_strategies.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TEST_OBJS) $(TARGET) $(TEST_TARGET) output/*.txt output/*.json output/*.nfa output/*.dfa

# Generate compile_commands.json for LSP
compile_commands.json:
	bear -- make all test 2>/dev/null

.PHONY: all clean test
