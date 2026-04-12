#
# Makefile for liblandlock-builder
#
# Targets:
#   all       – build static library and test runner (default)
#   lib       – build liblandlock-builder.a
#   test      – build and run unit tests
#   benchmark – build and run performance benchmarks
#   clean     – remove build artifacts
#

CC      ?= gcc
CFLAGS  := -Wall -Wextra -Wpedantic -std=c11 -O2 -g \
           -I$(CURDIR)/include -I$(CURDIR)/src
LDFLAGS := 
LDLIBS  :=

SRCDIR   := src
TESTDIR  := tests
BUILDDIR := build

# Library sources and objects
LIB_SRCS := $(SRCDIR)/arena.c $(SRCDIR)/radix_tree.c $(SRCDIR)/builder.c $(SRCDIR)/rule_engine.c $(SRCDIR)/rule_engine_compile.c $(SRCDIR)/policy_parser.c $(SRCDIR)/landlock_bridge.c
LIB_OBJS := $(BUILDDIR)/arena.o $(BUILDDIR)/radix_tree.o $(BUILDDIR)/builder.o $(BUILDDIR)/rule_engine.o $(BUILDDIR)/rule_engine_compile.o $(BUILDDIR)/policy_parser.o $(BUILDDIR)/landlock_bridge.o
LIB      := $(BUILDDIR)/liblandlock-builder.a

# Test sources
TEST_SRCS := $(TESTDIR)/test_radix_tree.c \
             $(TESTDIR)/test_builder.c \
             $(TESTDIR)/test_mock_fs.c \
             $(TESTDIR)/test_main.c \
             $(TESTDIR)/mock_fs.c \
             $(TESTDIR)/test_radix_tree_extended.c \
             $(TESTDIR)/test_builder_extended.c \
             $(TESTDIR)/test_vfs_filter.c \
             $(TESTDIR)/test_rule_engine.c \
             $(TESTDIR)/test_arena.c \
             $(TESTDIR)/test_builder_edge.c \
             $(TESTDIR)/test_radix_tree_edge.c \
             $(TESTDIR)/test_policy_parser.c \
             $(TESTDIR)/test_landlock_bridge.c \
             $(TESTDIR)/test_compilation_core.c \
             $(TESTDIR)/test_compilation_advanced.c \
             $(TESTDIR)/test_compilation_internal.c \
             $(TESTDIR)/test_compilation_remaining2.c \
             $(TESTDIR)/test_compilation_remaining3.c \
             $(TESTDIR)/test_compilation_final_gaps.c \
             $(TESTDIR)/test_compilation_extra.c \
             $(TESTDIR)/test_compilation_gaps.c \
             $(TESTDIR)/test_compilation_binary.c \
             $(TESTDIR)/test_compilation_layered.c \
             $(TESTDIR)/test_compilation_stress.c
TEST_OBJS := $(TEST_SRCS:.c=.o)
TEST_BIN  := $(BUILDDIR)/test_runner

# Benchmark
BENCH_SRCS := $(BUILDDIR)/benchmark.o
BENCH_BIN  := $(BUILDDIR)/benchmark

.PHONY: all lib test benchmark clean

all: lib test

lib: $(LIB)

# ---- Library build ----

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -I$(CURDIR)/src -c $< -o $@

# Mock-fs-enabled library objects for test linking
$(BUILDDIR)/%_mock.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -DMOCK_FS -I$(TESTDIR) -c $< -o $@

# Benchmark needs mock_fs compiled without the redirect macros
$(BUILDDIR)/bench_mock_fs.o: $(TESTDIR)/mock_fs.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(LIB_OBJS)
	ar rcs $@ $^

# ---- Test build ----

$(TESTDIR)/%.o: $(TESTDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -DMOCK_FS -c $< -o $@

$(TESTDIR)/mock_fs.o: $(TESTDIR)/mock_fs.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Mock-enabled library objects for tests
MOCK_LIB_OBJS := $(BUILDDIR)/arena_mock.o $(BUILDDIR)/radix_tree_mock.o $(BUILDDIR)/builder_mock.o $(BUILDDIR)/rule_engine_mock.o $(BUILDDIR)/rule_engine_compile_mock.o $(BUILDDIR)/policy_parser_mock.o $(BUILDDIR)/landlock_bridge_mock.o

$(TEST_BIN): $(TEST_OBJS) $(MOCK_LIB_OBJS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

test: $(TEST_BIN)
	./$(TEST_BIN)

# ---- Benchmark ----

$(BUILDDIR)/benchmark.o: $(TESTDIR)/benchmark.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -DMOCK_FS -DMOCK_FS_INTERNAL -I$(TESTDIR) -c $< -o $@

BENCH_OBJS := $(BUILDDIR)/benchmark.o
$(BENCH_BIN): $(BENCH_OBJS) $(BUILDDIR)/arena_mock.o $(BUILDDIR)/radix_tree_mock.o $(BUILDDIR)/builder_mock.o $(BUILDDIR)/rule_engine_mock.o $(BUILDDIR)/rule_engine_compile_mock.o $(BUILDDIR)/policy_parser_mock.o $(BUILDDIR)/landlock_bridge_mock.o $(BUILDDIR)/bench_mock_fs.o | $(BUILDDIR)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

benchmark: $(BENCH_BIN)
	./$(BENCH_BIN)

# ---- Clean ----

clean:
	rm -rf $(BUILDDIR)
	find $(TESTDIR) -name '*.o' -delete
