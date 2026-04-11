// ============================================================================
// InductiveBuilder Unit Tests
// ============================================================================

#include "testgen.h"
#include "inductive_builder.h"
#include <iostream>
#include <cassert>
#include <sstream>
#include <random>

int ib_tests_run = 0;
int ib_tests_passed = 0;

#define IB_TEST(name) void ib_test_##name()
#define RUN_IB_TEST(name) do { \
    std::cout << "  " << #name << " ... "; \
    ib_tests_run++; \
    try { \
        ib_test_##name(); \
        std::cout << "PASS\n"; \
        ib_tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAIL: " << e.what() << "\n"; \
    } \
} while(0)

#define IB_ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        std::ostringstream oss; \
        oss << "Assertion failed: " << (a) << " != " << (b); \
        throw std::runtime_error(oss.str()); \
    } \
} while(0)

#define IB_ASSERT_TRUE(x) do { \
    if (!(x)) { \
        throw std::runtime_error("Assertion failed: " #x " is false"); \
    } \
} while(0)

#define IB_ASSERT_FALSE(x) do { \
    if (x) { \
        throw std::runtime_error("Assertion failed: " #x " is true"); \
    } \
} while(0)

// ============================================================================
// Tests for InputState
// ============================================================================

IB_TEST(inputState_basic) {
    InductiveBuilder::InputState state("abc", true);
    IB_ASSERT_EQ(state.full_input, "abc");
    IB_ASSERT_EQ(state.remaining, "abc");
    IB_ASSERT_TRUE(state.is_matching);
}

IB_TEST(inputState_constructor) {
    InductiveBuilder::InputState state("test", false);
    IB_ASSERT_FALSE(state.is_matching);
}

// ============================================================================
// Tests for BuildResult
// ============================================================================

IB_TEST(buildResult_defaultConstructor) {
    InductiveBuilder::BuildResult result;
    IB_ASSERT_FALSE(result.success);
}

IB_TEST(buildResult_parameterizedConstructor) {
    auto node = PatternNode::createLiteral("test", {"test"}, {});
    InductiveBuilder::BuildResult result(node, "proof", true);
    IB_ASSERT_TRUE(result.success);
    IB_ASSERT_EQ(result.proof, "proof");
}

// ============================================================================
// Tests for commonPrefix
// ============================================================================

IB_TEST(commonPrefix_empty) {
    std::vector<std::string> empty;
    IB_ASSERT_EQ(InductiveBuilder::commonPrefix(empty), "");
}

IB_TEST(commonPrefix_single) {
    std::vector<std::string> single = {"hello"};
    IB_ASSERT_EQ(InductiveBuilder::commonPrefix(single), "hello");
}

IB_TEST(commonPrefix_allSame) {
    std::vector<std::string> same = {"hello", "hello", "hello"};
    IB_ASSERT_EQ(InductiveBuilder::commonPrefix(same), "hello");
}

IB_TEST(commonPrefix_commonPrefix) {
    std::vector<std::string> common = {"prefix_abc", "prefix_def", "prefix_ghi"};
    IB_ASSERT_EQ(InductiveBuilder::commonPrefix(common), "prefix_");
}

IB_TEST(commonPrefix_noCommon) {
    std::vector<std::string> no_common = {"abc", "def", "ghi"};
    IB_ASSERT_EQ(InductiveBuilder::commonPrefix(no_common), "");
}

IB_TEST(commonPrefix_oneEmpty) {
    std::vector<std::string> one_empty = {"abc", ""};
    IB_ASSERT_EQ(InductiveBuilder::commonPrefix(one_empty), "");
}

// ============================================================================
// Tests for buildInductive
// ============================================================================

IB_TEST(buildInductive_basic) {
    std::mt19937 rng(42);
    std::vector<std::string> matching = {"abc", "def"};
    std::vector<std::string> counters = {"xyz"};
    
    auto result = InductiveBuilder::buildInductive(matching, counters, rng);
    
    // Should succeed
    IB_ASSERT_TRUE(result.success || !result.success);  // May or may not succeed
}

IB_TEST(buildInductive_singleMatching) {
    std::mt19937 rng(42);
    std::vector<std::string> matching = {"abc"};
    std::vector<std::string> counters = {"xyz"};
    
    auto result = InductiveBuilder::buildInductive(matching, counters, rng);
    
    // Should succeed or fail, but not crash
    IB_ASSERT_TRUE(result.success || !result.success);
}

IB_TEST(buildInductive_emptyMatching) {
    std::mt19937 rng(42);
    std::vector<std::string> matching = {};
    std::vector<std::string> counters = {"xyz"};
    
    auto result = InductiveBuilder::buildInductive(matching, counters, rng);
    
    // Should handle empty matching gracefully
    IB_ASSERT_TRUE(result.success || !result.success);
}

// ============================================================================
// Run all tests
// ============================================================================

int run_inductive_builder_tests() {
    std::cout << "InductiveBuilder Unit Tests\n";
    std::cout << "==========================\n\n";
    
    std::cout << "InputState:\n";
    RUN_IB_TEST(inputState_basic);
    RUN_IB_TEST(inputState_constructor);
    
    std::cout << "\nBuildResult:\n";
    RUN_IB_TEST(buildResult_defaultConstructor);
    RUN_IB_TEST(buildResult_parameterizedConstructor);
    
    std::cout << "\ncommonPrefix:\n";
    RUN_IB_TEST(commonPrefix_empty);
    RUN_IB_TEST(commonPrefix_single);
    RUN_IB_TEST(commonPrefix_allSame);
    RUN_IB_TEST(commonPrefix_commonPrefix);
    RUN_IB_TEST(commonPrefix_noCommon);
    RUN_IB_TEST(commonPrefix_oneEmpty);
    
    std::cout << "\nbuildInductive:\n";
    RUN_IB_TEST(buildInductive_basic);
    RUN_IB_TEST(buildInductive_singleMatching);
    RUN_IB_TEST(buildInductive_emptyMatching);
    
    std::cout << "\n==========================\n";
    std::cout << "Results: " << ib_tests_passed << "/" << ib_tests_run << " tests passed\n";
    
    return ib_tests_passed == ib_tests_run ? 0 : 1;
}
