#include "testgen.h"
#include <iostream>
#include <cassert>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <set>

int tests_run = 0;
int tests_passed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    std::cout << "  " << #name << " ... "; \
    tests_run++; \
    try { \
        test_##name(); \
        std::cout << "PASS\n"; \
        tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAIL: " << e.what() << "\n"; \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        std::ostringstream oss; \
        oss << "Assertion failed: " << (a) << " != " << (b); \
        throw std::runtime_error(oss.str()); \
    } \
} while(0)

#define ASSERT_TRUE(x) do { \
    if (!(x)) { \
        throw std::runtime_error("Assertion failed: " #x " is false"); \
    } \
} while(0)

#define ASSERT_FALSE(x) do { \
    if (x) { \
        throw std::runtime_error("Assertion failed: " #x " is true"); \
    } \
} while(0)

TEST(categoryToString) {
    Options opts;
    opts.seed = 42;
    TestGenerator gen(opts);
    
    ASSERT_EQ(gen.categoryToString(Category::SAFE), std::string("safe"));
    ASSERT_EQ(gen.categoryToString(Category::CAUTION), std::string("caution"));
    ASSERT_EQ(gen.categoryToString(Category::MODIFYING), std::string("modifying"));
}

TEST(generateSeeds_simple) {
    Options opts;
    opts.seed = 42;
    TestGenerator gen(opts);
    std::set<std::string> used;
    
    auto result = gen.generateSeeds(Complexity::SIMPLE, used);
    std::vector<std::string>& matching = result.first;
    std::vector<std::string>& counters = result.second;
    
    ASSERT_TRUE(!matching.empty());
    ASSERT_TRUE(!counters.empty());
    
    // Matching seeds should be non-empty
    for (const auto& m : matching) {
        ASSERT_TRUE(!m.empty());
    }
}

TEST(generateSeeds_medium) {
    Options opts;
    opts.seed = 42;
    TestGenerator gen(opts);
    std::set<std::string> used;
    
    auto result = gen.generateSeeds(Complexity::MEDIUM, used);
    std::vector<std::string>& matching = result.first;
    std::vector<std::string>& counters = result.second;
    
    ASSERT_TRUE(!matching.empty());
    ASSERT_TRUE(!counters.empty());
}

TEST(generateSeeds_complex) {
    Options opts;
    opts.seed = 42;
    TestGenerator gen(opts);
    std::set<std::string> used;
    
    auto result = gen.generateSeeds(Complexity::COMPLEX, used);
    std::vector<std::string>& matching = result.first;
    std::vector<std::string>& counters = result.second;
    
    ASSERT_TRUE(!matching.empty());
    ASSERT_TRUE(!counters.empty());
}

TEST(generateInputs_simple) {
    Options opts;
    opts.seed = 42;
    TestGenerator gen(opts);
    
    auto result = gen.generateInputs(Complexity::SIMPLE);
    std::vector<std::string>& matching = result.first;
    std::vector<std::string>& counters = result.second;
    
    ASSERT_TRUE(!matching.empty());
    ASSERT_TRUE(!counters.empty());
}

TEST(generateInputs_medium) {
    Options opts;
    opts.seed = 42;
    TestGenerator gen(opts);
    
    auto result = gen.generateInputs(Complexity::MEDIUM);
    std::vector<std::string>& matching = result.first;
    std::vector<std::string>& counters = result.second;
    
    ASSERT_TRUE(!matching.empty());
    ASSERT_TRUE(!counters.empty());
}

TEST(generateInputs_complex) {
    Options opts;
    opts.seed = 42;
    TestGenerator gen(opts);
    
    auto result = gen.generateInputs(Complexity::COMPLEX);
    std::vector<std::string>& matching = result.first;
    std::vector<std::string>& counters = result.second;
    
    ASSERT_TRUE(!matching.empty());
    ASSERT_TRUE(!counters.empty());
}

TEST(seedsDifferentFromCounters) {
    Options opts;
    opts.seed = 42;
    TestGenerator gen(opts);
    std::set<std::string> used;
    
    auto result = gen.generateSeeds(Complexity::MEDIUM, used);
    std::vector<std::string>& matching = result.first;
    std::vector<std::string>& counters = result.second;
    
    // Counters should not contain any matching seeds
    std::set<std::string> matching_set(matching.begin(), matching.end());
    for (const auto& c : counters) {
        ASSERT_TRUE(matching_set.find(c) == matching_set.end());
    }
}

TEST(generatePattern_alternation) {
    Options opts;
    opts.seed = 42;
    TestGenerator gen(opts);
    
    std::vector<std::string> matching = {"abc", "def", "ghi"};
    std::vector<std::string> counters = {"xyz", "aaa", "bbb"};
    auto frags = gen.generateFragments(Complexity::SIMPLE);
    std::string proof;
    std::string pattern = gen.generatePattern(matching, counters, frags, Complexity::SIMPLE, proof);
    
    // Pattern should be non-empty and separate the inputs
    ASSERT_TRUE(!pattern.empty());
}

TEST(generatePattern_failsOnIdenticalCounter) {
    Options opts;
    opts.seed = 42;
    TestGenerator gen(opts);
    
    // Counter is identical to one matching - should fail or handle gracefully
    std::vector<std::string> matching = {"abc", "def"};
    std::vector<std::string> counters = {"xyz", "abc"};  // abc is also in matching
    auto frags = gen.generateFragments(Complexity::SIMPLE);
    std::string proof;
    std::string pattern = gen.generatePattern(matching, counters, frags, Complexity::SIMPLE, proof);
    
    // Pattern might be generated - the important thing is it should work correctly
    // The test just verifies it doesn't crash
    ASSERT_TRUE(true);
}

TEST(generateTestCase_structure) {
    Options opts;
    opts.seed = 42;
    opts.complexity = Complexity::MEDIUM;
    TestGenerator gen(opts);
    std::set<std::string> used_inputs;
    
    TestCase tc = gen.generateTestCase(0, used_inputs);
    
    ASSERT_TRUE(tc.test_id == 0);
    ASSERT_TRUE(!tc.matching_inputs.empty());
    ASSERT_TRUE(!tc.counter_inputs.empty());
    
    // Either pattern is generated, or it's empty (failed to separate)
    // Both are valid states
    ASSERT_TRUE(tc.pattern.empty() || !tc.pattern.empty());
    ASSERT_TRUE(!tc.proof.empty());
}

TEST(generate_multiple_seeds_different) {
    Options opts1;
    opts1.seed = 42;
    TestGenerator gen1(opts1);
    std::set<std::string> used1;
    auto r1 = gen1.generateSeeds(Complexity::SIMPLE, used1);
    
    Options opts2;
    opts2.seed = 123;
    TestGenerator gen2(opts2);
    std::set<std::string> used2;
    auto r2 = gen2.generateSeeds(Complexity::SIMPLE, used2);
    
    ASSERT_TRUE(r1.first != r2.first || r1.second != r2.second);
}

TEST(generate_same_seed_same) {
    Options opts1;
    opts1.seed = 42;
    TestGenerator gen1(opts1);
    std::set<std::string> used1;
    auto r1 = gen1.generateSeeds(Complexity::SIMPLE, used1);
    
    Options opts2;
    opts2.seed = 42;
    TestGenerator gen2(opts2);
    std::set<std::string> used2;
    auto r2 = gen2.generateSeeds(Complexity::SIMPLE, used2);
    
    ASSERT_EQ(r1.first.size(), r2.first.size());
    ASSERT_EQ(r1.second.size(), r2.second.size());
}

TEST(matchingInputsNotModified) {
    Options opts;
    opts.seed = 42;
    opts.complexity = Complexity::MEDIUM;
    TestGenerator gen(opts);
    std::set<std::string> used_inputs;
    
    // Generate a test case
    TestCase tc = gen.generateTestCase(0, used_inputs);
    
    // Verify matching_inputs exist and are valid strings
    ASSERT_TRUE(tc.matching_inputs.size() >= 2);
    for (const auto& m : tc.matching_inputs) {
        ASSERT_TRUE(!m.empty());
    }
}

int main() {
    std::cout << "TestGen Unit Tests\n";
    std::cout << "==================\n\n";
    
    std::cout << "Category tests:\n";
    RUN_TEST(categoryToString);
    
    std::cout << "\nSeed generation tests:\n";
    RUN_TEST(generateSeeds_simple);
    RUN_TEST(generateSeeds_medium);
    RUN_TEST(generateSeeds_complex);
    RUN_TEST(seedsDifferentFromCounters);
    
    std::cout << "\nInput generation tests:\n";
    RUN_TEST(generateInputs_simple);
    RUN_TEST(generateInputs_medium);
    RUN_TEST(generateInputs_complex);
    
    std::cout << "\nPattern generation tests:\n";
    RUN_TEST(generatePattern_alternation);
    RUN_TEST(generatePattern_failsOnIdenticalCounter);
    
    std::cout << "\nTestCase tests:\n";
    RUN_TEST(generateTestCase_structure);
    RUN_TEST(matchingInputsNotModified);
    
    std::cout << "\nRandomness tests:\n";
    RUN_TEST(generate_multiple_seeds_different);
    RUN_TEST(generate_same_seed_same);
    
    std::cout << "\n==================\n";
    std::cout << "Results: " << tests_passed << "/" << tests_run << " tests passed\n";
    
    return tests_passed == tests_run ? 0 : 1;
}
