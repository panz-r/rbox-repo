#include "testgen.h"
#include <iostream>
#include <cassert>
#include <cstring>
#include <sstream>
#include <algorithm>

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
    ASSERT_EQ(gen.categoryToString(Category::DANGEROUS), std::string("dangerous"));
    ASSERT_EQ(gen.categoryToString(Category::NETWORK), std::string("network"));
    ASSERT_EQ(gen.categoryToString(Category::ADMIN), std::string("admin"));
    ASSERT_EQ(gen.categoryToString(Category::BUILD), std::string("build"));
    ASSERT_EQ(gen.categoryToString(Category::CONTAINER), std::string("container"));
}

TEST(generateSimpleArg) {
    Options opts;
    opts.seed = 42;
    opts.complexity = Complexity::SIMPLE;
    TestGenerator gen(opts);
    
    for (int i = 0; i < 100; i++) {
        std::string arg = gen.generateSimpleArg();
        ASSERT_FALSE(arg.empty());
    }
}

TEST(generateFlags) {
    Options opts;
    opts.seed = 42;
    TestGenerator gen(opts);
    
    std::string flags = gen.generateFlags(2);
    ASSERT_FALSE(flags.empty());
    
    std::string flags3 = gen.generateFlags(3);
    ASSERT_FALSE(flags3.empty());
}

TEST(generatePath) {
    Options opts;
    opts.seed = 42;
    TestGenerator gen(opts);
    
    std::string path = gen.generatePath();
    ASSERT_FALSE(path.empty());
    ASSERT_TRUE(path.find('/') != std::string::npos);
}

TEST(generatePattern_simple_literal) {
    Options opts;
    opts.seed = 42;
    opts.complexity = Complexity::SIMPLE;
    TestGenerator gen(opts);
    
    std::map<std::string, std::string> fragments = {{"digit", "0|1|2|3|4|5|6|7|8|9"}};
    
    std::string matching = "git status";
    std::vector<std::string> counters = {"git log", "hg status"};
    
    std::string pattern = gen.generatePattern(matching, counters, fragments, Complexity::SIMPLE);
    
    ASSERT_EQ(pattern, matching);
}

TEST(generatePattern_medium_literal) {
    Options opts;
    opts.seed = 42;
    opts.complexity = Complexity::MEDIUM;
    TestGenerator gen(opts);
    
    std::map<std::string, std::string> fragments = {{"digit", "0|1|2|3|4|5|6|7|8|9"}};
    
    std::string matching = "git status";
    std::vector<std::string> counters = {"git log", "hg status"};
    
    std::string pattern = gen.generatePattern(matching, counters, fragments, Complexity::MEDIUM);
    
    ASSERT_FALSE(pattern.empty());
    ASSERT_TRUE(pattern.find("git") != std::string::npos);
    ASSERT_TRUE(pattern.find("status") != std::string::npos);
}

TEST(generatePattern_preserves_command) {
    Options opts;
    opts.seed = 12345;
    opts.complexity = Complexity::MEDIUM;
    TestGenerator gen(opts);
    
    std::map<std::string, std::string> fragments = {{"digit", "0|1|2|3|4|5|6|7|8|9"}};
    
    std::string matching = "ls -l file.txt";
    std::vector<std::string> counters = {"ls file.txt", "dir -l file.txt"};
    
    std::string pattern = gen.generatePattern(matching, counters, fragments, Complexity::MEDIUM);
    
    ASSERT_TRUE(pattern.find("ls") != std::string::npos);
}

TEST(transformPart_simple_unchanged) {
    Options opts;
    opts.seed = 42;
    opts.complexity = Complexity::SIMPLE;
    TestGenerator gen(opts);
    
    std::map<std::string, std::string> fragments = {{"digit", "0|1|2|3|4|5|6|7|8|9"}};
    
    std::string part = "file.txt";
    std::string result = gen.transformPart(part, fragments, Complexity::SIMPLE);
    
    ASSERT_EQ(result, part);
}

TEST(transformPart_medium_may_vary) {
    Options opts;
    opts.seed = 42;
    opts.complexity = Complexity::MEDIUM;
    TestGenerator gen(opts);
    
    std::map<std::string, std::string> fragments = {{"digit", "0|1|2|3|4|5|6|7|8|9"}};
    
    bool found_literal = false;
    bool found_wildcard = false;
    
    for (int i = 0; i < 20; i++) {
        opts.seed = i;
        TestGenerator gen2(opts);
        std::string part = "-n123";
        std::string result = gen2.transformPart(part, fragments, Complexity::MEDIUM);
        
        if (result == part) found_literal = true;
        if (result == "(*)") found_wildcard = true;
    }
    
    ASSERT_TRUE(found_literal || found_wildcard);
}

TEST(generateFragments_simple) {
    Options opts;
    opts.complexity = Complexity::SIMPLE;
    TestGenerator gen(opts);
    
    auto frags = gen.generateFragments(Complexity::SIMPLE);
    
    ASSERT_TRUE(frags.find("digit") != frags.end());
    ASSERT_EQ(frags.size(), (size_t)1);
}

TEST(generateFragments_medium) {
    Options opts;
    opts.complexity = Complexity::MEDIUM;
    TestGenerator gen(opts);
    
    auto frags = gen.generateFragments(Complexity::MEDIUM);
    
    ASSERT_TRUE(frags.find("digit") != frags.end());
    ASSERT_TRUE(frags.find("lower") != frags.end());
    ASSERT_TRUE(frags.find("alnum") != frags.end());
    ASSERT_EQ(frags.size(), (size_t)3);
}

TEST(generateFragments_complex) {
    Options opts;
    opts.complexity = Complexity::COMPLEX;
    TestGenerator gen(opts);
    
    auto frags = gen.generateFragments(Complexity::COMPLEX);
    
    ASSERT_TRUE(frags.find("digit") != frags.end());
    ASSERT_TRUE(frags.find("lower") != frags.end());
    ASSERT_TRUE(frags.find("upper") != frags.end());
    ASSERT_TRUE(frags.find("alpha") != frags.end());
    ASSERT_TRUE(frags.find("alnum") != frags.end());
    ASSERT_TRUE(frags.find("filename") != frags.end());
}

TEST(generateInputs_simple) {
    Options opts;
    opts.seed = 42;
    opts.complexity = Complexity::SIMPLE;
    TestGenerator gen(opts);
    
    auto result = gen.generateInputs(Complexity::SIMPLE);
    std::string& matching = result.first;
    std::vector<std::string>& counters = result.second;
    
    ASSERT_FALSE(matching.empty());
    ASSERT_FALSE(counters.empty());
    ASSERT_TRUE(counters.size() >= 3);
}

TEST(generateInputs_medium) {
    Options opts;
    opts.seed = 42;
    opts.complexity = Complexity::MEDIUM;
    TestGenerator gen(opts);
    
    auto result = gen.generateInputs(Complexity::MEDIUM);
    std::string& matching = result.first;
    std::vector<std::string>& counters = result.second;
    
    ASSERT_FALSE(matching.empty());
    ASSERT_FALSE(counters.empty());
    
    size_t space_count = std::count(matching.begin(), matching.end(), ' ');
    ASSERT_TRUE(space_count >= 1);
}

TEST(generateInputs_complex) {
    Options opts;
    opts.seed = 42;
    opts.complexity = Complexity::COMPLEX;
    TestGenerator gen(opts);
    
    auto result = gen.generateInputs(Complexity::COMPLEX);
    std::string& matching = result.first;
    std::vector<std::string>& counters = result.second;
    
    ASSERT_FALSE(matching.empty());
    ASSERT_FALSE(counters.empty());
    
    size_t space_count = std::count(matching.begin(), matching.end(), ' ');
    ASSERT_TRUE(space_count >= 2);
}

TEST(counterInputsDifferent) {
    Options opts;
    opts.seed = 42;
    opts.complexity = Complexity::MEDIUM;
    TestGenerator gen(opts);
    
    auto result = gen.generateInputs(Complexity::MEDIUM);
    std::string& matching = result.first;
    std::vector<std::string>& counters = result.second;
    
    for (const auto& counter : counters) {
        ASSERT_TRUE(counter != matching);
    }
}

TEST(generateTestCase_structure) {
    Options opts;
    opts.seed = 42;
    opts.complexity = Complexity::MEDIUM;
    TestGenerator gen(opts);
    
    TestCase tc = gen.generateTestCase(0);
    
    ASSERT_FALSE(tc.pattern.empty());
    ASSERT_FALSE(tc.matching_input.empty());
    ASSERT_FALSE(tc.counter_inputs.empty());
    ASSERT_TRUE(tc.category != Category::UNKNOWN);
}

TEST(generate_multiple_seeds_different) {
    Options opts1, opts2;
    opts1.seed = 1;
    opts1.complexity = Complexity::SIMPLE;
    opts2.seed = 2;
    opts2.complexity = Complexity::SIMPLE;
    
    TestGenerator gen1(opts1);
    TestGenerator gen2(opts2);
    
    auto r1 = gen1.generateInputs(Complexity::SIMPLE);
    auto r2 = gen2.generateInputs(Complexity::SIMPLE);
    
    bool all_same = (r1.first == r2.first);
    for (size_t i = 0; i < r1.second.size() && i < r2.second.size(); i++) {
        all_same = all_same && (r1.second[i] == r2.second[i]);
    }
    
    ASSERT_FALSE(all_same);
}

TEST(generate_same_seed_same) {
    Options opts1, opts2;
    opts1.seed = 42;
    opts1.complexity = Complexity::SIMPLE;
    opts2.seed = 42;
    opts2.complexity = Complexity::SIMPLE;
    
    TestGenerator gen1(opts1);
    TestGenerator gen2(opts2);
    
    auto r1 = gen1.generateInputs(Complexity::SIMPLE);
    auto r2 = gen2.generateInputs(Complexity::SIMPLE);
    
    ASSERT_EQ(r1.first, r2.first);
    ASSERT_EQ(r1.second.size(), r2.second.size());
    for (size_t i = 0; i < r1.second.size(); i++) {
        ASSERT_EQ(r1.second[i], r2.second[i]);
    }
}

int main() {
    std::cout << "TestGen Unit Tests\n";
    std::cout << "==================\n\n";
    
    std::cout << "Category tests:\n";
    RUN_TEST(categoryToString);
    
    std::cout << "\nInput generation tests:\n";
    RUN_TEST(generateSimpleArg);
    RUN_TEST(generateFlags);
    RUN_TEST(generatePath);
    RUN_TEST(generateInputs_simple);
    RUN_TEST(generateInputs_medium);
    RUN_TEST(generateInputs_complex);
    RUN_TEST(counterInputsDifferent);
    
    std::cout << "\nFragment tests:\n";
    RUN_TEST(generateFragments_simple);
    RUN_TEST(generateFragments_medium);
    RUN_TEST(generateFragments_complex);
    
    std::cout << "\nPattern generation tests:\n";
    RUN_TEST(generatePattern_simple_literal);
    RUN_TEST(generatePattern_medium_literal);
    RUN_TEST(generatePattern_preserves_command);
    RUN_TEST(transformPart_simple_unchanged);
    RUN_TEST(transformPart_medium_may_vary);
    
    std::cout << "\nTestCase tests:\n";
    RUN_TEST(generateTestCase_structure);
    
    std::cout << "\nRandomness tests:\n";
    RUN_TEST(generate_multiple_seeds_different);
    RUN_TEST(generate_same_seed_same);
    
    std::cout << "\n==================\n";
    std::cout << "Results: " << tests_passed << "/" << tests_run << " tests passed\n";
    
    return tests_passed == tests_run ? 0 : 1;
}
