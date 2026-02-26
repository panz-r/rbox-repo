#ifndef TESTGEN_H
#define TESTGEN_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <random>
#include <memory>
#include <functional>

enum class Category {
    UNKNOWN = 0,
    SAFE = 1,
    CAUTION = 2,
    MODIFYING = 3,
    DANGEROUS = 4,
    NETWORK = 5,
    ADMIN = 6,
    BUILD = 7,
    CONTAINER = 8
};

enum class Complexity {
    SIMPLE,
    MEDIUM,
    COMPLEX
};

struct TestCase {
    int test_id;
    std::string pattern;
    Category category;           // Category for matching inputs
    Category counter_category;   // Category for counter inputs (different to distinguish)
    std::vector<std::string> matching_inputs;  // ALL must match with category
    std::vector<std::string> counter_inputs;   // NONE must match with category
    std::map<std::string, std::string> fragments;
    Complexity complexity;
    std::string proof;  // Proof of correctness
};

struct Options {
    int num_tests = 100;
    std::string output_dir = "testgen/output";
    int seed = 0;
    Complexity complexity = Complexity::MEDIUM;
    bool run_tests = false;
    bool keep_files = false;
};

class TestGenerator {
public:
    TestGenerator(const Options& opts);
    
    std::vector<TestCase> generate();
    void writePatternFile(const std::vector<TestCase>& tests, const std::string& filename);
    void writeExpectations(const std::vector<TestCase>& tests, const std::string& filename);
    int runTests(const std::string& pattern_file, const std::string& expectations_file);
    int runTestsIndividual(const std::string& pattern_file, const std::string& expectations_file);
    
    std::string categoryToString(Category cat);
    std::map<std::string, std::string> generateFragments(Complexity complexity);
    std::pair<std::vector<std::string>, std::vector<std::string>> generateSeeds(Complexity complexity, std::set<std::string>& used_inputs);
    std::pair<std::vector<std::string>, std::vector<std::string>> generateInputs(Complexity complexity);
    std::string generateSimpleArg();
    std::string generateFlags(int count = 1);
    std::string generatePath();
    TestCase generateTestCase(int test_id, std::set<std::string>& used_inputs);
    std::string generatePattern(const std::vector<std::string>& matching_inputs, 
                                const std::vector<std::string>& counter_inputs,
                                const std::map<std::string, std::string>& fragments,
                                Complexity complexity,
                                std::string& proof_out);
    std::string transformPart(const std::string& part,
                              const std::map<std::string, std::string>& fragments,
                              Complexity complexity,
                              bool allow_wildcard,
                              const std::vector<std::string>& counter_inputs,
                              const std::string& current_pattern,
                              std::string& proof_out);
    bool wouldPatternMatch(const std::string& input, const std::string& pattern);

private:
    Options opts;
    std::mt19937 rng;
    std::vector<TestCase> generated_tests;
    int global_failed_count = 0;  // Persist across batches for saving failed cases
    
    static const std::vector<std::string> COMMANDS;
    static const std::vector<std::string> FLAGS;
    static const std::vector<std::string> FILE_EXTS;
    static const std::map<std::string, std::string> FRAGMENTS;
    
    std::string makeLiteralPattern(const std::vector<std::string>& parts);
    std::string makeMediumPattern(const std::vector<std::string>& parts, 
                                  const std::map<std::string, std::string>& fragments);
    std::string makeComplexPattern(const std::vector<std::string>& parts,
                                    const std::map<std::string, std::string>& fragments);
    
    Category randomCategory();
    std::string generateMediumArg();
    std::string generateComplexArg();
    std::vector<std::string> generateCounterInputsSimple(const std::string& arg, const std::string& cmd);
    std::vector<std::string> generateCounterInputsMedium(const std::string& flags, const std::string& arg, const std::string& cmd);
    std::vector<std::string> generateCounterInputsComplex(const std::string& flags, const std::vector<std::string>& args, const std::string& cmd);
    
    bool wouldMatchWithoutOptional(const std::string& pattern_prefix, const std::string& counter_input);
    bool wouldMatchWithAlternation(const std::string& pattern_prefix, const std::string& literal_part, const std::string& counter_input);
};

#endif // TESTGEN_H
