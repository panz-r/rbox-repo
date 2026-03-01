#ifndef TESTGEN_H
#define TESTGEN_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <random>
#include <memory>
#include <functional>

// ============================================================================
// Pattern AST - Represents patterns as an Abstract Syntax Tree
// ============================================================================

enum class PatternType {
    LITERAL,           // Plain string: "abc"
    OPTIONAL,          // Optional: (abc)?
    PLUS_QUANTIFIER,   // One or more: (abc)+
    STAR_QUANTIFIER,   // Zero or more: (abc)*
    ALTERNATION,       // OR: (a|b|c)
    FRAGMENT_REF,      // Fragment reference: ((name))+
    SEQUENCE           // Sequence: abcdef
};

struct PatternNode {
    PatternType type = PatternType::LITERAL;
    std::string value;                              // For literals
    std::string fragment_name;                      // For fragments
    std::vector<std::shared_ptr<PatternNode>> children;  // For sequences/alternations
    std::shared_ptr<PatternNode> quantified;         // For quantifiers (+, *, ?)
    std::vector<std::string> matched_seeds;         // Seeds this node matches
    std::string capture_tag;                        // If set, wrap with <tag>...</tag>
    std::string capture_begin_only;                 // Unmatched <tag>
    std::string capture_end_only;                   // Unmatched </tag>
    
    static std::shared_ptr<PatternNode> createLiteral(const std::string& val, const std::vector<std::string>& seeds = {});
    static std::shared_ptr<PatternNode> createFragment(const std::string& name, const std::vector<std::string>& seeds = {});
    static std::shared_ptr<PatternNode> createSequence(const std::vector<std::shared_ptr<PatternNode>>& kids, const std::vector<std::string>& seeds = {});
    static std::shared_ptr<PatternNode> createAlternation(const std::vector<std::shared_ptr<PatternNode>>& alts, const std::vector<std::string>& seeds = {});
    static std::shared_ptr<PatternNode> createQuantified(std::shared_ptr<PatternNode> child, PatternType quant_type, const std::vector<std::string>& seeds = {});
};

// Serialize PatternNode to string with capture tags
std::string serializePattern(std::shared_ptr<PatternNode> node);

// Parse pattern string to AST
std::shared_ptr<PatternNode> parsePatternToAST(const std::string& pattern);

// Add capture tags to AST nodes
void addCaptureTags(std::shared_ptr<PatternNode> node, std::mt19937& rng);

// Pattern rewriting that keeps matching set constant but complicates expression
void rewritePattern(std::shared_ptr<PatternNode> node, std::mt19937& rng);

// Collect all seeds that should be captured
std::vector<std::string> collectCaptureSeeds(std::shared_ptr<PatternNode> node);

// ============================================================================
// Edge-Case Seeding Types - Coordinated seeds + pattern for bug detection
// ============================================================================

enum class EdgeCaseType {
    RANGE_BOUNDARY,      // Consecutive chars at boundaries (a-z, 0-9)
    PARTIAL_MATCH_FAIL,  // Prefix matches, then fails (ab matches, abx fails)
    QUANTIFIER_EDGE,    // Empty, single, multiple repetitions
    ALTERNATION_EDGE,   // Some alternatives match, some don't
    NESTED_QUANTIFIER   // Nested quantifiers ((ab)+)*
};

struct EdgeCaseResult {
    std::vector<std::string> matching_seeds;
    std::vector<std::string> counter_seeds;
    std::shared_ptr<PatternNode> initial_ast;
    std::string proof;
    EdgeCaseType type;
    std::map<std::string, std::string> fragments;  // fragment definitions
};

// Generate edge-case coordinated seeds + pattern
EdgeCaseResult generateEdgeCase(EdgeCaseType type, std::mt19937& rng);

// ============================================================================
// Test Generator Types
// ============================================================================

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

enum class ExpectationType {
    MATCH_EXACT,           // Input must match exactly with category
    NO_MATCH,              // Input must NOT match the category
    FRAGMENT_MATCH,        // Fragment reference must match fragment definition
    QUANTIFIER_STAR_EMPTY, // * should match empty string
    QUANTIFIER_PLUS_MINONE, // + should require at least one character
    ALTERNATION_INDIVIDUAL, // Each alternative must match individually
    CAPTURE_TAG_MATCH,     // Capture tags shouldn't change matching
    PREFIX_MATCH,          // Input must have specific prefix
    SUFFIX_MATCH,           // Input must have specific suffix
    CHAR_CLASS_MATCH,      // Input must match character class
    REPETITION_MIN_COUNT,  // Repetition must have minimum count
    FRAGMENT_NESTED         // Nested fragment reference must resolve correctly
};

struct Expectation {
    ExpectationType type;
    std::string input;           // The input to test
    std::string expected_match;  // "yes" or "no"
    std::string description;     // Human-readable description
    std::map<std::string, std::string> meta;  // Additional metadata
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
    std::string proof;           // Proof of correctness
    std::vector<Expectation> expectations;  // Deep semantic expectations
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
    void setTestsPerBatch(int count) { tests_per_batch_override = count; }
    
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
    int tests_per_batch_override = 0;  // Override for tests per batch
    
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
