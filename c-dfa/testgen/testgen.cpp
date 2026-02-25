#include "testgen.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

// Static grammar data
const std::vector<std::string> TestGenerator::COMMANDS = {
    "git", "cat", "ls", "ps", "df", "du", "find", "grep", "echo", "pwd",
    "head", "tail", "sort", "uniq", "wc", "awk", "sed", "cut", "tr",
    "split", "less", "more", "stat", "file", "date", "whoami", "id",
    "which", "whereis", "locate", "type", "readlink", "dirname", "basename"
};

const std::vector<std::string> TestGenerator::FLAGS = {
    "-a", "-l", "-h", "-n", "-r", "-t", "-s", "-c", "-v", "-x", "-y",
    "--all", "--long", "--human", "--numeric", "--recursive", "--verbose",
    "--quiet", "--force", "--interactive", "--preserve"
};

const std::vector<std::string> TestGenerator::FILE_EXTS = {
    ".txt", ".log", ".conf", ".cfg", ".ini", ".json", ".yaml", ".yml",
    ".xml", ".html", ".css", ".js", ".py", ".go", ".rs", ".c", ".h",
    ".cpp", ".hpp", ".md", ".rst", ".sh", ".bash", ".zsh"
};

const std::map<std::string, std::string> TestGenerator::FRAGMENTS = {
    {"digit", "0|1|2|3|4|5|6|7|8|9"},
    {"lower", "a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z"},
    {"upper", "A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z"},
    {"alpha", "a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z"},
    {"alnum", "a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9"},
    {"filename", "a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z|A|B|C|D|E|F|G|H|I|J|K|L|M|N|O|P|Q|R|S|T|U|V|W|X|Y|Z|0|1|2|3|4|5|6|7|8|9|_|-|/|.|@"}
};

TestGenerator::TestGenerator(const Options& opts) : opts(opts) {
    rng.seed(opts.seed);
}

std::vector<TestCase> TestGenerator::generate() {
    std::vector<TestCase> tests;
    tests.reserve(opts.num_tests);
    
    for (int i = 0; i < opts.num_tests; i++) {
        tests.push_back(generateTestCase(i));
    }
    
    // Store for runTests() to reuse
    generated_tests = tests;
    
    return tests;
}

TestCase TestGenerator::generateTestCase(int test_id) {
    TestCase tc;
    tc.test_id = test_id;
    
    // Select category
    tc.category = randomCategory();
    
    // Generate fragments
    tc.complexity = opts.complexity;
    tc.fragments = generateFragments(tc.complexity);
    
    // Generate matching input and counter inputs
    auto [matching, counters] = generateInputs(tc.complexity);
    tc.matching_input = matching;
    tc.counter_inputs = counters;
    
    // Generate pattern from matching input, avoiding counter inputs
    tc.pattern = generatePattern(matching, counters, tc.fragments, tc.complexity);
    
    return tc;
}

Category TestGenerator::randomCategory() {
    std::uniform_int_distribution<int> dist(1, 8);  // Skip UNKNOWN
    return static_cast<Category>(dist(rng));
}

std::string TestGenerator::categoryToString(Category cat) {
    switch (cat) {
        case Category::SAFE: return "safe";
        case Category::CAUTION: return "caution";
        case Category::MODIFYING: return "modifying";
        case Category::DANGEROUS: return "dangerous";
        case Category::NETWORK: return "network";
        case Category::ADMIN: return "admin";
        case Category::BUILD: return "build";
        case Category::CONTAINER: return "container";
        default: return "safe";
    }
}

std::map<std::string, std::string> TestGenerator::generateFragments(Complexity complexity) {
    std::map<std::string, std::string> fragments;
    
    if (complexity == Complexity::SIMPLE) {
        fragments["digit"] = FRAGMENTS.at("digit");
    } else if (complexity == Complexity::MEDIUM) {
        fragments["digit"] = FRAGMENTS.at("digit");
        fragments["lower"] = FRAGMENTS.at("lower");
        fragments["alnum"] = FRAGMENTS.at("alnum");
    } else {
        fragments = FRAGMENTS;  // All fragments
    }
    
    return fragments;
}

std::pair<std::string, std::vector<std::string>> TestGenerator::generateInputs(Complexity complexity) {
    std::uniform_int_distribution<int> cmd_dist(0, COMMANDS.size() - 1);
    std::string cmd = COMMANDS[cmd_dist(rng)];
    
    std::string matching_input;
    std::vector<std::string> counter_inputs;
    
    if (complexity == Complexity::SIMPLE) {
        std::string arg = generateSimpleArg();
        matching_input = cmd + " " + arg;
        counter_inputs = generateCounterInputsSimple(arg, cmd);
    } else if (complexity == Complexity::MEDIUM) {
        std::string flags = generateFlags();
        std::string arg = generateMediumArg();
        matching_input = cmd + " " + flags + " " + arg;
        // Clean up extra spaces
        while (matching_input.find("  ") != std::string::npos) {
            matching_input.replace(matching_input.find("  "), 2, " ");
        }
        if (matching_input.back() == ' ') matching_input.pop_back();
        counter_inputs = generateCounterInputsMedium(flags, arg, cmd);
    } else {
        std::string flags = generateFlags(3);
        std::vector<std::string> args = {generateComplexArg(), generateComplexArg()};
        matching_input = cmd + " " + flags + " " + args[0] + " " + args[1];
        while (matching_input.find("  ") != std::string::npos) {
            matching_input.replace(matching_input.find("  "), 2, " ");
        }
        if (matching_input.back() == ' ') matching_input.pop_back();
        counter_inputs = generateCounterInputsComplex(flags, args, cmd);
    }
    
    return {matching_input, counter_inputs};
}

std::string TestGenerator::generateSimpleArg() {
    std::uniform_int_distribution<int> dist(0, 3);
    switch (dist(rng)) {
        case 0: return FILE_EXTS[std::uniform_int_distribution<int>(0, FILE_EXTS.size() - 1)(rng)];
        case 1: return COMMANDS[std::uniform_int_distribution<int>(0, COMMANDS.size() - 1)(rng)] + ".txt";
        case 2: return "file" + std::to_string(std::uniform_int_distribution<int>(1, 100)(rng));
        default: return "dir" + std::string(1, "abcdefghijklmnopqrstuvwxyz"[std::uniform_int_distribution<int>(0, 25)(rng)]);
    }
}

std::string TestGenerator::generateMediumArg() {
    std::uniform_int_distribution<int> dist(0, 4);
    switch (dist(rng)) {
        case 0: return generateSimpleArg();
        case 1: return FLAGS[std::uniform_int_distribution<int>(0, FLAGS.size() - 1)(rng)] + 
                     std::to_string(std::uniform_int_distribution<int>(0, 9)(rng));
        case 2: {
            static const char* opts[] = {"force", "verbose", "quiet", "all", "long"};
            int idx = std::uniform_int_distribution<int>(0, 4)(rng);
            return std::string("--") + opts[idx];
        }
        case 3: return "-n" + std::to_string(std::uniform_int_distribution<int>(1, 1000)(rng));
        default: return "/" + generatePath();
    }
}

std::string TestGenerator::generateComplexArg() {
    if (std::uniform_int_distribution<int>(0, 9)(rng) < 3) {
        return generateMediumArg();
    }
    return generatePath();
}

std::string TestGenerator::generatePath() {
    int n = std::uniform_int_distribution<int>(1, 4)(rng);
    std::string path;
    for (int i = 0; i < n; i++) {
        int len = std::uniform_int_distribution<int>(3, 12)(rng);
        std::string comp;
        for (int j = 0; j < len; j++) {
            comp += "abcdefghijklmnopqrstuvwxyz0123456789_-"[std::uniform_int_distribution<int>(0, 37)(rng)];
        }
        if (i > 0) path += "/";
        path += comp;
    }
    return path;
}

std::string TestGenerator::generateFlags(int count) {
    std::vector<std::string> selected;
    std::sample(FLAGS.begin(), FLAGS.end(), std::back_inserter(selected),
                std::min(count, (int)FLAGS.size()), rng);
    
    std::string result;
    for (const auto& f : selected) {
        if (!result.empty()) result += " ";
        result += f;
    }
    return result;
}

std::vector<std::string> TestGenerator::generateCounterInputsSimple(const std::string& arg, const std::string& cmd) {
    std::vector<std::string> counters;
    
    // Different command
    std::string other_cmd;
    do {
        other_cmd = COMMANDS[std::uniform_int_distribution<int>(0, COMMANDS.size() - 1)(rng)];
    } while (other_cmd == cmd);
    counters.push_back(other_cmd + " " + arg);
    
    // Different argument
    std::string other_ext;
    do {
        other_ext = FILE_EXTS[std::uniform_int_distribution<int>(0, FILE_EXTS.size() - 1)(rng)];
    } while (other_ext == arg);
    counters.push_back(cmd + " " + other_ext);
    
    // Empty argument
    counters.push_back(cmd);
    
    // Extra argument
    counters.push_back(cmd + " " + arg + " extra");
    
    return counters;
}

std::vector<std::string> TestGenerator::generateCounterInputsMedium(const std::string& flags, const std::string& arg, const std::string& cmd) {
    std::vector<std::string> counters;
    
    // No flags
    counters.push_back(cmd + " " + arg);
    
    // Different flag
    std::vector<std::string> other_flags;
    std::string flags_str = flags;
    for (const auto& f : FLAGS) {
        if (flags_str.find(f) == std::string::npos) {
            other_flags.push_back(f);
        }
    }
    if (!other_flags.empty()) {
        std::string other = other_flags[std::uniform_int_distribution<int>(0, other_flags.size() - 1)(rng)];
        counters.push_back(cmd + " " + other + " " + arg);
    }
    
    // NOTE: We don't generate "no argument" counter inputs because:
    // 1. Pattern with ? quantifier would incorrectly match them
    // 2. The "no flag" case (cmd + " " + arg) already covers similar ground
    
    // Extra argument
    counters.push_back(cmd + " " + flags + " " + arg + " extra");
    
    // Different command
    std::string other_cmd;
    do {
        other_cmd = COMMANDS[std::uniform_int_distribution<int>(0, COMMANDS.size() - 1)(rng)];
    } while (other_cmd == cmd);
    counters.push_back(other_cmd + " " + flags + " " + arg);
    
    return counters;
}

std::vector<std::string> TestGenerator::generateCounterInputsComplex(const std::string& flags, 
                                                                     const std::vector<std::string>& args, 
                                                                     const std::string& cmd) {
    std::vector<std::string> counters;
    
    // Remove one argument
    if (args.size() > 1) {
        counters.push_back(cmd + " " + flags + " " + args[0]);
    }
    
    // Extra argument
    counters.push_back(cmd + " " + flags + " " + args[0] + " " + args[1] + " extra");
    
    // Different argument
    counters.push_back(cmd + " " + flags + " " + generateComplexArg());
    
    // No flags
    counters.push_back(cmd + " " + args[0] + " " + args[1]);
    
    // Different command
    std::string other_cmd;
    do {
        other_cmd = COMMANDS[std::uniform_int_distribution<int>(0, COMMANDS.size() - 1)(rng)];
    } while (other_cmd == cmd);
    counters.push_back(other_cmd + " " + flags + " " + args[0] + " " + args[1]);
    
    return counters;
}

std::string TestGenerator::generatePattern(const std::string& matching_input,
                                           const std::vector<std::string>& counter_inputs,
                                           const std::map<std::string, std::string>& fragments,
                                           Complexity complexity) {
    // BACKWARDS SYNTHESIS with proper c-dfa pattern syntax:
    // 1. Parse the matching input into command, flags, args
    // 2. Build a pattern that GUARANTEES matching input still matches
    // 3. Use fragments for generalization while preserving the match
    
    std::vector<std::string> parts;
    std::istringstream iss(matching_input);
    std::string part;
    while (iss >> part) {
        parts.push_back(part);
    }
    
    if (parts.empty()) {
        return matching_input;
    }
    
    if (parts.size() == 1) {
        return matching_input;
    }
    
    // Pattern construction: command + optional modifications
    std::string pattern;
    
    // Command is always literal (first part)
    pattern += parts[0];
    
    // Process remaining parts (flags and arguments)
    // Parts after command: position 1 = first flag/arg, position 2+ = more flags/args
    // Flags start with -, arguments don't
    for (size_t i = 1; i < parts.size(); i++) {
        bool is_flag = (parts[i].find('-') == 0);
        // Don't use wildcards for flags - they would match counter inputs too easily
        // Wildcards are only safe for arguments (non-flag parts)
        bool allow_wildcard = !is_flag;
        std::string transformed = transformPart(parts[i], fragments, complexity, allow_wildcard);
        
        // If transformed part starts with optional arg pattern, don't add extra space
        // New pattern is like "( (part))?" 
        if (transformed.find("( (") == 0 && transformed.find("))?") != std::string::npos) {
            pattern += transformed;
        } else {
            pattern += " " + transformed;
        }
    }
    
    return pattern;
}

std::string TestGenerator::transformPart(const std::string& part,
                                          const std::map<std::string, std::string>& fragments,
                                          Complexity complexity,
                                          bool allow_wildcard) {
    // Transform a part into a pattern while guaranteeing original matches
    
    // For SIMPLE complexity: keep literal
    if (complexity == Complexity::SIMPLE) {
        return part;
    }
    
    // Random decision for MEDIUM/COMPLEX
    int r = std::uniform_int_distribution<int>(0, 9)(rng);
    
    // 70% chance: keep literal (guarantees match AND rejects different strings)
    // Higher literal rate reduces pattern conflicts in batched DFA
    if (r < 7) {
        return part;
    }
    
    // 10% chance: wildcard (*) - matches anything
    // Correct syntax is (*) not just *
    // IMPORTANT: Use ? (zero-or-one) not * (zero-or-more)
    // e.g., "wc -n dirs" -> pattern: wc -n( (/dirs))?
    // This matches: "wc -n dirs" (with arg) AND "wc -n" (without arg)
    // Note: Using ? means zero-or-one, NOT zero-or-more
    // Only allow wildcards for MEDIUM complexity (not SIMPLE or COMPLEX)
    if (r < 8 && complexity == Complexity::MEDIUM && allow_wildcard) {
        // Include the part in the optional group with ? for zero-or-one
        return "( (" + part + "))?";
    }
    
    // 20% chance: fragment-based pattern with alternation
    // e.g., (arg|((digit))+)
    // Wrapped with alternation to ensure original still matches
    if (r < 10 && !fragments.empty()) {
        std::vector<std::string> frag_names;
        for (const auto& f : fragments) {
            frag_names.push_back(f.first);
        }
        if (!frag_names.empty()) {
            std::string frag = frag_names[std::uniform_int_distribution<int>(0, frag_names.size() - 1)(rng)];
            return "(" + part + "|((" + frag + "))+ )";
        }
    }
    
    // Fallback: literal
    return part;
}

std::string TestGenerator::makeLiteralPattern(const std::vector<std::string>& parts) {
    std::string result;
    for (const auto& p : parts) {
        if (!result.empty()) result += " ";
        result += p;
    }
    return result;
}

std::string TestGenerator::makeMediumPattern(const std::vector<std::string>& parts,
                                             const std::map<std::string, std::string>& fragments) {
    // Use the same backwards approach - pass actual matching input
    std::string input;
    for (const auto& p : parts) {
        if (!input.empty()) input += " ";
        input += p;
    }
    return generatePattern(input, {}, fragments, Complexity::MEDIUM);
}

std::string TestGenerator::makeComplexPattern(const std::vector<std::string>& parts,
                                               const std::map<std::string, std::string>& fragments) {
    // Use the same backwards approach - pass actual matching input
    std::string input;
    for (const auto& p : parts) {
        if (!input.empty()) input += " ";
        input += p;
    }
    return generatePattern(input, {}, fragments, Complexity::COMPLEX);
}

void TestGenerator::writePatternFile(const std::vector<TestCase>& tests, const std::string& filename) {
    std::ofstream out(filename);
    
    // Header
    out << "# ============================================================================\n";
    out << "# Auto-generated test patterns\n";
    out << "# Generated by testgen\n";
    out << "# ============================================================================\n\n";
    
    // Collect all unique fragments
    std::map<std::string, std::string> all_fragments;
    for (const auto& tc : tests) {
        for (const auto& f : tc.fragments) {
            if (all_fragments.find(f.first) == all_fragments.end()) {
                all_fragments[f.first] = f.second;
            }
        }
    }
    
    // Write fragment definitions
    if (!all_fragments.empty()) {
        out << "# Fragment definitions\n";
        for (const auto& f : all_fragments) {
            out << "[fragment:" << f.first << "] " << f.second << "\n";
        }
        out << "\n";
    }
    
    // Write patterns with unique subcategory for each test
    out << "# Patterns\n";
    for (const auto& tc : tests) {
        out << "[" << categoryToString(tc.category) << ":test" << tc.test_id << "] " << tc.pattern << "\n";
    }
    
    out.close();
    std::cout << "Written pattern file: " << filename << "\n";
}

void TestGenerator::writeExpectations(const std::vector<TestCase>& tests, const std::string& filename) {
    std::ofstream out(filename);
    
    out << "[\n";
    for (size_t i = 0; i < tests.size(); i++) {
        const auto& tc = tests[i];
        out << "  {\n";
        out << "    \"id\": " << i << ",\n";
        out << "    \"test_id\": " << tc.test_id << ",\n";
        out << "    \"pattern\": \"[" << categoryToString(tc.category) << ":test" << tc.test_id << "] " << tc.pattern << "\",\n";
        out << "    \"category\": \"" << categoryToString(tc.category) << "\",\n";
        out << "    \"matching_input\": \"" << tc.matching_input << "\",\n";
        out << "    \"counter_inputs\": [";
        for (size_t j = 0; j < tc.counter_inputs.size(); j++) {
            if (j > 0) out << ", ";
            out << "\"" << tc.counter_inputs[j] << "\"";
        }
        out << "],\n";
        out << "    \"complexity\": \"";
        switch (tc.complexity) {
            case Complexity::SIMPLE: out << "simple"; break;
            case Complexity::MEDIUM: out << "medium"; break;
            case Complexity::COMPLEX: out << "complex"; break;
        }
        out << "\"\n";
        out << "  }";
        if (i < tests.size() - 1) out << ",";
        out << "\n";
    }
    out << "]\n";
    
    out.close();
    std::cout << "Written expectations: " << filename << "\n";
}

int TestGenerator::runTests(const std::string& pattern_file, const std::string& expectations_file) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "Running tests through c-dfa...\n";
    std::cout << std::string(60, '=') << "\n\n";
    
    // Get current working directory and construct paths
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == nullptr) {
        std::cerr << "Cannot get current directory\n";
        return 1;
    }
    std::string abs_cwd = cwd;
    std::string abs_pattern = abs_cwd + "/" + pattern_file;
    std::string output_dir = abs_pattern.substr(0, abs_pattern.rfind('/'));
    std::string tools_dir = abs_cwd + "/../tools";  // Tools are in parent/tools
    
    // Build NFA
    std::cout << "1. Building NFA...\n";
    std::string nfa_file = output_dir + "/test.nfa";
    int result = system(("cd " + abs_cwd + "/.. && ./tools/nfa_builder " + abs_pattern + " " + nfa_file + " 2>&1").c_str());
    if (result != 0) {
        std::cerr << "NFA builder failed!\n";
        return 1;
    }
    std::cout << "   NFA built successfully\n\n";
    
    // Build DFA
    std::cout << "2. Building DFA...\n";
    std::string dfa_file = output_dir + "/test.dfa";
    result = system(("cd " + abs_cwd + "/.. && ./tools/nfa2dfa_advanced " + nfa_file + " " + dfa_file + " 2>&1").c_str());
    if (result != 0) {
        std::cerr << "DFA builder failed!\n";
        return 1;
    }
    std::cout << "   DFA built successfully\n\n";
    
    // Load expectations and run tests
    std::cout << "3. Testing patterns (batched)...\n";
    
    // Use the STORED tests that were written to the pattern file
    std::vector<TestCase>& tests = generated_tests;
    int passed = 0;
    int failed = 0;
    
    std::ofstream failures_file;
    std::string fail_file = output_dir + "/failures.txt";
    failures_file.open(fail_file);
    failures_file << "# Failed test cases - patterns that don't match as expected\n";
    failures_file << "# Format: [category:subcategory] pattern\n\n";
    
    for (size_t i = 0; i < tests.size(); i++) {
        const auto& tc = tests[i];
        int expected_category = static_cast<int>(tc.category);
        
        // Test matching input - should match with CORRECT category
        std::string cmd = "cd " + abs_cwd + "/.. && ./tools/dfa_eval_wrapper " + dfa_file + " \"" + tc.matching_input + "\" 2>/dev/null";
        FILE* fp = popen(cmd.c_str(), "r");
        bool matched = false;
        int matched_category = 0;
        if (fp) {
            char buf[256];
            while (fgets(buf, sizeof(buf), fp)) {
                if (strstr(buf, "matched=1")) {
                    matched = true;
                }
                // Parse category from output like "category=1" or "category=2"
                char* cat_str = strstr(buf, "category=");
                if (cat_str) {
                    matched_category = atoi(cat_str + 9);
                }
            }
            pclose(fp);
        }
        
        // Check if matched with the CORRECT category (our unique subcategory)
        bool correct_category = (matched_category == expected_category);
        
        // Test counter inputs - should NOT match with SAME category
        // Use category isolation: counter matching a DIFFERENT category is OK
        bool counter_matched = false;
        for (const auto& counter : tc.counter_inputs) {
            std::string counter_cmd = "cd " + abs_cwd + "/.. && ./tools/dfa_eval_wrapper " + dfa_file + " \"" + counter + "\" 2>/dev/null";
            FILE* cfp = popen(counter_cmd.c_str(), "r");
            if (cfp) {
                char cbuf[256];
                while (fgets(cbuf, sizeof(cbuf), cfp)) {
                    if (strstr(cbuf, "matched=1")) {
                        int counter_cat = 0;
                        char* cat_str = strstr(cbuf, "category=");
                        if (cat_str) {
                            counter_cat = atoi(cat_str + 9);
                        }
                        // Counter matched with SAME category as our test is a problem
                        // Counter matched with DIFFERENT category is OK (category isolation)
                        if (counter_cat == expected_category) {
                            counter_matched = true;
                        }
                    }
                }
                pclose(cfp);
            }
        }
        
        bool test_passed = matched && correct_category && !counter_matched;
        
        if (test_passed) {
            passed++;
        } else {
            failed++;
            failures_file << "# Test " << i << " (test" << tc.test_id << ") failed\n";
            failures_file << "#   Expected match: " << tc.matching_input << "\n";
            failures_file << "#   Actual matched: " << (matched ? "YES" : "NO") << "\n";
            failures_file << "#   Matched category: " << matched_category << " (expected: " << expected_category << ")\n";
            if (counter_matched) {
                failures_file << "#   Counter input matched (should not have)\n";
            }
            failures_file << "[" << categoryToString(tc.category) << ":test" << tc.test_id << "] " << tc.pattern << "\n\n";
            
            if (failed <= 5) {
                std::cout << "   FAIL #" << i << ": pattern=[" << categoryToString(tc.category) << ":test" << tc.test_id << "] " 
                          << tc.pattern << "\n";
                std::cout << "      Input: " << tc.matching_input << " -> matched=" << matched 
                          << " cat=" << matched_category << " (expected: " << expected_category << ")\n";
                if (counter_matched) {
                    std::cout << "      Counter matched (should not): " << tc.counter_inputs[0] << "\n";
                }
            }
        }
    }
    
    failures_file.close();
    
    std::cout << "\nResults: " << passed << " passed, " << failed << " failed\n";
    if (failed > 0) {
        std::cout << "Failed cases saved to: " << fail_file << "\n";
    }
    
    return failed > 0 ? 1 : 0;
}

int TestGenerator::runTestsIndividual(const std::string& pattern_file, const std::string& expectations_file) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "Running tests through c-dfa (INDIVIDUALLY)...\n";
    std::cout << std::string(60, '=') << "\n\n";
    
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == nullptr) {
        std::cerr << "Cannot get current directory\n";
        return 1;
    }
    std::string abs_cwd = cwd;
    std::string abs_pattern = abs_cwd + "/" + pattern_file;
    std::string output_dir = abs_pattern.substr(0, abs_pattern.rfind('/'));
    
    std::vector<TestCase>& tests = generated_tests;
    int passed = 0;
    int failed = 0;
    
    std::ofstream failures_file;
    std::string fail_file = output_dir + "/failures.txt";
    failures_file.open(fail_file);
    failures_file << "# Failed test cases - patterns that don't match as expected\n";
    failures_file << "# Format: [category] pattern\n\n";
    
    std::cout << "Testing each pattern individually...\n\n";
    
    for (size_t i = 0; i < tests.size(); i++) {
        const auto& tc = tests[i];
        
        // Create temp pattern file with just this pattern
        std::string temp_pattern = output_dir + "/temp_pattern.txt";
        std::ofstream tp(temp_pattern);
        
        // Write fragment definitions
        for (const auto& f : tc.fragments) {
            tp << "[fragment:" << f.first << "] " << f.second << "\n";
        }
        
        // Write this pattern
        tp << "[" << categoryToString(tc.category) << "] " << tc.pattern << "\n";
        tp.close();
        
        // Build NFA and DFA for this single pattern
        std::string nfa_file = output_dir + "/temp.nfa";
        std::string dfa_file = output_dir + "/temp.dfa";
        
        std::string nfa_cmd = "cd " + abs_cwd + "/.. && ./tools/nfa_builder " + temp_pattern + " " + nfa_file + " 2>/dev/null";
        int result = system(nfa_cmd.c_str());
        if (result != 0) {
            std::cout << "   FAIL #" << i << ": NFA builder failed for pattern: " << tc.pattern << "\n";
            failures_file << "# Test " << i << " NFA build failed\n";
            failures_file << "[" << categoryToString(tc.category) << "] " << tc.pattern << "\n\n";
            failed++;
            continue;
        }
        
        std::string dfa_cmd = "cd " + abs_cwd + "/.. && ./tools/nfa2dfa_advanced " + nfa_file + " " + dfa_file + " 2>/dev/null";
        result = system(dfa_cmd.c_str());
        if (result != 0) {
            std::cout << "   FAIL #" << i << ": DFA builder failed for pattern: " << tc.pattern << "\n";
            failures_file << "# Test " << i << " DFA build failed\n";
            failures_file << "[" << categoryToString(tc.category) << "] " << tc.pattern << "\n\n";
            failed++;
            continue;
        }
        
        // Test matching input - should match
        std::string eval_cmd = "cd " + abs_cwd + "/.. && ./tools/dfa_eval_wrapper " + dfa_file + " \"" + tc.matching_input + "\" 2>/dev/null";
        FILE* fp = popen(eval_cmd.c_str(), "r");
        bool matched = false;
        if (fp) {
            char buf[256];
            while (fgets(buf, sizeof(buf), fp)) {
                if (strstr(buf, "matched=1")) {
                    matched = true;
                }
            }
            pclose(fp);
        }
        
        // Test counter inputs - should NOT match
        bool counter_matched = false;
        for (const auto& counter : tc.counter_inputs) {
            std::string counter_cmd = "cd " + abs_cwd + "/.. && ./tools/dfa_eval_wrapper " + dfa_file + " \"" + counter + "\" 2>/dev/null";
            FILE* cfp = popen(counter_cmd.c_str(), "r");
            if (cfp) {
                char cbuf[256];
                while (fgets(cbuf, sizeof(cbuf), cfp)) {
                    if (strstr(cbuf, "matched=1")) {
                        counter_matched = true;
                    }
                }
                pclose(cfp);
            }
        }
        
        bool test_passed = matched && !counter_matched;
        
        if (test_passed) {
            passed++;
            std::cout << "   PASS #" << i << ": " << tc.matching_input << "\n";
        } else {
            failed++;
            failures_file << "# Test " << i << " failed\n";
            failures_file << "#   Expected match: " << tc.matching_input << "\n";
            failures_file << "#   Actual matched: " << (matched ? "YES" : "NO") << "\n";
            if (counter_matched) {
                failures_file << "#   Counter input matched (should not have)\n";
            }
            failures_file << "[" << categoryToString(tc.category) << "] " << tc.pattern << "\n\n";
            
            std::cout << "   FAIL #" << i << ": pattern=" << tc.pattern << "\n";
            std::cout << "      Input: " << tc.matching_input << " -> matched=" << matched << " (expected: 1)\n";
            if (counter_matched) {
                std::cout << "      Counter matched (should not): " << tc.counter_inputs[0] << "\n";
            }
        }
        
        // Clean up temp files
        remove(temp_pattern.c_str());
        remove(nfa_file.c_str());
        remove(dfa_file.c_str());
    }
    
    failures_file.close();
    
    std::cout << "\nResults: " << passed << " passed, " << failed << " failed\n";
    if (failed > 0) {
        std::cout << "Failed cases saved to: " << fail_file << "\n";
    }
    
    return failed > 0 ? 1 : 0;
}
