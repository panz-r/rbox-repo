#include "testgen.h"
#include "pattern_strategies.h"
#include "expectation_gen.h"
#include "inductive_builder.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <set>
#include <unordered_set>
#include <optional>
#include <tuple>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

// ============================================================================
// Path Resolution Helper - Find tools directory relative to executable
// ============================================================================

#include <libgen.h>

std::string getToolsDir() {
    // Try to find tools directory relative to this executable
    // First check if we're in testgen/ subdirectory
    char exe_path[4096];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len != -1) {
        exe_path[len] = '\0';
        std::string exe_dir = dirname(exe_path);
        // If running from testgen/, tools are in parent directory
        if (exe_dir.find("testgen") != std::string::npos) {
            return exe_dir + "/../tools";
        }
        // Otherwise assume tools are in subdirectory
        return exe_dir + "/tools";
    }
    // Fallback: assume current directory
    return "./tools";
}

// ============================================================================
// Command Execution Helper - Captures stdout, stderr, and exit code
// ============================================================================

struct CommandResult {
    std::string stdout;
    std::string stderr;
    int exit_code;
};

CommandResult runCommand(const std::string& cmd) {
    CommandResult result;
    result.exit_code = 0;
    
    // Use popen for simpler stdout capture
    FILE* fp = popen((cmd + " 2>&1").c_str(), "r");
    if (!fp) {
        result.exit_code = -1;
        return result;
    }
    
    char buf[256];
    while (fgets(buf, sizeof(buf), fp) != nullptr) {
        result.stdout += buf;
    }
    
    int status = pclose(fp);
    if (WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    } else {
        result.exit_code = -1;
    }
    
    return result;
}

// ============================================================================
// Pattern AST Implementation
// ============================================================================

std::shared_ptr<PatternNode> PatternNode::createLiteral(const std::string& val, 
    const std::vector<std::string>& seeds,
    const std::vector<std::string>& counters) {
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::LITERAL;
    node->value = val;
    node->matched_seeds = seeds;
    node->counter_seeds = counters;
    return node;
}

std::shared_ptr<PatternNode> PatternNode::createFragment(const std::string& name, 
    const std::vector<std::string>& seeds,
    const std::vector<std::string>& counters) {
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::FRAGMENT_REF;
    node->fragment_name = name;
    node->matched_seeds = seeds;
    node->counter_seeds = counters;
    return node;
}

std::shared_ptr<PatternNode> PatternNode::createSequence(const std::vector<std::shared_ptr<PatternNode>>& kids, 
    const std::vector<std::string>& seeds,
    const std::vector<std::string>& counters) {
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::SEQUENCE;
    node->children = kids;
    node->matched_seeds = seeds;
    node->counter_seeds = counters;
    return node;
}

std::shared_ptr<PatternNode> PatternNode::createAlternation(const std::vector<std::shared_ptr<PatternNode>>& alts, 
    const std::vector<std::string>& seeds,
    const std::vector<std::string>& counters) {
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::ALTERNATION;
    node->children = alts;
    node->matched_seeds = seeds;
    node->counter_seeds = counters;
    return node;
}

std::shared_ptr<PatternNode> PatternNode::createQuantified(std::shared_ptr<PatternNode> child, 
    PatternType quant_type, 
    const std::vector<std::string>& seeds,
    const std::vector<std::string>& counters) {
    auto node = std::make_shared<PatternNode>();
    node->type = quant_type;
    node->quantified = child;
    node->matched_seeds = seeds;
    node->counter_seeds = counters;
    return node;
}

// ============================================================================
// Pattern Factory - Consolidated Quantified Node Creation
// ============================================================================
//
// These functions create quantified pattern nodes. The pattern is:
// 1. Create a child node (alternation, literal, or fragment)
// 2. Set the parent's type to the quantifier type
// 3. Set the parent's quantified field to the child
// 4. Assign matched_seeds to track which inputs should match
//
// Generalized factory functions handle all quantifier types. Convenience
// wrappers are provided for backward compatibility.


// ============================================================================
// Edge-Case Coordinated Seed+Pattern Generation
// ============================================================================

// Random string generator for edge cases
std::string randomAlphaEdge(int len, std::mt19937& rng) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::uniform_int_distribution<int> dist(0, sizeof(charset) - 2);
    std::string result;
    for (int i = 0; i < len; i++) {
        result += charset[dist(rng)];
    }
    return result;
}

// Edge Case 1: RANGE_BOUNDARY - Consecutive chars at boundaries
EdgeCaseResult createRangeBoundaryEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::RANGE_BOUNDARY;
    
    // Choose a consecutive range: lowercase, uppercase, or digits
    std::uniform_int_distribution<int> range_dist(0, 2);
    int range_type = range_dist(rng);
    
    std::string range_name;
    std::vector<char> chars;
    
    if (range_type == 0) {
        // lowercase a-z
        range_name = "lower";
        for (char c = 'a'; c <= 'z'; c++) chars.push_back(c);
    } else if (range_type == 1) {
        // uppercase A-Z
        range_name = "upper";
        for (char c = 'A'; c <= 'Z'; c++) chars.push_back(c);
    } else {
        // digits 0-9
        range_name = "digit";
        for (char c = '0'; c <= '9'; c++) chars.push_back(c);
    }
    
    // Create fragment definition with some chars from range
    std::string frag_def;
    std::vector<std::string> frag_chars;
    std::uniform_int_distribution<int> char_idx(0, (int)chars.size() - 1);
    
    // Pick 5-10 characters from the range
    int num_chars = 5 + std::uniform_int_distribution<int>(0, 5)(rng);
    std::set<char> selected;
    for (int i = 0; i < num_chars; i++) {
        selected.insert(chars[char_idx(rng)]);
    }
    for (char c : selected) {
        std::string s(1, c);
        frag_def += s + "|";
        frag_chars.push_back(s);
    }
    if (!frag_def.empty()) frag_def.pop_back(); // remove trailing |
    
    // Create fragment reference
    std::string frag_name = "range_" + range_name;
    
    // Build AST: ((range_lower))+
    auto frag_node = PatternNode::createFragment(frag_name, frag_chars);
    frag_node->type = PatternType::PLUS_QUANTIFIER;
    frag_node->quantified = PatternNode::createFragment(frag_name, frag_chars);
    result.initial_ast = frag_node;
    
    // Add fragment definition
    result.fragments[frag_name] = frag_def;
    
    result.proof = "EDGE_CASE: RANGE_BOUNDARY\n";
    result.proof += "  Fragment: " + frag_name + " = " + frag_def + "\n";
    result.proof += "  Pattern: ((" + frag_name + "))+\n";
    
    // Matching seeds: use the SELECTED chars (those in the fragment), not the full range
    // The selected set contains exactly the chars that are in frag_def
    for (char c : selected) {
        result.matching_seeds.push_back(std::string(1, c));
    }
    // Add some repetitions using selected chars
    std::vector<char> selected_vec(selected.begin(), selected.end());
    if (selected_vec.size() >= 2) {
        result.matching_seeds.push_back(std::string(1, selected_vec.front()) + std::string(1, selected_vec.front()));
        result.matching_seeds.push_back(std::string(1, selected_vec.back()) + std::string(1, selected_vec.back()));
    }
    
    // Counter seeds: characters NOT in the range
    static const char non_range[] = "!@#$%^&*()[]{}|;':\",./<>?";
    std::uniform_int_distribution<int> non_dist(0, sizeof(non_range) - 2);
    for (int i = 0; i < 10; i++) {
        std::string s(1, non_range[non_dist(rng)]);
        result.counter_seeds.push_back(s);
    }
    
    result.proof += "  Matching: ";
    for (auto& s : result.matching_seeds) result.proof += s + " ";
    result.proof += "\n  Counters: ";
    for (auto& s : result.counter_seeds) result.proof += s + " ";
    result.proof += "\n  Rationale: Tests range boundaries - matching uses edge chars from range, counters use non-range chars\n";
    
    return result;
}

// Edge Case 2: PARTIAL_MATCH_FAIL - Prefix matches, then fails
EdgeCaseResult createPartialMatchEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::PARTIAL_MATCH_FAIL;
    
    // Create a 2-3 char prefix
    std::string prefix = randomAlphaEdge(2, rng);
    
    // Create pattern: (prefix)+
    auto node = PatternNode::createLiteral(prefix, {prefix});
    node->type = PatternType::PLUS_QUANTIFIER;
    node->quantified = PatternNode::createLiteral(prefix, {prefix});
    result.initial_ast = node;
    
    // Matching seeds: exact repetitions of prefix
    result.matching_seeds.push_back(prefix);
    result.matching_seeds.push_back(prefix + prefix);
    result.matching_seeds.push_back(prefix + prefix + prefix);
    
    // Counter seeds: prefix + unexpected character
    static const char extras[] = "xyzXYZ012!@#%^&*()";
    std::uniform_int_distribution<int> extra_dist(0, sizeof(extras) - 2);
    for (int i = 0; i < 8; i++) {
        result.counter_seeds.push_back(prefix + extras[extra_dist(rng)]);
    }
    
    result.proof = "EDGE_CASE: PARTIAL_MATCH_FAIL\n";
    result.proof += "  Pattern: (" + prefix + ")+\n";
    result.proof += "  Matching: ";
    for (auto& s : result.matching_seeds) result.proof += s + " ";
    result.proof += "\n  Counters: ";
    for (auto& s : result.counter_seeds) result.proof += s + " ";
    result.proof += "\n  Rationale: Counters share prefix with pattern but have unexpected continuation\n";
    
    return result;
}

// Edge Case 3: QUANTIFIER_EDGE - Empty, single, multiple
EdgeCaseResult createQuantifierEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::QUANTIFIER_EDGE;
    
    // Choose quantifier type
    std::uniform_int_distribution<int> qtype(0, 2);
    int qt = qtype(rng);
    
    std::string base = randomAlphaEdge(1, rng); // single char
    
    PatternType quant_type;
    std::string quant_str;
    if (qt == 0) {
        quant_type = PatternType::PLUS_QUANTIFIER;
        quant_str = "+";
    } else if (qt == 1) {
        quant_type = PatternType::STAR_QUANTIFIER;
        quant_str = "*";
    } else {
        quant_type = PatternType::OPTIONAL;
        quant_str = "?";
    }
    
    // Create pattern
    auto node = PatternNode::createLiteral(base, {base});
    node->type = quant_type;
    node->quantified = PatternNode::createLiteral(base, {base});
    result.initial_ast = node;
    
    // Matching seeds based on quantifier
    if (qt == 0) {
        // + : one or more - need at least one
        result.matching_seeds.push_back(base);
        result.matching_seeds.push_back(base + base);
        result.matching_seeds.push_back(base + base + base);
    } else if (qt == 1) {
        // * : zero or more - empty allowed
        result.matching_seeds.push_back("");
        result.matching_seeds.push_back(base);
        result.matching_seeds.push_back(base + base + base);
    } else {
        // ? : zero or one
        result.matching_seeds.push_back("");
        result.matching_seeds.push_back(base);
    }
    
    // Counter seeds: different character
    std::string diff(1, base[0] + 1); // different char
    if (diff[0] > 'z') diff[0] = 'a';
    result.counter_seeds.push_back(diff);
    result.counter_seeds.push_back(diff + diff);
    
    result.proof = "EDGE_CASE: QUANTIFIER_EDGE\n";
    result.proof += "  Pattern: (" + base + ")" + quant_str + "\n";
    result.proof += "  Matching: ";
    for (auto& s : result.matching_seeds) result.proof += (s.empty() ? "<empty>, " : s + ", ");
    result.proof += "\n  Counters: ";
    for (auto& s : result.counter_seeds) result.proof += s + " ";
    result.proof += "\n  Rationale: Tests quantifier " + quant_str + " edge cases (empty, single, multiple)\n";
    
    return result;
}

// Edge Case 4: ALTERNATION_EDGE - Some alternatives match, some don't
EdgeCaseResult createAlternationEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::ALTERNATION_EDGE;
    
    // Create 3-5 alternatives
    int num_alts = 3 + std::uniform_int_distribution<int>(0, 2)(rng);
    std::vector<std::string> alts;
    std::set<char> used_chars;
    
    for (int i = 0; i < num_alts; i++) {
        std::string alt;
        do {
            alt = randomAlphaEdge(1 + std::uniform_int_distribution<int>(0, 1)(rng), rng);
        } while (used_chars.count(alt[0]));
        used_chars.insert(alt[0]);
        alts.push_back(alt);
    }
    
    // Build AST: (alt1|alt2|alt3)+
    std::vector<std::shared_ptr<PatternNode>> alt_nodes;
    for (auto& alt : alts) {
        alt_nodes.push_back(PatternNode::createLiteral(alt, {alt}));
    }
    auto node = PatternNode::createAlternation(alt_nodes, alts);
    node->type = PatternType::PLUS_QUANTIFIER;
    node->quantified = PatternNode::createAlternation(alt_nodes, alts);
    result.initial_ast = node;
    
    // Matching: each alternative individually and combined
    for (auto& alt : alts) {
        result.matching_seeds.push_back(alt);
    }
    // Combination
    result.matching_seeds.push_back(alts[0] + alts[1]);
    
    // Counter seeds: character NOT in alternatives
    char counter_char = '!';
    while (used_chars.count(counter_char)) counter_char++;
    result.counter_seeds.push_back(std::string(1, counter_char));
    result.counter_seeds.push_back(std::string(1, counter_char) + std::string(1, counter_char));
    // Also: wrong combination
    result.counter_seeds.push_back(alts[0] + counter_char);
    
    result.proof = "EDGE_CASE: ALTERNATION_EDGE\n";
    result.proof += "  Pattern: (";
    for (size_t i = 0; i < alts.size(); i++) {
        if (i > 0) result.proof += "|";
        result.proof += alts[i];
    }
    result.proof += ")+\n";
    result.proof += "  Matching: ";
    for (auto& s : result.matching_seeds) result.proof += s + " ";
    result.proof += "\n  Counters: ";
    for (auto& s : result.counter_seeds) result.proof += s + " ";
    result.proof += "\n  Rationale: Tests alternation - some alts match, counters fail at different points\n";
    
    return result;
}

// Edge Case 5: NESTED_QUANTIFIER - ((ab)+)*
EdgeCaseResult createNestedQuantifierEdge(std::mt19937& rng) {
    EdgeCaseResult result;
    result.type = EdgeCaseType::NESTED_QUANTIFIER;
    
    // Create inner pattern
    std::string inner = randomAlphaEdge(2, rng);
    
    // Build AST: ((inner)+
    auto inner_node = PatternNode::createLiteral(inner, {inner});
    inner_node->type = PatternType::PLUS_QUANTIFIER;
    inner_node->quantified = PatternNode::createLiteral(inner, {inner});
    
    // Outer: *
    auto node = PatternNode::createQuantified(inner_node, PatternType::STAR_QUANTIFIER, {inner});
    result.initial_ast = node;
    
    // Matching: inner repeated
    result.matching_seeds.push_back(inner);
    result.matching_seeds.push_back(inner + inner);
    result.matching_seeds.push_back(inner + inner + inner);
    
    // Counter: inner + unexpected (partial match that fails)
    static const char extras[] = "xyzXYZ012!@#";
    std::uniform_int_distribution<int> extra_dist(0, sizeof(extras) - 2);
    for (int i = 0; i < 6; i++) {
        result.counter_seeds.push_back(inner + extras[extra_dist(rng)]);
    }
    
    result.proof = "EDGE_CASE: NESTED_QUANTIFIER\n";
    result.proof += "  Pattern: ((" + inner + ")+)*\n";
    result.proof += "  Matching: ";
    for (auto& s : result.matching_seeds) result.proof += s + " ";
    result.proof += "\n  Counters: ";
    for (auto& s : result.counter_seeds) result.proof += s + " ";
    result.proof += "\n  Rationale: Tests nested quantifiers - inner + should match, partial should fail\n";
    
    return result;
}

// Main edge case dispatcher
EdgeCaseResult generateEdgeCase(EdgeCaseType type, std::mt19937& rng) {
    switch (type) {
        case EdgeCaseType::RANGE_BOUNDARY:
            return createRangeBoundaryEdge(rng);
        case EdgeCaseType::PARTIAL_MATCH_FAIL:
            return createPartialMatchEdge(rng);
        case EdgeCaseType::QUANTIFIER_EDGE:
            return createQuantifierEdge(rng);
        case EdgeCaseType::ALTERNATION_EDGE:
            return createAlternationEdge(rng);
        case EdgeCaseType::NESTED_QUANTIFIER:
            return createNestedQuantifierEdge(rng);
        default:
            return createPartialMatchEdge(rng);
    }
}

// Escape regex special characters in literal values
std::string escapeRegexSpecial(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '(':
            case ')':
            case '|':
            case '*':
            case '+':
            case '?':
            case '{':
            case '}':
            case '[':
            case ']':
            case '^':
            case '$':
            case '.':
            case '\\':
                result += '\\';
                result += c;
                break;
            default:
                result += c;
        }
    }
    return result;
}

// Conservative pattern matching check - returns true only if input clearly matches
// the pattern structure. Used to filter matching_inputs after factorization.
bool wouldInputMatchPattern(const std::string& input, const std::string& pattern) {
    // Extract just the pattern part (after category tag if present)
    std::string pattern_only = pattern;
    size_t bracket_end = pattern.find("] ");
    if (bracket_end != std::string::npos) {
        pattern_only = pattern.substr(bracket_end + 2);
    }
    
    // Remove capture tags from pattern_only
    std::string clean_pattern;
    size_t i = 0;
    while (i < pattern_only.size()) {
        if (pattern_only[i] == '<') {
            size_t tag_end = pattern_only.find('>', i);
            if (tag_end != std::string::npos) {
                if (i + 1 < pattern_only.size() && pattern_only[i + 1] == '/') {
                    i = tag_end + 1;
                } else {
                    std::string tag_name = pattern_only.substr(i + 1, tag_end - i - 1);
                    size_t close_tag = pattern_only.find("</" + tag_name + ">", tag_end);
                    if (close_tag != std::string::npos) {
                        clean_pattern += pattern_only.substr(tag_end + 1, close_tag - tag_end - 1);
                        i = close_tag + tag_name.size() + 3;
                    } else {
                        i = tag_end + 1;
                    }
                }
            } else {
                clean_pattern += pattern_only[i++];
            }
        } else {
            clean_pattern += pattern_only[i++];
        }
    }
    
    // For simple patterns (no alternations), do direct comparison
    if (clean_pattern.find('(') == std::string::npos && 
        clean_pattern.find('|') == std::string::npos) {
        return input == clean_pattern;
    }
    
    // For patterns with alternations, we need to be careful
    // Check if input could match any top-level alternative
    
    // Extract top-level alternatives (not nested)
    // Handle the case where pattern is wrapped in outer parens: (a|b|c)
    std::string pattern_to_parse = clean_pattern;
    
    // If pattern starts with ( and ends with matching ), remove outer parens
    if (!pattern_to_parse.empty() && pattern_to_parse.front() == '(') {
        size_t end = pattern_to_parse.size() - 1;
        int depth = 1;
        size_t i = 1;
        while (i < end && depth > 0) {
            if (pattern_to_parse[i] == '(') depth++;
            else if (pattern_to_parse[i] == ')') depth--;
            i++;
        }
        // If we found matching closing paren at the end, strip outer parens
        if (depth == 0 && i - 1 == end) {
            pattern_to_parse = pattern_to_parse.substr(1, end - 1);
        }
    }
    
    std::vector<std::string> top_alts;
    size_t start = 0;
    int depth = 0;
    for (size_t j = 0; j < pattern_to_parse.size(); j++) {
        if (pattern_to_parse[j] == '(') depth++;
        else if (pattern_to_parse[j] == ')') depth--;
        else if (pattern_to_parse[j] == '|' && depth == 0) {
            top_alts.push_back(pattern_to_parse.substr(start, j - start));
            start = j + 1;
        }
    }
    top_alts.push_back(pattern_to_parse.substr(start));
    
    // Check each top-level alternative
    for (const auto& alt : top_alts) {
        // Remove surrounding parentheses if present
        std::string clean_alt = alt;
        if (clean_alt.size() >= 2 && clean_alt.front() == '(' && clean_alt.back() == ')') {
            clean_alt = clean_alt.substr(1, clean_alt.size() - 2);
        }
        
        // If alternative has no nested structure, do direct comparison
        if (clean_alt.find('|') == std::string::npos && 
            clean_alt.find('(') == std::string::npos) {
            if (input == clean_alt) return true;
            continue;
        }
        
        // Alternative has nested structure - check if it has a simple prefix+suffix pattern
        // Pattern: prefix + (alt1|alt2|...)
        size_t paren_pos = clean_alt.find('(');
        if (paren_pos != std::string::npos) {
            std::string prefix = clean_alt.substr(0, paren_pos);
            
            // Find matching closing paren (handle nesting)
            size_t close = paren_pos + 1;
            int depth = 1;
            while (close < clean_alt.size() && depth > 0) {
                if (clean_alt[close] == '(') depth++;
                else if (clean_alt[close] == ')') depth--;
                close++;
            }
            close--; // Now points to the matching ')'
            
            if (close > paren_pos) {
                std::string nested = clean_alt.substr(paren_pos + 1, close - paren_pos - 1);
                
                // Check for quantifiers after the closing paren
                char quant = '\0';
                size_t after_close = close + 1;
                if (after_close < clean_alt.size()) {
                    quant = clean_alt[after_close];
                }
                
                // If input starts with prefix, check remainder against nested alternatives
                if (input.size() >= prefix.size() && 
                    input.substr(0, prefix.size()) == prefix) {
                    std::string remainder = input.substr(prefix.size());
                    
                    // Split nested by | at depth 0 (respecting nested parens)
                    std::vector<std::string> nested_alts;
                    size_t ns = 0;
                    int nested_depth = 0;
                    for (size_t i = 0; i < nested.size(); i++) {
                        if (nested[i] == '(') nested_depth++;
                        else if (nested[i] == ')') nested_depth--;
                        else if (nested[i] == '|' && nested_depth == 0) {
                            nested_alts.push_back(nested.substr(ns, i - ns));
                            ns = i + 1;
                        }
                    }
                    nested_alts.push_back(nested.substr(ns));
                    
                    // Check if remainder matches any nested alternative
                    for (const auto& na : nested_alts) {
                        std::string clean_na = na;
                        // Remove surrounding parens from nested alt if present
                        if (clean_na.size() >= 2 && clean_na.front() == '(' && clean_na.back() == ')') {
                            clean_na = clean_na.substr(1, clean_na.size() - 2);
                        }
                        
                        // Check for quantifiers at the end
                        if (!clean_na.empty() && clean_na.back() == '?') {
                            // Optional: X? matches empty or X
                            std::string base = clean_na.substr(0, clean_na.size() - 1);
                            if (remainder == base || remainder.empty()) return true;
                        } else if (!clean_na.empty() && clean_na.back() == '*') {
                            // Star: X* matches empty, X, XX, XXX, etc.
                            std::string base = clean_na.substr(0, clean_na.size() - 1);
                            if (base.empty()) continue;
                            bool valid = true;
                            size_t pos = 0;
                            while (pos < remainder.size()) {
                                if (remainder.substr(pos, base.size()) == base) {
                                    pos += base.size();
                                } else {
                                    valid = false;
                                    break;
                                }
                            }
                            if (valid) return true;
                        } else if (!clean_na.empty() && clean_na.back() == '+') {
                            // Plus: X+ matches X, XX, XXX, etc. (at least one)
                            std::string base = clean_na.substr(0, clean_na.size() - 1);
                            if (base.empty()) continue;
                            bool valid = true;
                            size_t pos = 0;
                            while (pos < remainder.size()) {
                                if (remainder.substr(pos, base.size()) == base) {
                                    pos += base.size();
                                } else {
                                    valid = false;
                                    break;
                                }
                            }
                            if (valid && pos > 0) return true;
                        } else if (remainder == clean_na) {
                            return true;
                        }
                    }
                    
                    // Check if the group itself is optional and remainder is empty
                    if (quant == '?' && remainder.empty()) return true;
                }
            }
        }
    }
    
    // If we get here, the input doesn't match any alternative we could parse
    return false;
}

// Serialize PatternNode to string with capture tags
std::string serializePattern(std::shared_ptr<PatternNode> node) {
    if (!node) return "";
    
    std::string capture_prefix = node->capture_tag.empty() ? "" : "<" + node->capture_tag + ">";
    std::string capture_suffix = node->capture_tag.empty() ? "" : "</" + node->capture_tag + ">";
    std::string begin_only = node->capture_begin_only.empty() ? "" : "<" + node->capture_begin_only + ">";
    std::string end_only = node->capture_end_only.empty() ? "" : "</" + node->capture_end_only + ">";
    
    switch (node->type) {
        case PatternType::LITERAL:
            if (!node->fragment_name.empty()) {
                return begin_only + capture_prefix + "((" + node->fragment_name + "))+" + capture_suffix + end_only;
            }
            return begin_only + capture_prefix + escapeRegexSpecial(node->value) + capture_suffix + end_only;
            
        case PatternType::OPTIONAL:
            if (node->quantified) {
                return "(" + serializePattern(node->quantified) + ")?";
            }
            return "(.)?";
            
        case PatternType::PLUS_QUANTIFIER:
            if (node->quantified) {
                return begin_only + capture_prefix + "(" + serializePattern(node->quantified) + ")+" + capture_suffix + end_only;
            }
            return "(.)+";
            
        case PatternType::STAR_QUANTIFIER:
            if (node->quantified) {
                return begin_only + capture_prefix + "(" + serializePattern(node->quantified) + ")*" + capture_suffix + end_only;
            }
            return "(.)*";
            
        case PatternType::ALTERNATION: {
            // If there's a quantifier set on an ALTERNATION node, handle it
            if (node->quantified) {
                // Serialize the quantified content
                std::string inner = "(";
                for (size_t i = 0; i < node->children.size(); i++) {
                    if (i > 0) inner += "|";
                    inner += serializePattern(node->children[i]);
                }
                inner += ")";
                
                // Determine quantifier from the original node's type field
                // Note: The type might have been changed to quantifier type, so check that too
                PatternType actual_type = node->type;
                
                if (actual_type == PatternType::PLUS_QUANTIFIER) {
                    return begin_only + capture_prefix + inner + "+" + capture_suffix + end_only;
                } else if (actual_type == PatternType::STAR_QUANTIFIER) {
                    return begin_only + capture_prefix + inner + "*" + capture_suffix + end_only;
                } else if (actual_type == PatternType::OPTIONAL) {
                    return begin_only + capture_prefix + inner + "?" + capture_suffix + end_only;
                }
                // Fall through to normal alternation
            }
            
            // Normal alternation serialization (no quantifier)
            std::string result = "(";
            for (size_t i = 0; i < node->children.size(); i++) {
                if (i > 0) result += "|";
                result += serializePattern(node->children[i]);
            }
            result += ")";
            return result;
        }
        
        case PatternType::SEQUENCE: {
            std::string result;
            for (const auto& child : node->children) {
                result += serializePattern(child);
            }
            return result;
        }
        
        case PatternType::FRAGMENT_REF:
            return "((" + node->fragment_name + "))+";
            
        default:
            return node->value;
    }
}

// Parse pattern string to AST (simple parser for basic patterns)
std::shared_ptr<PatternNode> parsePatternToAST(const std::string& pattern) {
    if (pattern.empty()) return nullptr;
    
    // Handle alternation with quantifier: (a|b|c)+
    // The quantifier is AFTER the closing paren, not inside
    if (pattern.size() >= 3 && pattern[0] == '(') {
        size_t close_paren = pattern.find(')');
        if (close_paren != std::string::npos) {
            std::string inner = pattern.substr(1, close_paren - 1);
            std::vector<std::shared_ptr<PatternNode>> alts;
            
            // Check if inner contains |
            if (inner.find('|') != std::string::npos) {
                size_t start = 0;
                for (size_t i = 0; i <= inner.size(); i++) {
                    if (i == inner.size() || inner[i] == '|') {
                        std::string alt = inner.substr(start, i - start);
                        if (!alt.empty()) {
                            alts.push_back(PatternNode::createLiteral(alt, {}));
                        }
                        start = i + 1;
                    }
                }
                
                if (alts.size() >= 2) {
                    // Check what comes after the closing paren
                    std::string after = pattern.substr(close_paren + 1);
                    std::shared_ptr<PatternNode> alt_node = PatternNode::createAlternation(alts, {});
                    
                    if (after == "+") {
                        alt_node->type = PatternType::PLUS_QUANTIFIER;
                        alt_node->quantified = PatternNode::createAlternation(alts, {});
                    } else if (after == "*") {
                        alt_node->type = PatternType::STAR_QUANTIFIER;
                        alt_node->quantified = PatternNode::createAlternation(alts, {});
                    } else if (after == "?") {
                        alt_node->type = PatternType::OPTIONAL;
                        alt_node->quantified = PatternNode::createAlternation(alts, {});
                    }
                    // If nothing after, it's just a grouped alternation, return as-is
                    return alt_node;
                }
            }
        }
    }
    
    // Handle simple pattern without alternation: (xxx)+
    if (pattern.size() >= 4 && pattern[0] == '(') {
        size_t close_paren = pattern.find(')');
        if (close_paren != std::string::npos) {
            std::string inner = pattern.substr(1, close_paren - 1);
            std::string after = pattern.substr(close_paren + 1);
            
            // No alternation, just a literal with quantifier
            if (!inner.empty() && (after == "+" || after == "*" || after == "?")) {
                std::shared_ptr<PatternNode> node = PatternNode::createLiteral(inner, {});
                if (after == "+") {
                    node->type = PatternType::PLUS_QUANTIFIER;
                    node->quantified = PatternNode::createLiteral(inner, {});
                } else if (after == "*") {
                    node->type = PatternType::STAR_QUANTIFIER;
                    node->quantified = PatternNode::createLiteral(inner, {});
                } else if (after == "?") {
                    node->type = PatternType::OPTIONAL;
                    node->quantified = PatternNode::createLiteral(inner, {});
                }
                return node;
            }
        }
    }
    
    // Simple literal
    return PatternNode::createLiteral(pattern, {});
}

// Add capture tags to AST nodes
void addCaptureTags(std::shared_ptr<PatternNode> node, std::mt19937& rng) {
    if (!node) return;
    
    std::vector<std::string> all_seeds = node->matched_seeds;
    
    std::function<void(std::shared_ptr<PatternNode>)> collect = [&](std::shared_ptr<PatternNode> n) {
        if (!n) return;
        for (const auto& s : n->matched_seeds) {
            all_seeds.push_back(s);
        }
        if (n->quantified) collect(n->quantified);
        for (const auto& c : n->children) collect(c);
    };
    collect(node);
    
    std::sort(all_seeds.begin(), all_seeds.end());
    all_seeds.erase(std::unique(all_seeds.begin(), all_seeds.end()), all_seeds.end());
    
    if (all_seeds.empty()) return;
    
    // Strategy 1: Capture entire alternation
    if (node->type == PatternType::ALTERNATION && node->children.size() >= 2) {
        bool all_single = true;
        for (const auto& child : node->children) {
            if (child->matched_seeds.size() != 1) {
                all_single = false; break;
            }
        }
        if (all_single) {
            node->capture_tag = "c" + std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
            return;
        }
    }
    
    // Strategy 2: Capture entire quantified node
    if ((node->type == PatternType::PLUS_QUANTIFIER || 
         node->type == PatternType::STAR_QUANTIFIER ||
         node->type == PatternType::OPTIONAL) && 
        node->quantified && 
        !node->quantified->matched_seeds.empty()) {
        node->capture_tag = "c" + std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
        return;
    }
    
    // Recurse
    for (auto& child : node->children) {
        addCaptureTags(child, rng);
    }
    if (node->quantified) {
        addCaptureTags(node->quantified, rng);
    }
}

// Collect all seeds from captured nodes
std::vector<std::string> collectCaptureSeeds(std::shared_ptr<PatternNode> node) {
    std::vector<std::string> seeds;
    if (!node) return seeds;
    
    if (!node->capture_tag.empty()) {
        seeds.insert(seeds.end(), node->matched_seeds.begin(), node->matched_seeds.end());
    }
    
    for (const auto& c : node->children) {
        auto child_seeds = collectCaptureSeeds(c);
        seeds.insert(seeds.end(), child_seeds.begin(), child_seeds.end());
    }
    if (node->quantified) {
        auto quant_seeds = collectCaptureSeeds(node->quantified);
        seeds.insert(seeds.end(), quant_seeds.begin(), quant_seeds.end());
    }
    
    std::sort(seeds.begin(), seeds.end());
    seeds.erase(std::unique(seeds.begin(), seeds.end()), seeds.end());
    return seeds;
}

// ============================================================================
// Pattern Rewriting - Keeps matching set constant, complicates expression
// ============================================================================

void rewritePattern(std::shared_ptr<PatternNode> node, std::mt19937& rng) {
    if (!node) return;
    
    // Much lower probability to avoid creating invalid patterns
    std::uniform_int_distribution<int> apply_dist(0, 99);
    std::uniform_int_distribution<int> char_dist(0, 61);
    
    // Collect all seed values
    std::set<std::string> all_seeds;
    std::function<void(std::shared_ptr<PatternNode>)> collect = [&](std::shared_ptr<PatternNode> n) {
        if (!n) return;
        for (const auto& s : n->matched_seeds) {
            all_seeds.insert(s);
        }
        if (n->quantified) collect(n->quantified);
        for (const auto& c : n->children) collect(c);
    };
    collect(node);
    
    // Strategy 1: Reorder alternation alternatives (very rare)
    if (node->type == PatternType::ALTERNATION && node->children.size() > 1) {
        if (apply_dist(rng) < 2) {  // 2% chance
            std::shuffle(node->children.begin(), node->children.end(), rng);
        }
    }
    
    // Strategy 2: Add random non-matching alternatives (very rare)
    if (node->type == PatternType::ALTERNATION && !all_seeds.empty() && apply_dist(rng) < 2) {
        int num_new = 1;
        for (int i = 0; i < num_new; i++) {
            int len = std::uniform_int_distribution<int>(3, 6)(rng);
            static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            std::string new_alt;
            for (int j = 0; j < len; j++) {
                new_alt += charset[char_dist(rng)];
            }
            if (all_seeds.find(new_alt) == all_seeds.end()) {
                node->children.push_back(PatternNode::createLiteral(new_alt, {}));
            }
        }
    }
    
    // Strategy 3: Add empty alternative (ε) - makes pattern optional
    // Creates: (a|b|"") which means (a|b)? - matches empty OR a OR b
    if (node->type == PatternType::ALTERNATION && !all_seeds.empty() && apply_dist(rng) < 3) {
        bool has_empty = false;
        for (const auto& child : node->children) {
            if (child->type == PatternType::LITERAL && child->value.empty()) {
                has_empty = true; break;
            }
        }
        if (!has_empty) {
            // Add empty literal with empty seed (meaning "matches empty")
            auto empty_lit = PatternNode::createLiteral("", {}, {});
            empty_lit->matched_seeds = {};  // Empty matches empty
            node->children.push_back(empty_lit);
            // Note: matched_seeds will be updated by parent to track which inputs match
        }
    }
    
    // Strategy 4: Duplicate alternatives (very rare)
    if (node->type == PatternType::ALTERNATION && node->children.size() >= 2 && apply_dist(rng) < 2) {
        size_t idx = std::uniform_int_distribution<int>(0, node->children.size() - 1)(rng);
        auto& child = node->children[idx];
        if (child->type == PatternType::LITERAL && !child->value.empty() && child->fragment_name.empty()) {
            node->children.push_back(PatternNode::createLiteral(child->value, {}));
        }
    }
    
    // Strategy 5: Wrap literal in parens - DISABLED (causes nesting issues)
    // if (node->type == PatternType::LITERAL && !node->value.empty() && node->fragment_name.empty()) {
    //     if (apply_dist(rng) == 0) {
    //         node->type = PatternType::ALTERNATION;
    //         node->children.push_back(PatternNode::createLiteral(node->value, node->matched_seeds));
    //         node->value.clear();
    //     }
    // }
    
    // Strategy 6: Unmatched capture begin tag - DISABLED (creates invalid patterns)
    // if (node->capture_tag.empty() && node->capture_begin_only.empty() && node->capture_end_only.empty()) {
    //     if (apply_dist(rng) == 0 && std::uniform_int_distribution<int>(0, 9)(rng) == 0) {
    //         node->capture_begin_only = "u" + std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
    //     }
    // }
    
    // Strategy 7: Unmatched capture end tag - DISABLED (creates invalid patterns)
    // if (node->capture_tag.empty() && node->capture_begin_only.empty() && node->capture_end_only.empty()) {
    //     if (apply_dist(rng) == 0 && std::uniform_int_distribution<int>(0, 9)(rng) == 0) {
    //         node->capture_end_only = "u" + std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
    //     }
    // }
    
    // Strategy 8: Quantifier manipulation - DISABLED (changes matching semantics)
    // if (node->quantified) {
    //     if (apply_dist(rng) == 0) {
    //         ...
    //     }
    // }
    
    // Strategy 9: Case variation - DISABLED (changes matching semantics)
    // if (node->type == PatternType::LITERAL && !node->value.empty() && node->fragment_name.empty()) {
    //     ...
    // }
    
    // Strategy 10: Character class conversion - DISABLED (changes matching semantics)
    // if (node->type == PatternType::LITERAL && node->value.size() == 1 && node->fragment_name.empty()) {
    //     ...
    // }
    
    // Strategy 11: Split literal into prefix alternation - DISABLED (changes matching semantics)
    // if (node->type == PatternType::LITERAL && node->value.size() >= 3 && node->fragment_name.empty()) {
    //     ...
    // }
    
    // Strategy 12: Interleave wildcard between characters - DISABLED (changes matching semantics)
    // if (node->type == PatternType::LITERAL && node->value.size() >= 2 && node->fragment_name.empty()) {
    //     ...
    // }
    
    // Strategy 13: Wrap in nested capture group - DISABLED (creates invalid patterns)
    // if (node->type == PatternType::LITERAL && !node->value.empty() && node->capture_tag.empty() && node->fragment_name.empty()) {
    //     if (apply_dist(rng) < 3) {  // 3% chance
    //         node->capture_tag = "c" + std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
    //     }
    // }
    
    // Strategy 14: Add optional suffix - DISABLED (changes matching semantics)
    // if (node->type == PatternType::LITERAL && !node->value.empty() && node->fragment_name.empty()) {
    //     ...
    // }
    
    // Recurse
    if (node->quantified) {
        rewritePattern(node->quantified, rng);
    }
    for (auto& child : node->children) {
        rewritePattern(child, rng);
    }
}

// ============================================================================
// Pattern Building Blocks (elementary units of c-dfa patterns)
// ============================================================================

struct PatternComponent {
    PatternType type;
    std::string value;           // For literals
    std::string fragment_name;   // For fragments
    std::vector<std::string> alternatives;  // For alternation
};

// ============================================================================
// TestGenerator Implementation
// ============================================================================

TestGenerator::TestGenerator(const Options& opts) : opts(opts) {
    rng.seed(opts.seed);
}

std::vector<TestCase> TestGenerator::generate() {
    std::vector<TestCase> tests;
    // For combined testing, max 4 test cases (8 patterns: 4 matching + 4 counter)
    int max_tests = std::min(opts.num_tests, 4);
    tests.reserve(max_tests);
    
    // Track all inputs used so far to avoid collisions between test cases
    std::set<std::string> all_used_inputs;
    
    for (int i = 0; i < max_tests; i++) {
        tests.push_back(generateTestCase(i, all_used_inputs));
        // Add this test case's inputs to the global set
        for (const auto& inp : tests.back().matching_inputs) {
            all_used_inputs.insert(inp);
        }
        for (const auto& inp : tests.back().counter_inputs) {
            all_used_inputs.insert(inp);
        }
    }
    generated_tests = tests;
    return tests;
}

// Generate random seed strings for a test case
std::pair<std::vector<std::string>, std::vector<std::string>> 
TestGenerator::generateSeeds(Complexity complexity, std::set<std::string>& used_inputs) {
    // Only use safe characters that don't need escaping in regex patterns
    const std::string lowercase = "abcdefghijklmnopqrstuvwxyz";
    const std::string uppercase = "ABCDEFGHIJKLMQRSTUVWXYZ";
    const std::string digits = "0123456789";
    const std::string alphanum = lowercase + uppercase + digits;
    
    std::vector<std::string> matching_seeds;
    std::vector<std::string> counter_seeds;
    std::set<std::string> used = used_inputs;
    
    // Generate correlation-based seeds with structure
    // Auto-correlation: 5 elements, each randomly initialized to [0.02, 0.34]
    // Cross-correlation: controls how much inputs influence each other
    std::vector<double> autocorr(5);
    for (int i = 0; i < 5; i++) {
        autocorr[i] = 0.02 + std::uniform_real_distribution<double>(0.0, 0.32)(rng);
    }
    double crosscorr = 0.3;
    
    // Determine base parameters from complexity
    int num_matching = 5;
    int num_counters = 25;
    int min_len, max_len;
    
    if (complexity == Complexity::SIMPLE) {
        min_len = 3;
        max_len = 6;
    } else if (complexity == Complexity::MEDIUM) {
        min_len = 4;
        max_len = 10;
    } else {
        min_len = 6;
        max_len = 16;
    }
    
    // Generate base pattern: a repeating unit that will be mutated
    // This creates correlation within and between strings
    std::string base_unit;
    int unit_len = 2 + std::uniform_int_distribution<int>(0, 2)(rng);
    for (int i = 0; i < unit_len; i++) {
        base_unit += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
    }
    
    // Generate matching seeds with correlation
    std::vector<std::string> base_matching;
    for (int i = 0; i < num_matching; i++) {
        // Length varies around base unit length
        int target_len = min_len + std::uniform_int_distribution<int>(0, max_len - min_len)(rng);
        
        // Determine how to build this string:
        // 0 = pure random, 1 = repeat base_unit, 2 = repeat prefix, 3 = prefix + repeat
        int build_type = std::uniform_int_distribution<int>(0, 3)(rng);
        
        std::string s;
        if (build_type == 0) {
            // Pure random (add some entropy)
            for (int j = 0; j < target_len; j++) {
                s += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
            }
        } else if (build_type == 1) {
            // Repeat base unit
            while ((int)s.size() < target_len) {
                s += base_unit;
            }
            s = s.substr(0, target_len);
        } else if (build_type == 2) {
            // Repeat a prefix of base_unit
            std::string prefix = base_unit.substr(0, 1 + std::uniform_int_distribution<int>(0, base_unit.size()-1)(rng));
            while ((int)s.size() < target_len) {
                s += prefix;
            }
            s = s.substr(0, target_len);
        } else {
            // Prefix + variation: start with some chars from base, then vary
            int prefix_len = std::uniform_int_distribution<int>(1, std::min(3, target_len-1))(rng);
            s = base_unit.substr(0, prefix_len);
            // Add correlated continuation using 5-element autocorrelation vector
            while ((int)s.size() < target_len) {
                double r = std::uniform_real_distribution<double>(0.0, 1.0)(rng);
                bool used_autocorr = false;
                
                // Check each autocorrelation element
                double cumulative = 0.0;
                for (int i = 0; i < (int)autocorr.size() && i + 1 < (int)s.size(); i++) {
                    cumulative += autocorr[i];
                    if (r < cumulative) {
                        // Repeat the character at position (i+1) back from end
                        s += s[s.size() - (i + 1)];
                        used_autocorr = true;
                        break;
                    }
                }
                
                if (!used_autocorr) {
                    // Random char
                    s += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
                }
            }
        }
        
        if (used.insert(s).second) {
            matching_seeds.push_back(s);
            base_matching.push_back(s);
        }
    }
    
    // Ensure we have enough matching seeds
    while ((int)matching_seeds.size() < num_matching) {
        std::string s;
        int len = min_len + std::uniform_int_distribution<int>(0, max_len - min_len)(rng);
        
        // Use cross-correlation: build from existing matching seeds
        if (!base_matching.empty() && std::uniform_real_distribution<double>(0.0, 1.0)(rng) < crosscorr) {
            // Take a prefix from one matching seed and suffix from another
            const std::string& src1 = base_matching[std::uniform_int_distribution<int>(0, base_matching.size()-1)(rng)];
            const std::string& src2 = base_matching[std::uniform_int_distribution<int>(0, base_matching.size()-1)(rng)];
            int split = std::uniform_int_distribution<int>(1, std::min((int)src1.size()-1, len-1))(rng);
            s = src1.substr(0, split) + src2.substr(0, std::min((int)src2.size(), len - split));
        } else {
            // Random
            for (int j = 0; j < len; j++) {
                s += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
            }
        }
        
        if (used.insert(s).second) {
            matching_seeds.push_back(s);
            base_matching.push_back(s);
        }
    }
    
    // Generate counter seeds that are different from matching
    // They should NOT follow the same patterns
    while ((int)counter_seeds.size() < num_counters) {
        std::string s;
        int len = min_len + std::uniform_int_distribution<int>(0, max_len - min_len)(rng);
        
        // For counters, use completely different approach:
        // Use a different character set or reverse patterns
        int counter_type = std::uniform_int_distribution<int>(0, 2)(rng);
        
        if (counter_type == 0) {
            // Different character set (e.g., only lowercase when matching uses mixed)
            std::string diff_chars = lowercase;
            for (int j = 0; j < len; j++) {
                s += diff_chars[std::uniform_int_distribution<int>(0, diff_chars.size()-1)(rng)];
            }
        } else if (counter_type == 1) {
            // Reverse or modify a matching seed to create near-miss
            if (!matching_seeds.empty()) {
                const std::string& src = matching_seeds[std::uniform_int_distribution<int>(0, matching_seeds.size()-1)(rng)];
                if (!src.empty()) {
                    // Take a different length
                    len = std::uniform_int_distribution<int>(1, (int)src.size())(rng);
                    s = src.substr(0, len);
                    // Change one character
                    if (!s.empty() && len > 1) {
                        int pos = std::uniform_int_distribution<int>(0, len-1)(rng);
                        char replacement = alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
                        while (replacement == s[pos]) {
                            replacement = alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
                        }
                        s[pos] = replacement;
                    }
                }
            } else {
                for (int j = 0; j < len; j++) {
                    s += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
                }
            }
        } else {
            // Pure random (high entropy - opposite of matching)
            for (int j = 0; j < len; j++) {
                s += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
            }
        }
        
        // Must be different from all matching and existing counters
        if (used.find(s) == used.end()) {
            bool invalid = false;
            for (const auto& m : matching_seeds) {
                // Reject if too similar to a matching seed
                if (s.size() == m.size()) {
                    int diff = 0;
                    for (size_t k = 0; k < s.size(); k++) {
                        if (s[k] != m[k]) diff++;
                    }
                    if (diff <= 1) {  // Too similar
                        invalid = true;
                        break;
                    }
                }
                // Reject if one is a prefix of another
                if (s.find(m) == 0 || m.find(s) == 0) {
                    invalid = true;
                    break;
                }
            }
            if (!invalid) {
                used.insert(s);
                counter_seeds.push_back(s);
            }
        }
    }
    
    return {matching_seeds, counter_seeds};
}

struct SeedAnalysis {
    bool all_same_length;
    bool all_same_prefix;
    std::string common_prefix;
    std::string common_suffix;
    std::set<char> all_chars;
    std::map<int, std::set<char>> chars_at_pos;
};

SeedAnalysis analyzeSeeds(const std::vector<std::string>& matching, 
                          const std::vector<std::string>& counters) {
    SeedAnalysis analysis;
    analysis.all_same_length = true;
    
    if (matching.empty()) return analysis;
    
    size_t first_len = matching[0].size();
    for (const auto& s : matching) {
        if (s.size() != first_len) {
            analysis.all_same_length = false;
            break;
        }
    }
    
    if (!matching.empty()) {
        analysis.common_prefix = matching[0];
        for (const auto& s : matching) {
            std::string new_prefix;
            for (size_t i = 0; i < s.size() && i < analysis.common_prefix.size(); i++) {
                if (s[i] == analysis.common_prefix[i]) {
                    new_prefix += s[i];
                } else {
                    break;
                }
            }
            analysis.common_prefix = new_prefix;
        }
    }
    
    if (!matching.empty()) {
        analysis.common_suffix = matching[0];
        for (const auto& s : matching) {
            std::string new_suffix;
            size_t min_len = std::min(s.size(), analysis.common_suffix.size());
            for (size_t i = 0; i < min_len; i++) {
                if (s[s.size() - 1 - i] == analysis.common_suffix[analysis.common_suffix.size() - 1 - i]) {
                    new_suffix = s[s.size() - 1 - i] + new_suffix;
                } else {
                    break;
                }
            }
            analysis.common_suffix = new_suffix;
        }
    }
    
    for (const auto& s : matching) {
        for (char c : s) {
            analysis.all_chars.insert(c);
        }
    }
    for (const auto& s : counters) {
        for (char c : s) {
            analysis.all_chars.insert(c);
        }
    }
    
    size_t max_len = 0;
    for (const auto& s : matching) max_len = std::max(max_len, s.size());
    for (const auto& s : counters) max_len = std::max(max_len, s.size());
    
    for (size_t pos = 0; pos < max_len; pos++) {
        std::set<char> chars_at_this_pos;
        for (const auto& s : matching) {
            if (pos < s.size()) chars_at_this_pos.insert(s[pos]);
        }
        for (const auto& s : counters) {
            if (pos < s.size()) chars_at_this_pos.insert(s[pos]);
        }
        analysis.chars_at_pos[pos] = chars_at_this_pos;
    }
    
    return analysis;
}

bool literalMatches(const std::string& pattern, const std::string& str) {
    return pattern == str;
}

bool alternationMatches(const std::vector<std::string>& alts, const std::string& str) {
    for (const auto& alt : alts) {
        if (alt == str) return true;
    }
    return false;
}

bool charClassPlusMatches(const std::string& char_class, const std::string& str) {
    std::set<char> allowed;
    std::string current;
    for (char c : char_class) {
        if (c == '|') {
            if (current.size() == 1) allowed.insert(current[0]);
            current.clear();
        } else {
            current += c;
        }
    }
    if (current.size() == 1) allowed.insert(current[0]);
    
    for (char c : str) {
        if (allowed.find(c) == allowed.end()) return false;
    }
    return !str.empty();
}

// ============================================================================
// ============================================================================
// InductiveBuilder - Constraint-Propagating Pattern AST Construction
// ============================================================================
// At each step, we track:
//   already matched part , remaining to match
//   For matching input: aas, ttt
//   For counter-input:  aaa, geeew
// We add to pattern something that matches SOME of 'ttt' but NOT all of 'geeew'.
// The pattern matches part of ttt while matching as little as possible of constraints.
// Division strategy:
//   Input:    asfalkjsfha
//   Counter:  asdggeeeeha
//   Split into subproblems:
//     1: asf (input), asdgge (counter) - with extra constraint
//     2: alkjsfha (input), eeeha (counter)
//   The extra constraint on subproblem 1 ensures that we can concatenate the patterns

// Forward declaration for PatternFactorization namespace
namespace PatternFactorization {
    std::shared_ptr<PatternNode> applyFactorization(
        std::shared_ptr<PatternNode> root, 
        std::mt19937& rng,
        FactorizationProof* proof_out = nullptr);
    std::shared_ptr<PatternNode> applyRandomStars(std::shared_ptr<PatternNode> root, std::mt19937& rng);
    std::pair<std::shared_ptr<PatternNode>, std::map<std::string, std::string>> applyComplexRewrites(
        std::shared_ptr<PatternNode> root, std::mt19937& rng, std::string& proof_out);
    std::shared_ptr<PatternNode> copyPatternNode(std::shared_ptr<PatternNode> node);
    std::string detectStarInsertions(
        std::shared_ptr<PatternNode> before,
        std::shared_ptr<PatternNode> after,
        const std::string& context);
    
    // Internal factorization with proof generation
    std::shared_ptr<PatternNode> factorPattern(
        std::shared_ptr<PatternNode> node, 
        int depth,
        FactorizationProof* proof_out = nullptr);
}


// ============================================================================
// Constraint Subdivision - Distribute counter-inputs among child nodes
// For a sequence A+B+C, we can subdivide counter constraints:
// - A (prefix): Cannot match patterns ending with distinguishing char
// - B (middle): Cannot match that char directly
// - C (suffix): Cannot match patterns starting with that char
// This allows more flexible patterns while preserving overall guarantees
// ============================================================================

// Pick a distinguishing character from a counter-input
// Returns a char that appears in at least one counter but not in matching inputs at that position
char pickDistinguishingChar(const std::vector<std::string>& counter_seeds,
                            const std::vector<std::string>& matching_seeds,
                            int position,
                            std::mt19937& rng) {
    std::uniform_int_distribution<int> dist(0, 99);
    
    // Try to find a char in counters that differs from matching inputs
    for (const auto& counter : counter_seeds) {
        if (position < (int)counter.length()) {
            char c = counter[position];
            bool differs = true;
            for (const auto& match : matching_seeds) {
                if (position < (int)match.length() && match[position] == c) {
                    differs = false;
                    break;
                }
            }
            if (differs) return c;
        }
    }
    
    // Fallback: just pick a char from a random counter at that position
    if (!counter_seeds.empty()) {
        const auto& counter = counter_seeds[dist(rng) % counter_seeds.size()];
        if (position < (int)counter.length()) {
            return counter[position];
        }
    }
    
    // Ultimate fallback: return 'X' as generic distinguisher
    return 'X';
}

// Subdivide counter constraints among sequence children
// Returns vector of counter sets for each child (prefix, middle, suffix)
std::vector<std::vector<std::string>> subdivideCounterConstraints(
    const std::vector<std::string>& all_counters,
    const std::vector<std::string>& matching_seeds,
    int num_children,
    std::mt19937& rng) {
    
    if (num_children <= 1 || all_counters.empty()) {
        return std::vector<std::vector<std::string>>(num_children, all_counters);
    }
    
    std::vector<std::vector<std::string>> subdivided(num_children);
    std::uniform_int_distribution<int> dist(0, 99);
    
    // For each counter, assign it to children based on position constraints
    for (const auto& counter : all_counters) {
        if (counter.empty()) continue;
        
        // Pick a distinguishing position in this counter
        int pos = dist(rng) % std::min((int)counter.length(), 3);  // First 3 chars
        char dist_char = counter[pos];
        
        // Assign to children based on position
        // First child: block counters ending with suffix after pos
        if (num_children >= 2) {
            // First child gets constraint about ending pattern
            subdivided[0].push_back(counter);
        }
        
        // Middle children: block the char at pos
        for (int i = 1; i < num_children - 1; i++) {
            subdivided[i].push_back(counter);
        }
        
        // Last child: block counters starting with prefix before pos  
        if (num_children >= 2) {
            subdivided[num_children - 1].push_back(counter);
        }
    }
    
    return subdivided;
}

// Apply constraint subdivision to a sequence node
void applyConstraintSubdivision(std::shared_ptr<PatternNode> seq_node,
                                std::mt19937& rng) {
    if (!seq_node || seq_node->type != PatternType::SEQUENCE) return;
    if (seq_node->children.size() < 2) return;
    if (seq_node->counter_seeds.empty()) return;
    
    // Subdivide counter constraints among children
    auto subdivided = subdivideCounterConstraints(
        seq_node->counter_seeds,
        seq_node->matched_seeds,
        seq_node->children.size(),
        rng
    );
    
    // Assign subdivided constraints to each child
    for (size_t i = 0; i < seq_node->children.size() && i < subdivided.size(); i++) {
        auto& child = seq_node->children[i];
        
        // Child inherits its portion of counter constraints
        child->counter_seeds = subdivided[i];
        
        // Also propagate matching seeds (all children must collectively match all inputs)
        child->matched_seeds = seq_node->matched_seeds;
    }
}

// ============================================================================
// PatternFactorization - Rewrite alternations to factor out common prefixes/suffixes
// ============================================================================
// Prefix Example: d(7q7q7q|ddd|7qq8q|7qxd7qxd|7qNN7N)
//   -> d(ddd|(7q7q7q|7qq8q|7qxd7qxd|7qNN7N))
//   -> d(ddd|7(q7q7q|qq8q|qxd7qxd|qNN7N))
//   -> d(ddd|7q(7q7q|q8q|xd7qxd|NN7N))
// Suffix Example: (abc7q|bbc7q|cbc7q)
//   -> ((abc|bbc|cbc)7q)
//   -> (((ab|bb|cb)bc)7q)
//   -> (((a|b|c)bc)7q)
// This recursively factors common prefixes AND suffixes outside alternations.
// (Namespace definition continues from forward declaration above)

namespace PatternFactorization {

// Find common prefix among a set of strings
std::string findCommonPrefix(const std::vector<std::string>& strings) {
    if (strings.empty()) return "";
    std::string prefix = strings[0];
    for (size_t i = 1; i < strings.size() && !prefix.empty(); i++) {
        size_t j = 0;
        while (j < strings[i].size() && j < prefix.size() && strings[i][j] == prefix[j]) {
            j++;
        }
        prefix = prefix.substr(0, j);
    }
    return prefix;
}

// Group alternatives by their prefix
std::map<std::string, std::vector<std::string>> groupByPrefix(
    const std::vector<std::string>& alternatives,
    size_t prefix_len) {
    std::map<std::string, std::vector<std::string>> groups;
    
    for (const auto& alt : alternatives) {
        std::string prefix = alt.substr(0, std::min(prefix_len, alt.size()));
        groups[prefix].push_back(alt);
    }
    
    return groups;
}

// Find common suffix among a set of strings
std::string findCommonSuffix(const std::vector<std::string>& strings) {
    if (strings.empty()) return "";
    
    // Reverse each string and find common prefix of reversed strings
    std::string suffix;
    size_t min_len = strings[0].size();
    for (const auto& s : strings) {
        min_len = std::min(min_len, s.size());
    }
    
    for (size_t i = 0; i < min_len; i++) {
        char c = strings[0][strings[0].size() - 1 - i];
        bool all_match = true;
        for (size_t j = 1; j < strings.size(); j++) {
            if (strings[j][strings[j].size() - 1 - i] != c) {
                all_match = false;
                break;
            }
        }
        if (all_match) {
            suffix = c + suffix;
        } else {
            break;
        }
    }
    return suffix;
}

// Group alternatives by their suffix (last N characters)
std::map<std::string, std::vector<std::string>> groupBySuffix(
    const std::vector<std::string>& alternatives,
    size_t suffix_len) {
    std::map<std::string, std::vector<std::string>> groups;
    
    for (const auto& alt : alternatives) {
        if (alt.size() >= suffix_len) {
            std::string suffix = alt.substr(alt.size() - suffix_len);
            groups[suffix].push_back(alt);
        } else {
            // Short strings go in their own group
            groups[alt].push_back(alt);
        }
    }
    
    return groups;
}

// Recursively factor an alternation node
// Returns the factored node (may be same as input if no factoring possible)
std::shared_ptr<PatternNode> factorAlternation(
    std::shared_ptr<PatternNode> node, 
    int depth,
    FactorizationProof* proof_out) {
    if (!node || depth > 10) return node;
    
    // Only process alternations
    if (node->type != PatternType::ALTERNATION || node->children.size() < 2) {
        return node;
    }
    
    // DEBUG: Check if this alternation contains wzwz
    bool has_wzwz = false;
    for (const auto& child : node->children) {
        if (child->type == PatternType::LITERAL && child->value == "wzwz") {
            has_wzwz = true;
            break;
        }
    }
    if (has_wzwz && proof_out) {
        proof_out->valid = false;  // Mark for debugging
    }
    
    // Get all literal alternatives
    std::vector<std::string> alternatives;
    for (const auto& child : node->children) {
        if (child->type == PatternType::LITERAL && !child->value.empty()) {
            alternatives.push_back(child->value);
        } else {
            // Mixed types - don't factor
            return node;
        }
    }
    
    // Find common prefix among all alternatives
    std::string common = findCommonPrefix(alternatives);
    
    if (common.empty()) {
        // No common prefix - try to group by first char
        auto groups = groupByPrefix(alternatives, 1);
        
        if (groups.size() == 1) {
            // All start with same char - shouldn't happen since common is empty
            return node;
        }
        
        if (groups.size() == alternatives.size()) {
            // Each alt has unique first char - no factoring possible
            return node;
        }
        
        // Some groups have multiple alternatives - create nested structure
        // We need to track which original seeds belong to each group
        std::vector<std::shared_ptr<PatternNode>> new_children;
        std::vector<std::string> new_seeds;
        
        // Collect all counter seeds once (all counters apply to all alternatives in alternation)
        std::vector<std::string> all_counter_seeds = node->counter_seeds;
        
        for (const auto& [prefix, group_alts] : groups) {
            // Find original seeds for alternatives in this group
            std::vector<std::string> group_seeds;
            for (const auto& alt : group_alts) {
                // Find the index of this alternative in the original list
                bool found = false;
                for (size_t i = 0; i < alternatives.size(); i++) {
                    if (alternatives[i] == alt) {
                        group_seeds.push_back(node->matched_seeds[i]);
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    // CRITICAL: Alternative not found in original list!
                    // This should never happen - indicates a bug
                    if (proof_out) {
                        proof_out->valid = false;
                    }
                }
            }
            
            // DEBUG: Check if we have matching seeds for all alternatives
            if (proof_out && group_seeds.size() != group_alts.size()) {
                proof_out->valid = false;  // Mismatch - some alternatives lost their seeds
            }
            
            // DEBUG: Check for specific case
            if (proof_out && prefix == "wz") {
                // Detailed debug for wz group
                std::string debug_info = "WZ_GROUP: alts=[";
                for (size_t i = 0; i < group_alts.size(); i++) {
                    if (i > 0) debug_info += ",";
                    debug_info += group_alts[i];
                }
                debug_info += "] seeds=[";
                for (size_t i = 0; i < group_seeds.size(); i++) {
                    if (i > 0) debug_info += ",";
                    debug_info += group_seeds[i];
                }
                debug_info += "]";
                proof_out->before = debug_info;
            }
            
            if (group_alts.size() == 1) {
                // Single alternative in group - keep as literal with ORIGINAL seeds
                auto lit = PatternNode::createLiteral(group_alts[0], group_seeds, all_counter_seeds);
                new_children.push_back(lit);
                new_seeds.insert(new_seeds.end(), group_seeds.begin(), group_seeds.end());
            } else {
                // DEBUG: Trace group processing for wz group
                if (proof_out && prefix == "wz") {
                    proof_out->valid = false;  // Mark for debugging
                    // Log detailed info about this group
                    // Add debug info to proof
                    if (proof_out->steps.empty()) {
                        proof_out->before = "GROUP_WZ_DEBUG:";
                    }
                }
                // Multiple alternatives share a prefix - create inner alternation with factored prefix
                // Structure: prefix + (remainder1 | remainder2 | ...)
                // CRITICAL: Check if any input equals the prefix exactly (would have empty remainder)
                // NEW: Handle empty remainders by creating optional structure
                // If an alternative equals the prefix exactly, its remainder is empty (ε)
                // This creates: prefix + (remainder|ε) which is equivalent to prefix + remainder?
                std::vector<std::shared_ptr<PatternNode>> inner_children;
                std::vector<std::string> inner_seeds;
                bool has_empty_remainder = false;
                
                for (size_t i = 0; i < group_alts.size(); i++) {
                    std::string rem = group_alts[i].substr(prefix.size());
                    if (rem.empty()) {
                        // This alternative IS the prefix - create ε (empty) literal
                        has_empty_remainder = true;
                        auto empty_lit = PatternNode::createLiteral("", {group_seeds[i]}, all_counter_seeds);
                        inner_children.push_back(empty_lit);
                        inner_seeds.push_back(group_seeds[i]);
                    } else {
                        auto lit = PatternNode::createLiteral(rem, {group_seeds[i]}, all_counter_seeds);
                        inner_children.push_back(lit);
                        inner_seeds.push_back(group_seeds[i]);
                    }
                }
                
                // VALIDATION: Check if remainders share common structure
                // If not, don't create nested pattern - keep as separate literals
                std::vector<std::string> remainders;
                for (size_t i = 0; i < group_alts.size(); i++) {
                    std::string rem = group_alts[i].substr(prefix.size());
                    if (!rem.empty()) {
                        remainders.push_back(rem);
                    }
                }
                
                std::string remainder_common = findCommonPrefix(remainders);
                bool remainders_compatible = !remainders.empty() && 
                    (remainders.size() == 1 || !remainder_common.empty());
                
                // Also check: all remainders must be valid (non-empty or explicitly empty)
                bool all_remainders_valid = (remainders.size() + (has_empty_remainder ? 1 : 0)) == group_alts.size();
                
                // DEBUG: Trace wz group specifically
                if (proof_out && prefix == "wz") {
                    std::string debug = "WZ_GROUP:[";
                    for (size_t i = 0; i < group_alts.size(); i++) {
                        if (i > 0) debug += ",";
                        debug += group_alts[i];
                    }
                    debug += "] seeds=[";
                    for (size_t i = 0; i < group_seeds.size(); i++) {
                        if (i > 0) debug += ",";
                        debug += group_seeds[i];
                    }
                    debug += "] remainders=[";
                    for (size_t i = 0; i < remainders.size(); i++) {
                        if (i > 0) debug += ",";
                        debug += remainders[i];
                    }
                    debug += "] common=" + remainder_common + " compatible=" + 
                             (remainders_compatible ? "true" : "false") + " valid=" +
                             (all_remainders_valid ? "true" : "false");
                    proof_out->before = debug;
                }
                
                if (!remainders_compatible || !all_remainders_valid) {
                    // Remainders don't share structure - don't factor this group
                    // Keep as separate literal alternatives
                    for (size_t i = 0; i < group_alts.size(); i++) {
                        auto lit = PatternNode::createLiteral(
                            group_alts[i], {group_seeds[i]}, all_counter_seeds);
                        new_children.push_back(lit);
                        new_seeds.push_back(group_seeds[i]);
                    }
                    continue;  // Skip to next group
                }
                
                // Create inner alternation
                auto inner_alt = PatternNode::createAlternation(inner_children, inner_seeds, all_counter_seeds);
                inner_alt->matched_seeds = group_seeds;
                inner_alt->counter_seeds = all_counter_seeds;
                
                // If we have empty remainder, wrap in optional to make it cleaner
                if (has_empty_remainder && inner_children.size() == 2) {
                    // Convert (rem|"") to (rem)?
                    // Find the non-empty child
                    for (auto& child : inner_children) {
                        if (!child->value.empty()) {
                            auto opt_node = PatternNode::createQuantified(
                                child, PatternType::OPTIONAL, child->matched_seeds, child->counter_seeds);
                            opt_node->matched_seeds = group_seeds;
                            opt_node->counter_seeds = all_counter_seeds;
                            
                            std::vector<std::shared_ptr<PatternNode>> seq_kids;
                            seq_kids.push_back(PatternNode::createLiteral(prefix, group_seeds, all_counter_seeds));
                            seq_kids.push_back(opt_node);
                            auto seq = PatternNode::createSequence(seq_kids, group_seeds, all_counter_seeds);
                            
                            new_children.push_back(seq);
                            new_seeds.insert(new_seeds.end(), group_seeds.begin(), group_seeds.end());
                            break;
                        }
                    }
                } else if (!has_empty_remainder) {
                    // All have non-empty remainders
                    // CRITICAL: Validate that all inputs will match the factored pattern
                    // before creating the sequence structure
                    
                    // Build the would-be factored pattern string for validation
                    std::string inner_pattern;
                    for (size_t i = 0; i < inner_children.size(); i++) {
                        if (i > 0) inner_pattern += "|";
                        inner_pattern += inner_children[i]->value;
                    }
                    std::string factored_pattern = prefix + "(" + inner_pattern + ")";
                    
                    // Check each input against the factored pattern
                    // Simple check: input should equal prefix + one of the remainders
                    bool all_inputs_match = true;
                    std::vector<std::string> failed_inputs;
                    
                    for (size_t i = 0; i < group_alts.size(); i++) {
                        const std::string& input = group_alts[i];
                        std::string remainder = input.substr(prefix.size());
                        
                        // Check if remainder exactly matches any inner child value
                        bool remainder_matches = false;
                        for (const auto& child : inner_children) {
                            if (remainder == child->value) {
                                remainder_matches = true;
                                break;
                            }
                        }
                        
                        if (!remainder_matches) {
                            all_inputs_match = false;
                            failed_inputs.push_back(input);
                        }
                    }
                    
                    if (!all_inputs_match) {
                        // Validation failed - don't create this factored structure
                        // Instead, keep alternatives as separate literals
                        if (proof_out) {
                            proof_out->valid = false;
                        }
                        
                        for (size_t i = 0; i < group_alts.size(); i++) {
                            auto lit = PatternNode::createLiteral(
                                group_alts[i], {group_seeds[i]}, all_counter_seeds);
                            new_children.push_back(lit);
                            new_seeds.push_back(group_seeds[i]);
                        }
                    } else {
                        // Validation passed - create the factored structure
                        // NOTE: No recursive call - each factorization must do full verification
                        
                        std::vector<std::shared_ptr<PatternNode>> seq_kids;
                        seq_kids.push_back(PatternNode::createLiteral(prefix, group_seeds, all_counter_seeds));
                        seq_kids.push_back(inner_alt);
                        auto seq = PatternNode::createSequence(seq_kids, group_seeds, all_counter_seeds);
                        
                        new_children.push_back(seq);
                        new_seeds.insert(new_seeds.end(), group_seeds.begin(), group_seeds.end());
                    }
                } else {
                    // Multiple alternatives with mixed empty/non-empty remainders
                    // Keep as alternation with prefix + (rem|ε|rem2|ε|...)
                    // NOTE: No recursive call - each factorization must do full verification
                    
                    std::vector<std::shared_ptr<PatternNode>> seq_kids;
                    seq_kids.push_back(PatternNode::createLiteral(prefix, group_seeds, all_counter_seeds));
                    seq_kids.push_back(inner_alt);
                    auto seq = PatternNode::createSequence(seq_kids, group_seeds, all_counter_seeds);
                    
                    new_children.push_back(seq);
                    new_seeds.insert(new_seeds.end(), group_seeds.begin(), group_seeds.end());
                }
            }
        }
        
        // DEBUG: Check if we lost any alternatives
        if (proof_out && new_children.size() < alternatives.size()) {
            proof_out->valid = false;  // Lost alternatives!
            // Build debug info with detailed SEQ contents
            std::string debug = "LOST:" + std::to_string(new_children.size()) + "vs" + 
                               std::to_string(alternatives.size()) + " [";
            for (size_t i = 0; i < alternatives.size(); i++) {
                if (i > 0) debug += ",";
                debug += alternatives[i];
            }
            debug += "]->[";
            for (size_t i = 0; i < new_children.size(); i++) {
                if (i > 0) debug += ",";
                if (new_children[i]->type == PatternType::LITERAL) {
                    debug += new_children[i]->value;
                } else if (new_children[i]->type == PatternType::SEQUENCE) {
                    debug += "SEQ{";
                    // Show what's in the sequence
                    for (size_t j = 0; j < new_children[i]->children.size(); j++) {
                        if (j > 0) debug += ",";
                        if (new_children[i]->children[j]->type == PatternType::LITERAL) {
                            debug += new_children[i]->children[j]->value;
                        } else if (new_children[i]->children[j]->type == PatternType::ALTERNATION) {
                            debug += "ALT(" + std::to_string(new_children[i]->children[j]->children.size()) + ")[";
                            // Show alternation children
                            for (size_t k = 0; k < new_children[i]->children[j]->children.size(); k++) {
                                if (k > 0) debug += ",";
                                if (new_children[i]->children[j]->children[k]->type == PatternType::LITERAL) {
                                    debug += new_children[i]->children[j]->children[k]->value;
                                } else {
                                    debug += "?";
                                }
                            }
                            debug += "]";
                        } else if (new_children[i]->children[j]->type == PatternType::OPTIONAL) {
                            debug += "OPT";
                        } else {
                            debug += "?";
                        }
                    }
                    debug += "}";
                } else {
                    debug += "OTHER";
                }
            }
            debug += "]";
            proof_out->after = debug;
        }
        
        // Create new alternation with factored children
        auto result = PatternNode::createAlternation(new_children, new_seeds, all_counter_seeds);
        result->matched_seeds = new_seeds;
        result->counter_seeds = all_counter_seeds;
        return result;
    }
    
    // All alternatives share a common prefix
    // NEW: Handle empty remainders - they become ε (empty) alternatives
    std::vector<std::shared_ptr<PatternNode>> inner_children;
    std::vector<std::string> inner_seeds;
    std::vector<std::string> all_counter_seeds = node->counter_seeds;
    bool has_empty = false;
    
    for (size_t i = 0; i < alternatives.size(); i++) {
        std::string rem = alternatives[i].substr(common.size());
        if (rem.empty()) {
            has_empty = true;
            auto empty_lit = PatternNode::createLiteral("", {node->matched_seeds[i]}, all_counter_seeds);
            inner_children.push_back(empty_lit);
        } else {
            auto lit = PatternNode::createLiteral(rem, {node->matched_seeds[i]}, all_counter_seeds);
            inner_children.push_back(lit);
        }
        inner_seeds.push_back(node->matched_seeds[i]);
    }
    
    // If only one child (either empty or remainder), handle specially
    if (inner_children.size() == 1) {
        if (has_empty) {
            // Just the prefix - already covered
            return node;
        }
        // Just one remainder - create simple sequence
        std::vector<std::shared_ptr<PatternNode>> seq_kids;
        seq_kids.push_back(PatternNode::createLiteral(common, inner_seeds, all_counter_seeds));
        seq_kids.push_back(inner_children[0]);
        auto result = PatternNode::createSequence(seq_kids, inner_seeds, all_counter_seeds);
        return result;
    }
    
    // Handle case with empty remainders (ε alternatives)
    if (has_empty) {
        // Check if we should convert to optional: (rem|"") → (rem)?
        if (inner_children.size() == 2) {
            for (auto& child : inner_children) {
                if (!child->value.empty()) {
                    auto opt_node = PatternNode::createQuantified(
                        child, PatternType::OPTIONAL, inner_seeds, all_counter_seeds);
                    opt_node->matched_seeds = inner_seeds;
                    opt_node->counter_seeds = all_counter_seeds;
                    
                    std::vector<std::shared_ptr<PatternNode>> seq_kids;
                    seq_kids.push_back(PatternNode::createLiteral(common, inner_seeds, all_counter_seeds));
                    seq_kids.push_back(opt_node);
                    auto result = PatternNode::createSequence(seq_kids, inner_seeds, all_counter_seeds);
                    return result;
                }
            }
        }
        
        // Multiple alternatives with some empty - create alternation with ε
        auto inner_alt = PatternNode::createAlternation(inner_children, inner_seeds, all_counter_seeds);
        inner_alt->matched_seeds = inner_seeds;
        inner_alt->counter_seeds = all_counter_seeds;
        // NOTE: No recursive call - each factorization must do full verification
        
        std::vector<std::shared_ptr<PatternNode>> seq_kids;
        seq_kids.push_back(PatternNode::createLiteral(common, inner_seeds, all_counter_seeds));
        seq_kids.push_back(inner_alt);
        auto result = PatternNode::createSequence(seq_kids, inner_seeds, all_counter_seeds);
        return result;
    }
    
    // All alternatives have non-empty remainders - safe to factor (original logic)
    std::vector<std::string> non_empty_stripped;
    for (size_t i = 0; i < alternatives.size(); i++) {
        std::string rem = alternatives[i].substr(common.size());
        non_empty_stripped.push_back(rem);
    }
    
    // Recursively factor the inner alternation
    auto inner_alt = PatternNode::createAlternation(inner_children, inner_seeds, all_counter_seeds);
    inner_alt->matched_seeds = inner_seeds;
    inner_alt->counter_seeds = all_counter_seeds;
    // NOTE: No recursive call - each factorization must do full verification
    
    // The sequence tracks inputs
    std::vector<std::shared_ptr<PatternNode>> seq_kids;
    seq_kids.push_back(PatternNode::createLiteral(common, inner_seeds, all_counter_seeds));
    seq_kids.push_back(inner_alt);
    auto result = PatternNode::createSequence(seq_kids, inner_seeds, all_counter_seeds);
    result->counter_seeds = all_counter_seeds;
    
    return result;
}

// Simple suffix factorization - only factor when ALL alternatives share a common suffix
// Example: (abc7q|bbc7q|cbc7q) -> ((abc|bbc|cbc)7q)
// Does NOT do recursive nested factoring to keep patterns simple and verifiable
std::shared_ptr<PatternNode> factorSuffixes(std::shared_ptr<PatternNode> node, int depth) {
    if (!node || depth > 10) return node;
    
    // Only process alternations
    if (node->type != PatternType::ALTERNATION || node->children.size() < 2) {
        return node;
    }
    
    // Get all literal alternatives
    std::vector<std::string> alternatives;
    for (const auto& child : node->children) {
        if (child->type == PatternType::LITERAL && !child->value.empty()) {
            alternatives.push_back(child->value);
        } else {
            // Mixed types - don't factor
            return node;
        }
    }
    
    // Find common suffix among all alternatives
    std::string common_suffix = findCommonSuffix(alternatives);
    
    if (common_suffix.empty()) {
        // No common suffix - don't try to group (keep simple)
        return node;
    }
    
    // All alternatives share a common suffix
    // Strip it and create: (stripped_alts...) + common_suffix
    std::vector<std::shared_ptr<PatternNode>> inner_children;
    std::vector<std::string> non_empty_stripped;
    std::vector<std::string> non_empty_seeds;
    
    for (size_t i = 0; i < alternatives.size(); i++) {
        std::string rem = alternatives[i].substr(0, alternatives[i].size() - common_suffix.size());
        if (!rem.empty()) {
            // Inner literal's value is the remainder before suffix, but it tracks the FULL input
            inner_children.push_back(PatternNode::createLiteral(rem, {node->matched_seeds[i]}));
            non_empty_stripped.push_back(rem);
            non_empty_seeds.push_back(node->matched_seeds[i]);  // Full input for sequence level
        }
    }
    
    // If all stripped are empty or only one non-empty, don't create alternation
    if (inner_children.empty()) {
        // All alternatives equal the common suffix exactly
        return node;
    }
    if (inner_children.size() == 1) {
        // Only one non-empty remainder - create sequence
        std::vector<std::shared_ptr<PatternNode>> seq_kids;
        seq_kids.push_back(inner_children[0]);
        seq_kids.push_back(PatternNode::createLiteral(common_suffix, non_empty_seeds));
        return PatternNode::createSequence(seq_kids, non_empty_seeds);
    }
    
    // Inner alternation tracks full inputs (not stripped remainders)
    auto inner_alt = PatternNode::createAlternation(inner_children, non_empty_seeds);
    inner_alt->matched_seeds = non_empty_seeds;
    
    // NOTE: No recursive call - each factorization must do full verification
    
    // The sequence tracks full inputs (from non_empty_seeds)
    std::vector<std::shared_ptr<PatternNode>> seq_kids;
    seq_kids.push_back(inner_alt);
    seq_kids.push_back(PatternNode::createLiteral(common_suffix, non_empty_seeds));
    auto result = PatternNode::createSequence(seq_kids, non_empty_seeds);
    
    return result;
}

// Recursively factor all alternations in an AST
std::shared_ptr<PatternNode> factorPattern(
    std::shared_ptr<PatternNode> node, 
    int depth,
    FactorizationProof* proof_out) {
    if (!node || depth > 10) return node;
    
    switch (node->type) {
        case PatternType::LITERAL:
        case PatternType::FRAGMENT_REF:
            return node;
            
        case PatternType::ALTERNATION:
            // Apply prefix factorization first
            node = factorAlternation(node, depth, proof_out);
            // Then apply suffix factorization if still an alternation
            if (node->type == PatternType::ALTERNATION) {
                node = factorSuffixes(node, depth);
            }
            // Recursively factor children
            for (auto& child : node->children) {
                child = factorPattern(child, depth + 1, proof_out);
            }
            return node;
            
        case PatternType::SEQUENCE:
            for (auto& child : node->children) {
                child = factorPattern(child, depth + 1, proof_out);
            }
            return node;
            
        case PatternType::PLUS_QUANTIFIER:
        case PatternType::STAR_QUANTIFIER:
        case PatternType::OPTIONAL:
            if (node->quantified) {
                node->quantified = factorPattern(node->quantified, depth + 1, proof_out);
            }
            return node;
            
        default:
            return node;
    }
}

// ============================================================================
// Quantifier Detection - Convert repeated patterns to + quantifier
// Example: (bebe|bebebe|bebebebe) -> (be)+
// Also supports partial conversions: (bbbbbb|bbbbbbbb|bbb+) 
// Only creates (pattern)+ since we lack {n,m} syntax
// ============================================================================

// Check if a string consists of N repetitions of a base pattern
bool isRepetition(const std::string& str, const std::string& base, int n) {
    if (str.length() != base.length() * n) return false;
    for (int i = 0; i < n; i++) {
        if (str.substr(i * base.length(), base.length()) != base) {
            return false;
        }
    }
    return true;
}

// Find the minimal repeating unit in a string
std::string findMinimalRepeatingUnit(const std::string& str) {
    int n = str.length();
    for (int len = 1; len <= n / 2; len++) {
        if (n % len == 0) {
            std::string base = str.substr(0, len);
            bool valid = true;
            for (int i = len; i < n; i += len) {
                if (str.substr(i, len) != base) {
                    valid = false;
                    break;
                }
            }
            if (valid) return base;
        }
    }
    return str;  // No repetition found, return original
}

// Find the most common repeating base among alternatives
// Returns the base that appears most frequently, or empty if none found
std::string findMostCommonRepeatingBase(const std::vector<std::string>& alternatives) {
    if (alternatives.empty()) return "";
    
    // Count frequency of each base among repeating patterns
    std::map<std::string, int> base_counts;
    std::map<std::string, std::vector<std::string>> base_to_alts;
    
    for (const auto& alt : alternatives) {
        std::string base = findMinimalRepeatingUnit(alt);
        // Skip empty bases to avoid division by zero
        if (base.empty() || base.length() == 0) continue;
        int reps = alt.length() / base.length();
        // Only consider as repeating if reps >= 3 (for + quantifier to be useful)
        if (reps >= 3) {
            base_counts[base]++;
            base_to_alts[base].push_back(alt);
        }
    }
    
    // Find the base with highest count (at least 2 alternatives needed)
    std::string best_base = "";
    int best_count = 0;
    for (const auto& [base, count] : base_counts) {
        if (count > best_count && count >= 2) {
            best_count = count;
            best_base = base;
        }
    }
    
    return best_base;
}

// Convert an alternation to include quantifier patterns
// Supports partial conversion: (bbbbbb|bbbbbbbb|bbb+)
std::shared_ptr<PatternNode> convertToQuantifier(std::shared_ptr<PatternNode> node) {
    if (!node || node->type != PatternType::ALTERNATION) return node;
    if (node->children.size() < 2) return node;
    
    // Collect all literal alternatives and their seeds
    std::vector<std::string> alternatives;
    std::vector<std::string> seeds = node->matched_seeds;
    std::vector<std::string> all_counter_seeds = node->counter_seeds;
    
    for (const auto& child : node->children) {
        if (child->type != PatternType::LITERAL) {
            return node;  // Non-literal child, can't convert
        }
        alternatives.push_back(child->value);
    }
    
    if (alternatives.size() != seeds.size()) {
        return node;  // Mismatch between alternatives and seeds
    }
    
    // Try to find a common repeating base (at least 2 alternatives sharing it)
    std::string common_base = findMostCommonRepeatingBase(alternatives);
    if (common_base.empty()) return node;  // No repeating patterns found
    
    // Build new children: keep literals that don't match the common base, convert others
    std::vector<std::shared_ptr<PatternNode>> new_children;
    std::vector<std::string> new_seeds;
    std::vector<std::string> quantifier_seeds;  // Seeds for the merged quantifier
    bool made_conversion = false;
    
    for (size_t i = 0; i < alternatives.size(); i++) {
        const std::string& alt = alternatives[i];
        std::string base = findMinimalRepeatingUnit(alt);
        // Skip empty bases to avoid division by zero
        if (base.empty() || base.length() == 0) continue;
        int reps = alt.length() / base.length();
        
        if (base == common_base && reps >= 3) {
            // This alternative should be converted - collect its seed for merging
            quantifier_seeds.push_back(seeds[i]);
            made_conversion = true;
        } else {
            // Keep as literal with counter constraints
            auto lit_node = PatternNode::createLiteral(alt, {seeds[i]}, all_counter_seeds);
            lit_node->matched_seeds = {seeds[i]};
            lit_node->counter_seeds = all_counter_seeds;
            new_children.push_back(lit_node);
            new_seeds.push_back(seeds[i]);
        }
    }
    
    // Only return modified node if we made at least one conversion
    if (!made_conversion) return node;
    
    // Create a single merged quantifier for all converted alternatives
    // CRITICAL: Must verify that NO counter-input matches (base)+
    auto base_node = PatternNode::createLiteral(common_base, quantifier_seeds, all_counter_seeds);
    auto quant_node = PatternNode::createQuantified(base_node, PatternType::PLUS_QUANTIFIER, quantifier_seeds, all_counter_seeds);
    quant_node->matched_seeds = quantifier_seeds;
    quant_node->counter_seeds = all_counter_seeds;
    new_children.push_back(quant_node);
    new_seeds.insert(new_seeds.end(), quantifier_seeds.begin(), quantifier_seeds.end());
    
    // If only one child remains (all were converted), return just the quantifier
    if (new_children.size() == 1) {
        quant_node->matched_seeds = new_seeds;
        quant_node->counter_seeds = all_counter_seeds;
        return quant_node;
    }
    
    // Return mixed alternation (some literals, one quantifier for the rest)
    auto result = PatternNode::createAlternation(new_children, new_seeds, all_counter_seeds);
    result->matched_seeds = new_seeds;
    result->counter_seeds = all_counter_seeds;
    return result;
}

// Merge duplicate quantifiers in an alternation
// e.g., (be)+|(be)+ -> (be)+
std::shared_ptr<PatternNode> mergeDuplicateQuantifiers(std::shared_ptr<PatternNode> node) {
    if (!node || node->type != PatternType::ALTERNATION || node->children.size() < 2) {
        return node;
    }
    
    // Find duplicate + quantifiers with same base
    std::map<std::string, std::vector<std::shared_ptr<PatternNode>>> quantifier_groups;
    std::vector<std::shared_ptr<PatternNode>> non_quantifier_children;
    std::vector<std::string> all_seeds;
    
    for (const auto& child : node->children) {
        all_seeds.insert(all_seeds.end(), child->matched_seeds.begin(), child->matched_seeds.end());
        
        if (child->type == PatternType::PLUS_QUANTIFIER && child->quantified) {
            std::string base = child->quantified->value;
            quantifier_groups[base].push_back(child);
        } else {
            non_quantifier_children.push_back(child);
        }
    }
    
    // Collect all counter seeds from node
    std::vector<std::string> all_counter_seeds = node->counter_seeds;
    
    // If no duplicates found, return original (but update counter_seeds)
    bool has_duplicates = false;
    for (const auto& [base, children] : quantifier_groups) {
        if (children.size() > 1) {
            has_duplicates = true;
            break;
        }
    }
    if (!has_duplicates) {
        // Still update counter_seeds on the original node
        node->counter_seeds = all_counter_seeds;
        return node;
    }
    
    // Build new children with merged quantifiers
    std::vector<std::shared_ptr<PatternNode>> new_children;
    std::vector<std::string> new_seeds;
    
    // Add non-quantifier children
    for (const auto& child : non_quantifier_children) {
        new_children.push_back(child);
        new_seeds.insert(new_seeds.end(), child->matched_seeds.begin(), child->matched_seeds.end());
        // Ensure counter_seeds are propagated
        if (child->counter_seeds.empty() && !all_counter_seeds.empty()) {
            child->counter_seeds = all_counter_seeds;
        }
    }
    
    // Add merged quantifiers
    for (const auto& [base, children] : quantifier_groups) {
        if (children.size() == 1) {
            new_children.push_back(children[0]);
            new_seeds.insert(new_seeds.end(), children[0]->matched_seeds.begin(), children[0]->matched_seeds.end());
            // Ensure counter_seeds are propagated
            if (children[0]->counter_seeds.empty() && !all_counter_seeds.empty()) {
                children[0]->counter_seeds = all_counter_seeds;
            }
        } else {
            // Merge all seeds from duplicate quantifiers
            std::vector<std::string> merged_seeds;
            for (const auto& child : children) {
                merged_seeds.insert(merged_seeds.end(), child->matched_seeds.begin(), child->matched_seeds.end());
            }
            // Create single quantifier with all seeds and counter constraints
            auto base_node = PatternNode::createLiteral(base, merged_seeds, all_counter_seeds);
            auto quant_node = PatternNode::createQuantified(base_node, PatternType::PLUS_QUANTIFIER, merged_seeds, all_counter_seeds);
            quant_node->matched_seeds = merged_seeds;
            quant_node->counter_seeds = all_counter_seeds;
            new_children.push_back(quant_node);
            new_seeds.insert(new_seeds.end(), merged_seeds.begin(), merged_seeds.end());
        }
    }
    
    // If only one child remains after merging, return it directly
    if (new_children.size() == 1) {
        new_children[0]->counter_seeds = all_counter_seeds;
        return new_children[0];
    }
    
    auto result = PatternNode::createAlternation(new_children, new_seeds);
    result->matched_seeds = new_seeds;
    return result;
}

// Recursively apply quantifier detection to an AST
std::shared_ptr<PatternNode> applyQuantifierDetection(std::shared_ptr<PatternNode> node, int depth) {
    if (!node || depth > 10) return node;
    
    switch (node->type) {
        case PatternType::LITERAL:
        case PatternType::FRAGMENT_REF:
            return node;
            
        case PatternType::ALTERNATION: {
            // First recursively process children
            for (auto& child : node->children) {
                child = applyQuantifierDetection(child, depth + 1);
            }
            // Try to convert this alternation to a quantifier
            node = convertToQuantifier(node);
            // Then merge any duplicate quantifiers
            node = mergeDuplicateQuantifiers(node);
            return node;
        }
            
        case PatternType::SEQUENCE:
            for (auto& child : node->children) {
                child = applyQuantifierDetection(child, depth + 1);
            }
            return node;
            
        case PatternType::PLUS_QUANTIFIER:
        case PatternType::STAR_QUANTIFIER:
        case PatternType::OPTIONAL:
            if (node->quantified) {
                node->quantified = applyQuantifierDetection(node->quantified, depth + 1);
            }
            return node;
            
        default:
            return node;
    }
}

// ============================================================================
// Random Star Quantifier Insertion
// Randomly inserts (X)* patterns where X doesn't violate constraints
// This adds more variety while maintaining correctness
// ============================================================================

// Deep copy a PatternNode AST
std::shared_ptr<PatternNode> copyPatternNode(std::shared_ptr<PatternNode> node) {
    if (!node) return nullptr;
    
    auto copy = std::make_shared<PatternNode>();
    copy->type = node->type;
    copy->value = node->value;
    copy->fragment_name = node->fragment_name;
    copy->matched_seeds = node->matched_seeds;
    copy->counter_seeds = node->counter_seeds;
    copy->capture_tag = node->capture_tag;
    copy->capture_begin_only = node->capture_begin_only;
    copy->capture_end_only = node->capture_end_only;
    
    // Deep copy children
    for (const auto& child : node->children) {
        copy->children.push_back(copyPatternNode(child));
    }
    
    // Deep copy quantified node
    if (node->quantified) {
        copy->quantified = copyPatternNode(node->quantified);
    }
    
    return copy;
}

// Insert a random * quantified expression at safe positions
// 20% chance to trigger, then 20% chance to apply (80% skip) = 4% overall application rate
std::shared_ptr<PatternNode> insertRandomStarQuantifier(
    std::shared_ptr<PatternNode> node,
    std::mt19937& rng,
    int depth) {
    
    if (!node || depth > 5) return node;
    
    // 20% chance to consider inserting at this node
    std::uniform_int_distribution<int> chance_dist(0, 99);
    if (chance_dist(rng) >= 20) {
        // 80% of the time, skip this node entirely
        // Still recursively process children
        if (node->type == PatternType::ALTERNATION || node->type == PatternType::SEQUENCE) {
            for (auto& child : node->children) {
                child = insertRandomStarQuantifier(child, rng, depth + 1);
            }
        }
        return node;
    }
    
    // 20% of the time (when we reach here), try to insert star quantifier
    switch (node->type) {
        case PatternType::LITERAL: {
            // Only insert if literal has 3+ chars
            if (node->value.length() >= 3) {
                std::string base_value = node->value;
                std::vector<std::string> seeds = node->matched_seeds;
                std::vector<std::string> counter_seeds = node->counter_seeds;
                
                // Try with last 2 chars as star-quantified
                if (base_value.length() >= 3) {
                    std::string prefix = base_value.substr(0, base_value.length() - 2);
                    std::string star_part = base_value.substr(base_value.length() - 2);
                    
                    // CRITICAL SAFETY CHECK: Verify no counter-input would match prefix alone
                    // (prefix alone matching would mean zero star repetitions violates constraints)
                    bool safe_to_insert = true;
                    std::vector<std::string> violating_counters;
                    for (const auto& counter : counter_seeds) {
                        if (counter == prefix) {
                            // A counter-input equals the prefix - inserting star would allow it to match
                            safe_to_insert = false;
                            violating_counters.push_back(counter);
                        }
                    }
                    
                    if (!safe_to_insert) {
                        return node;  // Skip insertion to preserve constraints
                    }
                    
                    // Create sequence: prefix + (star_part)*
                    auto prefix_node = PatternNode::createLiteral(prefix, seeds, counter_seeds);
                    auto star_base = PatternNode::createLiteral(star_part, seeds, counter_seeds);
                    auto star_node = PatternNode::createQuantified(star_base, PatternType::STAR_QUANTIFIER, seeds, counter_seeds);
                    star_node->matched_seeds = seeds;
                    star_node->counter_seeds = counter_seeds;
                    
                    std::vector<std::shared_ptr<PatternNode>> seq_children;
                    seq_children.push_back(prefix_node);
                    seq_children.push_back(star_node);
                    auto seq_node = PatternNode::createSequence(seq_children, seeds, counter_seeds);
                    seq_node->matched_seeds = seeds;
                    seq_node->counter_seeds = counter_seeds;
                    return seq_node;
                }
            }
            return node;
        }
            
        case PatternType::PLUS_QUANTIFIER:
        case PatternType::STAR_QUANTIFIER:
        case PatternType::OPTIONAL:
            // Don't insert inside quantifiers
            return node;
            
        default:
            return node;
    }
}

// Apply constraint subdivision to sequences in an AST
void applyConstraintSubdivisionRecursive(std::shared_ptr<PatternNode> node, std::mt19937& rng) {
    if (!node) return;
    
    // Process children first (post-order traversal)
    if (node->type == PatternType::SEQUENCE || node->type == PatternType::ALTERNATION) {
        for (auto& child : node->children) {
            applyConstraintSubdivisionRecursive(child, rng);
        }
        
        // Apply subdivision to sequences
        if (node->type == PatternType::SEQUENCE) {
            applyConstraintSubdivision(node, rng);
        }
    }
    
    // Process quantified nodes
    if (node->quantified) {
        applyConstraintSubdivisionRecursive(node->quantified, rng);
    }
}

// Apply factorization to a PatternNode
// If proof pointer is provided, fills in detailed factorization steps
std::shared_ptr<PatternNode> applyFactorization(
    std::shared_ptr<PatternNode> root, 
    std::mt19937& rng,
    FactorizationProof* proof_out) {
    
    // First apply constraint subdivision to distribute counter constraints
    applyConstraintSubdivisionRecursive(root, rng);
    
    // Then apply prefix/suffix factorization
    auto result = factorPattern(root, 0, proof_out);
    
    // Then apply quantifier detection
    result = applyQuantifierDetection(result, 0);
    return result;
}

// Detect and report star insertions by comparing ASTs
std::string detectStarInsertions(std::shared_ptr<PatternNode> before,
                                  std::shared_ptr<PatternNode> after,
                                  const std::string& context) {
    std::string report;
    
    if (!before || !after) return report;
    
    // Log what we're comparing
    std::string btype, atype;
    switch(before->type) {
        case PatternType::LITERAL: btype = "LITERAL"; break;
        case PatternType::SEQUENCE: btype = "SEQUENCE"; break;
        case PatternType::ALTERNATION: btype = "ALT"; break;
        case PatternType::STAR_QUANTIFIER: btype = "STAR"; break;
        default: btype = "OTHER"; break;
    }
    switch(after->type) {
        case PatternType::LITERAL: atype = "LITERAL"; break;
        case PatternType::SEQUENCE: atype = "SEQUENCE"; break;
        case PatternType::ALTERNATION: atype = "ALT"; break;
        case PatternType::STAR_QUANTIFIER: atype = "STAR"; break;
        default: atype = "OTHER"; break;
    }
    
    // Check if this node changed from LITERAL to SEQUENCE-with-star
    // This happens when star insertion transforms a literal
    if (before->type == PatternType::LITERAL && after->type == PatternType::SEQUENCE) {
        // Check if the after sequence has the pattern: Literal + Star
        if (after->children.size() == 2 && 
            after->children[0]->type == PatternType::LITERAL &&
            after->children[1]->type == PatternType::STAR_QUANTIFIER) {
            
            std::string original = before->value;
            std::string prefix = after->children[0]->value;
            std::string star_subexp = after->children[1]->quantified ? 
                                     after->children[1]->quantified->value : "?";
            
            report += "      [Star insertion at " + context + "]\n";
            report += "        Original literal: '" + original + "'\n";
            report += "        Rewritten to: '" + prefix + "(" + star_subexp + ")*'\n";
            report += "        Local constraint: must-not-match any counter that equals '" + prefix + "'\n";
            
            // Check safety
            bool would_violate = false;
            for (const auto& c : before->counter_seeds) {
                if (c == prefix) {
                    would_violate = true;
                    break;
                }
            }
            report += "        Safety: " + std::string(would_violate ? "FAIL (blocked)" : "PASS") + 
                     " (checked " + std::to_string(before->counter_seeds.size()) + " counters)\n";
            
            return report;
        }
    }
    
    // Check if child types changed (star insertion changes LITERAL to SEQUENCE in parent)
    if (before->children.size() == after->children.size()) {
        for (size_t i = 0; i < before->children.size(); i++) {
            std::string child_ctx = context + "[" + std::to_string(i) + "]";
            // Check if this specific child changed type (indicates transformation)
            if (before->children[i]->type != after->children[i]->type) {
                // Type mismatch - likely a transformation occurred here
                report += detectStarInsertions(before->children[i], after->children[i], child_ctx);
            } else {
                // Same type, recurse normally
                report += detectStarInsertions(before->children[i], after->children[i], child_ctx);
            }
        }
    }
    
    // Check quantified child
    if (before->quantified && after->quantified) {
        report += detectStarInsertions(before->quantified, after->quantified, context + "->quantified");
    }
    
    return report;
}

// ============================================================================
// Rewrite 4: Character Class Introduction
// Convert repetitive character patterns to character classes
// Example: 'abc' with a,b,c being different → '([a-c])' or similar
// ============================================================================

std::shared_ptr<PatternNode> introduceCharClass(
    std::shared_ptr<PatternNode> node,
    std::mt19937& rng,
    int depth,
    std::map<std::string, std::string>& fragment_defs) {
    
    if (!node || depth > 5) return node;
    
    std::uniform_int_distribution<int> chance_dist(0, 99);
    
    switch (node->type) {
        case PatternType::LITERAL: {
            // 10% chance to convert literal to character class + quantifier
            if (node->value.length() >= 2 && chance_dist(rng) < 10) {
                std::string val = node->value;
                
                // Find a range of characters in the literal
                char min_char = val[0];
                char max_char = val[0];
                for (char c : val) {
                    if (c < min_char) min_char = c;
                    if (c > max_char) max_char = c;
                }
                
                // Only create class if range is small and meaningful
                if (max_char - min_char <= 5 && max_char != min_char) {
                    // Create candidate char class
                    std::string class_def = "(";
                    for (char c = min_char; c <= max_char; c++) {
                        if (c > min_char) class_def += "|";
                        class_def += std::string(1, c);
                    }
                    class_def += ")";
                    
                    // CRITICAL: Validate that no counter input matches the char class pattern
                    // The char class (a|b|c)+ with + quantifier matches ANY length >= 1
                    // where ALL characters are in the class. This is MUCH broader than a literal.
                    bool would_match_counters = false;
                    std::vector<std::string> violating_counters;
                    
                    for (const auto& counter : node->counter_seeds) {
                        // Check if counter would match (char_class)+
                        // Counter matches if: length >= 1 AND all chars in [min_char, max_char]
                        if (counter.length() >= 1) {
                            bool all_chars_in_class = true;
                            for (char c : counter) {
                                if (c < min_char || c > max_char) {
                                    all_chars_in_class = false;
                                    break;
                                }
                            }
                            if (all_chars_in_class) {
                                would_match_counters = true;
                                violating_counters.push_back(counter);
                            }
                        }
                    }
                    
                    if (would_match_counters) {
                        // Char class (with + quantifier) would match counter inputs - DON'T introduce it
                        return node;
                    }
                    
                    // Validation passed - create the fragment
                    std::string frag_name = "class" + std::to_string(rng() % 100);
                    fragment_defs[frag_name] = class_def;
                    
                    // Create fragment reference - it already has + quantifier in serialization!
                    auto frag_node = PatternNode::createFragment(
                        frag_name, node->matched_seeds, node->counter_seeds);
                    frag_node->matched_seeds = node->matched_seeds;
                    frag_node->counter_seeds = node->counter_seeds;
                    
                    return frag_node;
                }
            }
            return node;
        }
            
        case PatternType::ALTERNATION:
        case PatternType::SEQUENCE: {
            for (auto& child : node->children) {
                child = introduceCharClass(child, rng, depth + 1, fragment_defs);
            }
            return node;
        }
            
        case PatternType::PLUS_QUANTIFIER:
        case PatternType::STAR_QUANTIFIER:
        case PatternType::OPTIONAL: {
            if (node->quantified) {
                node->quantified = introduceCharClass(node->quantified, rng, depth + 1, fragment_defs);
            }
            return node;
        }
            
        default:
            return node;
    }
}

// ============================================================================
// Constraint Verification Framework
// ============================================================================

// Check if a string matches a literal pattern
bool stringMatchesLiteral(const std::string& str, const std::string& literal) {
    return str == literal;
}

// Check if a string starts with a prefix
bool stringStartsWith(const std::string& str, const std::string& prefix) {
    if (prefix.length() > str.length()) return false;
    return str.compare(0, prefix.length(), prefix) == 0;
}

// Result of optional group safety check
struct OptionalGroupSafety {
    bool is_safe;
    std::string reason;
    std::vector<std::string> failing_inputs;
    std::vector<std::string> violating_counters;
};

// Check if optional group transformation is safe
// Transforms: 'literal' -> 'prefix' + '(suffix)?'
OptionalGroupSafety checkOptionalGroupSafety(
    const std::string& literal,
    size_t split_point,
    const std::vector<std::string>& matching_inputs,
    const std::vector<std::string>& counter_inputs) {
    
    OptionalGroupSafety result;
    result.is_safe = true;
    
    if (split_point > literal.length()) {
        result.is_safe = false;
        result.reason = "Split point beyond literal length";
        return result;
    }
    
    std::string prefix = literal.substr(0, split_point);
    std::string suffix = literal.substr(split_point);
    
    // Check 1: All matching inputs must match either prefix or prefix+suffix
    for (const auto& m : matching_inputs) {
        bool matches_prefix = (m == prefix);
        bool matches_full = (m == literal);
        
        if (!matches_prefix && !matches_full) {
            result.is_safe = false;
            result.failing_inputs.push_back(m);
        }
    }
    
    if (!result.failing_inputs.empty()) {
        result.reason = "Input(s) don't match prefix '" + prefix + "' nor full '" + literal + "'";
        return result;
    }
    
    // Check 2: No counter inputs match just the prefix
    for (const auto& c : counter_inputs) {
        if (c == prefix) {
            result.is_safe = false;
            result.violating_counters.push_back(c);
        }
    }
    
    if (!result.violating_counters.empty()) {
        result.reason = "Counter-input(s) match prefix alone";
        return result;
    }
    
    // Count how many inputs match each form
    int prefix_count = 0;
    int full_count = 0;
    for (const auto& m : matching_inputs) {
        if (m == prefix) prefix_count++;
        if (m == literal) full_count++;
    }
    
    result.reason = "Safe: " + std::to_string(prefix_count) + " inputs match prefix only, " +
                   std::to_string(full_count) + " match full; no counter matches prefix";
    return result;
}

// ============================================================================
// Rewrite 5: Optional Group Insertion (with full constraint verification)
// ============================================================================

std::shared_ptr<PatternNode> insertOptionalGroup(
    std::shared_ptr<PatternNode> node,
    std::mt19937& rng,
    int depth,
    std::string& proof_log) {
    
    if (!node || depth > 5) return node;
    
    std::uniform_int_distribution<int> chance_dist(0, 99);
    
    switch (node->type) {
        case PatternType::LITERAL: {
            // 8% chance to make suffix optional
            if (node->value.length() >= 4 && chance_dist(rng) < 8) {
                std::string val = node->value;
                
                // Try split points
                std::vector<size_t> split_points = {2};
                if (val.length() >= 6) split_points.push_back(3);
                
                for (size_t split_point : split_points) {
                    if (split_point >= val.length() || split_point < 2) continue;
                    
                    // FULL constraint verification
                    auto safety = checkOptionalGroupSafety(
                        val, split_point,
                        node->matched_seeds,
                        node->counter_seeds);
                    
                    if (safety.is_safe) {
                        std::string prefix = val.substr(0, split_point);
                        std::string suffix = val.substr(split_point);
                        
                        // Partition seeds based on which form they match
                        std::vector<std::string> prefix_only_seeds;  // Inputs that equal just prefix
                        std::vector<std::string> full_form_seeds;    // Inputs that equal full literal
                        
                        for (const auto& seed : node->matched_seeds) {
                            if (seed == prefix) {
                                prefix_only_seeds.push_back(seed);
                            } else if (seed == val) {
                                full_form_seeds.push_back(seed);
                            }
                            // Note: seeds that match neither were already filtered by safety check
                        }
                        
                        // 50/50 random choice: use (suffix)? or (suffix|"") syntax
                        bool use_alternation_syntax = (chance_dist(rng) < 50);
                        
                        if (use_alternation_syntax) {
                            proof_log += "    [Optional group OK] '" + val + "' -> '" + 
                                        prefix + "(" + suffix + "|ε)'\n";
                        } else {
                            proof_log += "    [Optional group OK] '" + val + "' -> '" + 
                                        prefix + "(" + suffix + ")?'\n";
                        }
                        proof_log += "      Partition: " + std::to_string(prefix_only_seeds.size()) + 
                                    " inputs match prefix only, " + 
                                    std::to_string(full_form_seeds.size()) + " match full form\n";
                        
                        // Create: prefix + (suffix)? or prefix + (suffix|"")
                        // Prefix node tracks ALL seeds (both forms go through prefix)
                        auto prefix_node = PatternNode::createLiteral(
                            prefix, node->matched_seeds, node->counter_seeds);
                        
                        // Suffix node only tracks full-form seeds (only they use the suffix)
                        auto suffix_node = PatternNode::createLiteral(
                            suffix, full_form_seeds, node->counter_seeds);
                        
                        std::shared_ptr<PatternNode> opt_node;
                        if (use_alternation_syntax) {
                            // Create alternation: (suffix|"") using empty literal for ε
                            auto empty_lit = PatternNode::createLiteral(
                                "", prefix_only_seeds, node->counter_seeds);
                            std::vector<std::shared_ptr<PatternNode>> alt_children;
                            alt_children.push_back(suffix_node);
                            alt_children.push_back(empty_lit);
                            opt_node = PatternNode::createAlternation(
                                alt_children, node->matched_seeds, node->counter_seeds);
                        } else {
                            // Use standard optional quantifier: (suffix)?
                            opt_node = PatternNode::createQuantified(
                                suffix_node, PatternType::OPTIONAL, 
                                full_form_seeds, node->counter_seeds);
                        }
                        
                        std::vector<std::shared_ptr<PatternNode>> seq_children;
                        seq_children.push_back(prefix_node);
                        seq_children.push_back(opt_node);
                        
                        // Sequence tracks ALL seeds (both paths through sequence)
                        auto seq_node = PatternNode::createSequence(
                            seq_children, node->matched_seeds, node->counter_seeds);
                        seq_node->matched_seeds = node->matched_seeds;
                        seq_node->counter_seeds = node->counter_seeds;
                        
                        return seq_node;
                    } else {
                        proof_log += "    [Optional group REJECTED split=" + 
                                    std::to_string(split_point) + "] " + safety.reason + "\n";
                    }
                }
            }
            return node;
        }
            
        case PatternType::ALTERNATION:
        case PatternType::SEQUENCE: {
            for (auto& child : node->children) {
                child = insertOptionalGroup(child, rng, depth + 1, proof_log);
            }
            return node;
        }
            
        case PatternType::PLUS_QUANTIFIER:
        case PatternType::STAR_QUANTIFIER:
        case PatternType::OPTIONAL: {
            if (node->quantified) {
                node->quantified = insertOptionalGroup(node->quantified, rng, depth + 1, proof_log);
            }
            return node;
        }
            
        default:
            return node;
    }
}

// ============================================================================
// Rewrite 6: Nested Quantifier Creation
// Create patterns like ((ab)+)* or (a+|b+)*
// ============================================================================

std::shared_ptr<PatternNode> createNestedQuantifiers(
    std::shared_ptr<PatternNode> node,
    std::mt19937& rng,
    int depth) {
    
    if (!node || depth > 4) return node;
    
    std::uniform_int_distribution<int> chance_dist(0, 99);
    
    switch (node->type) {
        case PatternType::PLUS_QUANTIFIER: {
            // Recurse into quantified
            if (node->quantified) {
                node->quantified = createNestedQuantifiers(node->quantified, rng, depth + 1);
            }
            return node;
        }
            
        case PatternType::ALTERNATION: {
            // DISABLED: Wrapping alternation in + changes semantics
            // May allow 0 matches when original required at least 1
            // if (chance_dist(rng) < 10 && node->children.size() >= 2) {
            //     ... wrapping code ...
            // }
            
            for (auto& child : node->children) {
                child = createNestedQuantifiers(child, rng, depth + 1);
            }
            return node;
        }
            
        case PatternType::SEQUENCE: {
            for (auto& child : node->children) {
                child = createNestedQuantifiers(child, rng, depth + 1);
            }
            return node;
        }
            
        default:
            return node;
    }
}

// ============================================================================
// Rewrite: Fragment Extraction
// Randomly extract subexpressions into named fragments
// ============================================================================

std::shared_ptr<PatternNode> extractFragmentRewrite(
    std::shared_ptr<PatternNode> node,
    std::mt19937& rng,
    int depth,
    std::map<std::string, std::string>& fragment_defs) {
    
    if (!node || depth > 6) return node;
    
    std::uniform_int_distribution<int> chance_dist(0, 99);
    
    switch (node->type) {
        case PatternType::LITERAL: {
            // 8% chance to extract literal to fragment
            if (node->value.length() >= 3 && chance_dist(rng) < 8) {
                std::string frag_name = "frag" + std::to_string(rng() % 1000);
                std::string frag_def = node->value;
                
                // Register fragment
                fragment_defs[frag_name] = frag_def;
                
                // Create fragment reference
                auto frag_node = PatternNode::createFragment(
                    frag_name, node->matched_seeds, node->counter_seeds);
                frag_node->matched_seeds = node->matched_seeds;
                frag_node->counter_seeds = node->counter_seeds;
                
                return frag_node;
            }
            return node;
        }
            
        case PatternType::ALTERNATION:
        case PatternType::SEQUENCE: {
            // 5% chance to extract entire alternation/sequence
            if (node->children.size() >= 2 && chance_dist(rng) < 5) {
                std::string frag_name = "sub" + std::to_string(rng() % 1000);
                std::string frag_def = serializePattern(node);
                
                // Don't extract if already simple
                if (frag_def.length() > 5) {
                    fragment_defs[frag_name] = frag_def;
                    
                    auto frag_node = PatternNode::createFragment(
                        frag_name, node->matched_seeds, node->counter_seeds);
                    frag_node->matched_seeds = node->matched_seeds;
                    frag_node->counter_seeds = node->counter_seeds;
                    
                    return frag_node;
                }
            }
            
            // Recurse into children
            for (auto& child : node->children) {
                child = extractFragmentRewrite(child, rng, depth + 1, fragment_defs);
            }
            return node;
        }
            
        case PatternType::PLUS_QUANTIFIER:
        case PatternType::STAR_QUANTIFIER:
        case PatternType::OPTIONAL: {
            if (node->quantified) {
                node->quantified = extractFragmentRewrite(node->quantified, rng, depth + 1, fragment_defs);
            }
            return node;
        }
            
        default:
            return node;
    }
}

// ============================================================================
// Rewrite: Sequence Merge/Unmerge
// Merge adjacent literals OR split long literals
// ============================================================================

// Result of sequence split/merge safety check
struct SequenceSplitSafety {
    bool is_safe;
    std::string reason;
    std::vector<std::string> failing_inputs;  // Inputs that can't split correctly
};

// Check if literal split is safe
// Transforms: 'literal' -> 'part1' + 'part2'
SequenceSplitSafety checkSequenceSplitSafety(
    const std::string& literal,
    size_t split_point,
    const std::vector<std::string>& matching_inputs,
    const std::vector<std::string>& counter_inputs) {
    
    SequenceSplitSafety result;
    result.is_safe = true;
    
    if (split_point > literal.length() || split_point == 0) {
        result.is_safe = false;
        result.reason = "Invalid split point";
        return result;
    }
    
    std::string part1 = literal.substr(0, split_point);
    std::string part2 = literal.substr(split_point);
    
    // Check: All matching inputs must be able to concatenate from parts
    // Since we're only changing AST structure, not pattern semantics,
    // any input that matched the original must still match
    // The concern is counter-inputs that might match part1 or part2 alone
    
    // Check 1: Verify no counter matches just part1 + part2 separately somehow
    // Actually for literals, split is always semantically equivalent
    // The issue is if counters match the concatenation differently
    
    // The real check: counters that match the full literal might also match
    // if we add structure - but for simple split, semantics are identical
    
    // Most important: Ensure split doesn't create ambiguity
    // But since we're just restructuring, this is always safe for literals
    
    result.reason = "Safe: Literal split preserves exact matching semantics";
    return result;
}

// Check if literal merge is safe
// Transforms: 'lit1' + 'lit2' -> 'lit1+lit2'
SequenceSplitSafety checkSequenceMergeSafety(
    const std::string& lit1,
    const std::string& lit2,
    const std::vector<std::string>& matching_inputs,
    const std::vector<std::string>& counter_inputs) {
    
    SequenceSplitSafety result;
    result.is_safe = true;
    
    std::string merged = lit1 + lit2;
    
    // Check: No counter that doesn't match lit1+lit2 should match
    // This is preserved by the merge operation
    // But we need to ensure no counter matches lit1 alone and then 
    // something else could complete it
    
    // Actually, merge is semantically equivalent for sequence matching
    // The merged form matches exactly the same strings
    
    result.reason = "Safe: Literal merge preserves exact matching semantics";
    return result;
}

std::shared_ptr<PatternNode> sequenceMergeUnmerge(
    std::shared_ptr<PatternNode> node,
    std::mt19937& rng,
    int depth,
    std::string& proof_log) {
    
    if (!node || depth > 5) return node;
    
    std::uniform_int_distribution<int> chance_dist(0, 99);
    
    switch (node->type) {
        case PatternType::SEQUENCE: {
            // 5% chance to merge adjacent literals
            if (chance_dist(rng) < 5 && node->children.size() >= 2) {
                for (size_t i = 0; i < node->children.size() - 1; i++) {
                    if (node->children[i]->type == PatternType::LITERAL &&
                        node->children[i+1]->type == PatternType::LITERAL) {
                        
                        std::string lit1 = node->children[i]->value;
                        std::string lit2 = node->children[i+1]->value;
                        
                        // Check constraint preservation for merge
                        auto safety = checkSequenceMergeSafety(
                            lit1, lit2,
                            node->children[i]->matched_seeds,
                            node->children[i]->counter_seeds);
                        
                        if (safety.is_safe) {
                            std::string merged = lit1 + lit2;
                            auto merged_node = PatternNode::createLiteral(
                                merged, 
                                node->children[i]->matched_seeds, 
                                node->children[i]->counter_seeds);
                            merged_node->matched_seeds = node->children[i]->matched_seeds;
                            merged_node->counter_seeds = node->children[i]->counter_seeds;
                            
                            proof_log += "    [Sequence merge OK] '" + lit1 + "' + '" + 
                                        lit2 + "' -> '" + merged + "'\n";
                            
                            node->children[i] = merged_node;
                            node->children.erase(node->children.begin() + i + 1);
                            return node;
                        }
                    }
                }
            }
            
            // 5% chance to split a long literal
            if (chance_dist(rng) < 5) {
                for (size_t i = 0; i < node->children.size(); i++) {
                    if (node->children[i]->type == PatternType::LITERAL &&
                        node->children[i]->value.length() >= 4) {
                        
                        std::string val = node->children[i]->value;
                        size_t split = val.length() / 2;
                        
                        auto safety = checkSequenceSplitSafety(
                            val, split,
                            node->children[i]->matched_seeds,
                            node->children[i]->counter_seeds);
                        
                        if (safety.is_safe) {
                            auto first = PatternNode::createLiteral(
                                val.substr(0, split), 
                                node->children[i]->matched_seeds, 
                                node->children[i]->counter_seeds);
                            auto second = PatternNode::createLiteral(
                                val.substr(split), 
                                node->children[i]->matched_seeds,
                                node->children[i]->counter_seeds);
                            
                            first->matched_seeds = node->children[i]->matched_seeds;
                            first->counter_seeds = node->children[i]->counter_seeds;
                            second->matched_seeds = node->children[i]->matched_seeds;
                            second->counter_seeds = node->children[i]->counter_seeds;
                            
                            proof_log += "    [Sequence split OK] '" + val + "' -> '" + 
                                        val.substr(0, split) + "' + '" + val.substr(split) + "'\n";
                            
                            node->children[i] = first;
                            node->children.insert(node->children.begin() + i + 1, second);
                            return node;
                        }
                    }
                }
            }
            
            for (auto& child : node->children) {
                child = sequenceMergeUnmerge(child, rng, depth + 1, proof_log);
            }
            return node;
        }
            
        case PatternType::ALTERNATION: {
            for (auto& child : node->children) {
                child = sequenceMergeUnmerge(child, rng, depth + 1, proof_log);
            }
            return node;
        }
            
        case PatternType::PLUS_QUANTIFIER:
        case PatternType::STAR_QUANTIFIER:
        case PatternType::OPTIONAL: {
            if (node->quantified) {
                node->quantified = sequenceMergeUnmerge(node->quantified, rng, depth + 1, proof_log);
            }
            return node;
        }
            
        default:
            return node;
    }
}

// ============================================================================
// Rewrite: Add Extra Nesting
// Wrap expressions in redundant groups
// ============================================================================

std::shared_ptr<PatternNode> addExtraNesting(
    std::shared_ptr<PatternNode> node,
    std::mt19937& rng,
    int depth,
    std::string& proof_log) {
    
    if (!node || depth > 6) return node;
    
    std::uniform_int_distribution<int> chance_dist(0, 99);
    
    switch (node->type) {
        case PatternType::LITERAL: {
            // 6% chance to wrap literal in a sequence
            if (chance_dist(rng) < 6) {
                proof_log += "      [Nesting] Wrapped literal '" + node->value + "' in sequence\n";
                auto seq_node = PatternNode::createSequence(
                    {node}, node->matched_seeds, node->counter_seeds);
                seq_node->matched_seeds = node->matched_seeds;
                seq_node->counter_seeds = node->counter_seeds;
                return seq_node;
            }
            return node;
        }
            
        case PatternType::ALTERNATION: {
            // 5% chance to wrap alternation in a sequence
            if (chance_dist(rng) < 5) {
                proof_log += "      [Nesting] Wrapped alternation in sequence\n";
                auto seq_node = PatternNode::createSequence(
                    {node}, node->matched_seeds, node->counter_seeds);
                seq_node->matched_seeds = node->matched_seeds;
                seq_node->counter_seeds = node->counter_seeds;
                return seq_node;
            }
            
            for (auto& child : node->children) {
                child = addExtraNesting(child, rng, depth + 1, proof_log);
            }
            return node;
        }
            
        case PatternType::SEQUENCE: {
            // 4% chance to wrap in another sequence (double nesting)
            if (chance_dist(rng) < 4 && node->children.size() >= 2) {
                proof_log += "      [Nesting] Double-wrapped sequence\n";
                auto outer = PatternNode::createSequence(
                    {node}, node->matched_seeds, node->counter_seeds);
                outer->matched_seeds = node->matched_seeds;
                outer->counter_seeds = node->counter_seeds;
                return outer;
            }
            
            for (auto& child : node->children) {
                child = addExtraNesting(child, rng, depth + 1, proof_log);
            }
            return node;
        }
            
        case PatternType::PLUS_QUANTIFIER:
        case PatternType::STAR_QUANTIFIER:
        case PatternType::OPTIONAL: {
            if (node->quantified) {
                node->quantified = addExtraNesting(node->quantified, rng, depth + 1, proof_log);
            }
            return node;
        }
            
        default:
            return node;
    }
}

// ============================================================================
// Rewrite: Insert Empty Alternative
// Add empty option to alternations
// ============================================================================

std::shared_ptr<PatternNode> insertEmptyAlternative(
    std::shared_ptr<PatternNode> node,
    std::mt19937& rng,
    int depth) {
    
    if (!node || depth > 5) return node;
    
    // DISABLED: Empty alternative causes verification issues
    // The test framework expects all matched_seeds to be non-empty
    // Also c-dfa may not support empty alternatives in all contexts
    
    // Just recurse without adding empty alternatives
    switch (node->type) {
        case PatternType::ALTERNATION:
        case PatternType::SEQUENCE: {
            for (auto& child : node->children) {
                child = insertEmptyAlternative(child, rng, depth + 1);
            }
            return node;
        }
            
        case PatternType::PLUS_QUANTIFIER:
        case PatternType::STAR_QUANTIFIER:
        case PatternType::OPTIONAL: {
            if (node->quantified) {
                node->quantified = insertEmptyAlternative(node->quantified, rng, depth + 1);
            }
            return node;
        }
            
        default:
            return node;
    }
}

// ============================================================================
// Rewrite: Alternation Shuffling
// Randomly reorder alternatives
// ============================================================================

std::shared_ptr<PatternNode> shuffleAlternation(
    std::shared_ptr<PatternNode> node,
    std::mt19937& rng,
    int depth) {
    
    if (!node || depth > 5) return node;
    
    std::uniform_int_distribution<int> chance_dist(0, 99);
    
    switch (node->type) {
        case PatternType::ALTERNATION: {
            // 15% chance to shuffle this alternation
            if (chance_dist(rng) < 15 && node->children.size() >= 3) {
                // Shuffle children
                std::shuffle(node->children.begin(), node->children.end(), rng);
                // Also shuffle matched_seeds to keep correspondence
                std::shuffle(node->matched_seeds.begin(), node->matched_seeds.end(), rng);
            }
            
            for (auto& child : node->children) {
                child = shuffleAlternation(child, rng, depth + 1);
            }
            return node;
        }
            
        case PatternType::SEQUENCE: {
            for (auto& child : node->children) {
                child = shuffleAlternation(child, rng, depth + 1);
            }
            return node;
        }
            
        case PatternType::PLUS_QUANTIFIER:
        case PatternType::STAR_QUANTIFIER:
        case PatternType::OPTIONAL: {
            if (node->quantified) {
                node->quantified = shuffleAlternation(node->quantified, rng, depth + 1);
            }
            return node;
        }
            
        default:
            return node;
    }
}

// ============================================================================
// Apply all complex rewrites
// Returns pair of (modified_root, fragment_definitions)
// ============================================================================

std::pair<std::shared_ptr<PatternNode>, std::map<std::string, std::string>> applyComplexRewrites(
    std::shared_ptr<PatternNode> root, 
    std::mt19937& rng,
    std::string& proof_out) {
    
    std::string before = serializePattern(root);
    std::map<std::string, std::string> all_fragment_defs;
    
    // Apply character class introduction (with fragment tracking)
    std::map<std::string, std::string> fragment_defs;
    root = introduceCharClass(root, rng, 0, fragment_defs);
    std::string after_charclass = serializePattern(root);
    if (before != after_charclass) {
        proof_out += "  [Char class introduction]\n";
        proof_out += "    Pattern: " + before + " -> " + after_charclass + "\n";
        if (!fragment_defs.empty()) {
            proof_out += "    Fragments defined:\n";
            for (const auto& [name, def] : fragment_defs) {
                proof_out += "      " + name + " = " + def + "\n";
            }
            // Collect fragment definitions
            all_fragment_defs.insert(fragment_defs.begin(), fragment_defs.end());
        }
        before = after_charclass;
    }
    
    // Apply fragment extraction
    std::map<std::string, std::string> extract_defs;
    root = extractFragmentRewrite(root, rng, 0, extract_defs);
    std::string after_extract = serializePattern(root);
    if (before != after_extract) {
        proof_out += "  [Fragment extraction]\n";
        proof_out += "    Pattern: " + before + " -> " + after_extract + "\n";
        if (!extract_defs.empty()) {
            proof_out += "    Fragments extracted:\n";
            for (const auto& [name, def] : extract_defs) {
                proof_out += "      " + name + " = " + def + "\n";
            }
            all_fragment_defs.insert(extract_defs.begin(), extract_defs.end());
        }
        before = after_extract;
    }
    
    // Apply sequence merge/unmerge (DISABLED - causes constraint violations)
    // std::string merge_log;
    // root = sequenceMergeUnmerge(root, rng, 0, merge_log);
    
    // Apply extra nesting (DISABLED - verification issues)
    // root = addExtraNesting(root, rng, 0);
    
    // Apply empty alternative insertion (disabled - requires special empty-string handling)
    // root = insertEmptyAlternative(root, rng, 0);
    
    // Apply alternation shuffling
    root = shuffleAlternation(root, rng, 0);
    std::string after_shuffle = serializePattern(root);
    if (before != after_shuffle) {
        proof_out += "  [Alternation shuffle]\n";
        proof_out += "    Pattern: " + before + " -> " + after_shuffle + "\n";
        before = after_shuffle;
    }
    
    // Apply optional group insertion (DISABLED - complex constraint tracking)
    // std::string pre_optional = serializePattern(root);
    // std::string optional_log;
    // root = insertOptionalGroup(root, rng, 0, optional_log);
    
    // Apply extra nesting (DISABLED - creates structure that may not match all inputs)
    // std::string nest_log;
    // root = addExtraNesting(root, rng, 0, nest_log);
    
    // Apply nested quantifier creation
    root = createNestedQuantifiers(root, rng, 0);
    std::string after_nested = serializePattern(root);
    if (before != after_nested) {
        proof_out += "  [Nested quantifier creation]\n";
        proof_out += "    Pattern: " + before + " -> " + after_nested + "\n";
    }
    
    return {root, all_fragment_defs};
}

// Apply random star quantifier insertion
std::shared_ptr<PatternNode> applyRandomStars(std::shared_ptr<PatternNode> root, std::mt19937& rng) {
    return insertRandomStarQuantifier(root, rng, 0);
}

} // namespace PatternFactorization

// Main pattern generator - try all strategies
PatternResult generateSeparatingPattern(const std::vector<std::string>& matching,
                                        const std::vector<std::string>& counters,
                                        Complexity complexity,
                                        std::mt19937& rng) {
    PatternResult final_result;
    final_result.proof = "PROOF:\n";
    
    if (matching.empty()) {
        final_result.proof += "- No matching inputs provided\n";
        return final_result;
    }
    
    final_result.proof += "- Analyzing " + std::to_string(matching.size()) + " matching, " 
                 + std::to_string(counters.size()) + " counter inputs\n";
    
    // Try literal first if only one matching
    if (matching.size() == 1) {
        PatternResult r = tryLiteral(matching, counters, rng);
        if (!r.pattern.empty()) {
            final_result = r;
            final_result.proof = "PROOF:\n- SUCCESS with literal\n" + final_result.proof;
            // Apply edge cases with probability
            final_result = applyEdgeCases(final_result, matching, counters, rng);
            return final_result;
        }
    }
    
    // Try all strategies in random order and collect valid results
    std::vector<std::function<PatternResult(const std::vector<std::string>&,
                                            const std::vector<std::string>&,
                                            std::mt19937&)>> strategies;
    
    strategies.push_back(tryAlternation);
    strategies.push_back(tryRepetition);
    strategies.push_back(tryPrefixPlusFragment);
    strategies.push_back(trySuffixPlusFragment);
    strategies.push_back(tryTwoPartFragment);
    strategies.push_back(tryFragmentOnly);
    strategies.push_back(tryStarQuantifier);
    strategies.push_back(tryCharClassPlus);
    strategies.push_back(tryMixedQuantifiers);
    strategies.push_back(tryFragmentChaining);
    strategies.push_back(tryDeepNesting);
    strategies.push_back(tryComplexAlternation);
    strategies.push_back(tryAlternationWithQuantifier);
    strategies.push_back(trySequenceWithQuantifier);
    strategies.push_back(tryOptionalSequence);
    strategies.push_back(tryNestedQuantifiers);
    strategies.push_back(tryCharClassSequence);
    strategies.push_back(tryMultiFragmentCombo);
    strategies.push_back(tryNestedAlternation);
    strategies.push_back(tryQuantifierStack);
    strategies.push_back(tryLongAlternation);
    strategies.push_back(tryAltWithAffix);
    strategies.push_back(tryTripleQuant);
    
    // Shuffle
    std::shuffle(strategies.begin(), strategies.end(), rng);
    std::shuffle(strategies.begin(), strategies.end(), rng);
    
    // Collect ALL valid results
    std::vector<PatternResult> valid_results;
    for (auto& strategy : strategies) {
        PatternResult r = strategy(matching, counters, rng);
        if (!r.pattern.empty()) {
            valid_results.push_back(r);
        }
    }
    
    // If multiple valid, pick randomly (50/50 at each decision point)
    if (!valid_results.empty()) {
        std::uniform_int_distribution<int> dist(0, valid_results.size() - 1);
        final_result = valid_results[dist(rng)];
        final_result.proof = "PROOF:\n- SUCCESS (random choice from " + 
                             std::to_string(valid_results.size()) + " valid strategies):\n" + 
                             final_result.proof;
        // Apply edge cases with probability
        final_result = applyEdgeCases(final_result, matching, counters, rng);
        return final_result;
    }
    
    final_result.proof += "- All strategies failed\n";
    return final_result;
}

std::map<std::string, std::string> generateFragmentsForPattern(const std::string& pattern) {
    std::map<std::string, std::string> fragments;
    return fragments;
}

TestCase TestGenerator::generateTestCase(int test_id, std::set<std::string>& used_inputs) {
    TestCase tc;
    tc.test_id = test_id;
    
    // Assign random categories ensuring uniqueness within the batch
    // Use randomCategory() to test all 8 categories, not just a hardcoded subset
    // Must avoid: 
    // 1. Duplicate matching categories within the same batch
    // 2. Counter category matching any category already used in the batch
    
    static std::set<Category> batch_used_matching;
    static std::set<Category> batch_used_counter;
    
    // First test in batch? Clear the tracking sets
    if (test_id == 0) {
        batch_used_matching.clear();
        batch_used_counter.clear();
    }
    
    // Select a unique matching category not used in this batch
    do {
        tc.category = randomCategory();
    } while (batch_used_matching.count(tc.category) > 0);
    batch_used_matching.insert(tc.category);
    
    // Select a counter category not equal to any matching category in this batch
    // and not already used as a counter category
    do {
        tc.counter_category = randomCategory();
    } while (tc.counter_category == tc.category || 
             batch_used_matching.count(tc.counter_category) > 0 ||
             batch_used_counter.count(tc.counter_category) > 0);
    batch_used_counter.insert(tc.counter_category);
    
    tc.complexity = opts.complexity;
    tc.fragments.clear();
    
    // 5% chance to use edge-case coordinated seeding
    bool use_edge_case = (std::uniform_int_distribution<int>(0, 99)(rng) < 5);
    std::shared_ptr<PatternNode> edge_ast = nullptr;
    EdgeCaseResult edge;  // Declare outside to use in fragment handling
    
    if (use_edge_case) {
        // Randomly select an edge case type (skip NESTED_QUANTIFIER for now - creates conflicting expectations)
        std::uniform_int_distribution<int> edge_type_dist(0, 3);
        EdgeCaseType edge_types[] = {
            EdgeCaseType::RANGE_BOUNDARY,
            EdgeCaseType::PARTIAL_MATCH_FAIL,
            EdgeCaseType::QUANTIFIER_EDGE,
            EdgeCaseType::ALTERNATION_EDGE
        };
        EdgeCaseType selected_type = edge_types[edge_type_dist(rng)];
        
        edge = generateEdgeCase(selected_type, rng);
        
        // Use edge-case seeds
        tc.matching_inputs = edge.matching_seeds;
        tc.counter_inputs = edge.counter_seeds;
        edge_ast = edge.initial_ast;
        
        tc.proof += "\n=== EDGE CASE GENERATION ===\n";
        tc.proof += edge.proof;
        tc.proof += "\n";
    } else {
        // Normal random seeding
        auto [matching_seeds, counter_seeds] = generateSeeds(tc.complexity, used_inputs);
        tc.matching_inputs = matching_seeds;
        tc.counter_inputs = counter_seeds;
    }
    
    PatternResult result;
    
    std::map<std::string, std::string> edge_fragments;
    if (use_edge_case && edge_ast) {
        // Use edge-case AST directly
        result.ast = edge_ast;
        // Add fragment definitions from edge case
        for (const auto& frag : edge.fragments) {
            result.fragments[frag.first] = frag.second;
        }
    } else {
        // Use InductiveBuilder as primary approach
        InductiveBuilder::BuildResult ib_result = InductiveBuilder::buildInductive(
            tc.matching_inputs, tc.counter_inputs, rng);
        
        if (ib_result.success && ib_result.ast) {
            result.ast = ib_result.ast;
            result.pattern = serializePattern(ib_result.ast);
            result.proof = ib_result.proof;
        } else {
            // Fallback to old approach if InductiveBuilder fails
            PatternResult fallback = generateSeparatingPattern(tc.matching_inputs, tc.counter_inputs, tc.complexity, rng);
            result = fallback;
        }
    }

    // Skip rewritePattern for now
    
    tc.pattern = result.pattern;
    tc.fragments = result.fragments;
    
    // Apply factorization to create more compact patterns
    if (!use_edge_case || !edge_ast) {
        std::string before = serializePattern(result.ast);
        int before_match = result.ast ? result.ast->matched_seeds.size() : 0;
        int before_counters = result.ast ? result.ast->counter_seeds.size() : 0;
        
        result.proof += "  [Pre-transformation]\n";
        result.proof += "    Pattern: " + before + "\n";
        result.proof += "    Constraint: must-match(" + std::to_string(before_match) + "), must-not-match(" + std::to_string(before_counters) + ")\n";
        
        // Apply factorization with detailed proof generation
        FactorizationProof factor_proof;
        factor_proof.before = before;
        
        result.ast = PatternFactorization::applyFactorization(result.ast, rng, &factor_proof);
        std::string after_factor = serializePattern(result.ast);
        int after_match = result.ast ? result.ast->matched_seeds.size() : 0;
        int after_counters = result.ast ? result.ast->counter_seeds.size() : 0;
        
        if (before != after_factor) {
            result.proof += "  [Factorization]\n";
            result.proof += "    Before: " + before + "\n";
            result.proof += "    After:  " + after_factor + "\n";
            result.proof += "    Constraint: must-match(" + std::to_string(after_match) + "), must-not-match(" + std::to_string(after_counters) + ")\n";
            
            // DEBUG: Add any debug info from factorization
            if (!factor_proof.before.empty() && factor_proof.before.substr(0, 3) == "WZ_") {
                result.proof += "    DEBUG: " + factor_proof.before + "\n";
            }
            if (!factor_proof.after.empty() && factor_proof.after.substr(0, 5) == "LOST:") {
                result.proof += "    DEBUG: " + factor_proof.after + "\n";
            }
            
            // Generate detailed per-input derivation proof
            result.proof += "\n    DERIVATION (per input):\n";
            
            // Parse the before pattern to understand structure
            std::vector<std::string> before_alts;
            std::string before_clean = before;
            if (before_clean.size() >= 2 && before_clean.front() == '(' && before_clean.back() == ')') {
                before_clean = before_clean.substr(1, before_clean.size() - 2);
            }
            
            // Split by | at depth 0
            size_t start = 0;
            int depth = 0;
            for (size_t i = 0; i < before_clean.size(); i++) {
                if (before_clean[i] == '(') depth++;
                else if (before_clean[i] == ')') depth--;
                else if (before_clean[i] == '|' && depth == 0) {
                    before_alts.push_back(before_clean.substr(start, i - start));
                    start = i + 1;
                }
            }
            before_alts.push_back(before_clean.substr(start));
            
            // For each matching input, trace how it maps through factorization
            int valid_count = 0;
            int invalid_count = 0;
            
            for (const auto& input : result.ast->matched_seeds) {
                // Find which original alternative this input came from
                std::string original_alt;
                for (const auto& alt : before_alts) {
                    if (input == alt) {
                        original_alt = alt;
                        break;
                    }
                }
                
                if (original_alt.empty()) {
                    result.proof += "      ? '" + input + "': Cannot trace to original alternative\n";
                    invalid_count++;
                    continue;
                }
                
                // Use recursive matching function that handles nested patterns
                bool found_match = wouldInputMatchPattern(input, after_factor);
                
                if (found_match) {
                    result.proof += "      ✓ '" + input + "': matches pattern\n";
                    valid_count++;
                } else {
                    result.proof += "      ✗ '" + input + "': does NOT match pattern\n";
                    result.proof += "        Original: '" + original_alt + "'\n";
                    invalid_count++;
                }
            }
            
            result.proof += "\n    VALIDATION: " + std::to_string(valid_count) + "/" + 
                          std::to_string(after_match) + " inputs valid\n";
            
            if (invalid_count > 0) {
                result.proof += "    STATUS: FACTORIZATION BUG DETECTED - " + 
                              std::to_string(invalid_count) + " input(s) don't match factored pattern\n";
            } else {
                result.proof += "    STATUS: All inputs verified to match\n";
            }
        }
        
        // Apply complex rewrites (char classes, optional groups, nested quantifiers)
        std::string pre_complex = serializePattern(result.ast);
        auto [rewritten_ast, fragment_defs] = PatternFactorization::applyComplexRewrites(
            result.ast, rng, result.proof);
        result.ast = rewritten_ast;
        // Add any fragment definitions to BOTH result and tc
        for (const auto& [name, def] : fragment_defs) {
            result.fragments[name] = def;
            tc.fragments[name] = def;  // Also add to tc for pattern file output
        }
        std::string after_complex = serializePattern(result.ast);
        
        // Apply random star quantifier insertion (20% chance to trigger)
        // DEEP COPY the AST before star insertion for comparison
        std::string pre_star_pattern = serializePattern(result.ast);
        std::shared_ptr<PatternNode> pre_star_ast = PatternFactorization::copyPatternNode(result.ast);  // Deep copy!
        
        result.ast = PatternFactorization::applyRandomStars(result.ast, rng);
        std::string after_stars = serializePattern(result.ast);
        
        if (pre_star_pattern != after_stars) {
            // Use AST comparison to detect specific star insertions
            std::string star_details = PatternFactorization::detectStarInsertions(
                pre_star_ast, result.ast, "root");
            
            result.proof += "  [Star insertion]\n";
            result.proof += "    Pattern: " + pre_star_pattern + " -> " + after_stars + "\n";
            if (!star_details.empty()) {
                result.proof += star_details;
            } else {
                result.proof += "    (Star transformations detected but structure differed)\n";
            }
        }
        
        tc.pattern = after_stars;
    }
    
    // Use the AST's matched_seeds which contains all inputs that validly match
    if (result.ast && !result.ast->matched_seeds.empty()) {
        tc.matching_inputs = result.ast->matched_seeds;
    }
    
    // Generate expectations from the AST (uses matched_seeds annotations)
    tc.expectations = generateExpectationsFromAST(result.ast, tc.fragments,
                                                   tc.matching_inputs, tc.counter_inputs);
    
    if (tc.pattern.empty()) {
        result.proof += "\n[FAILED] Could not generate separating pattern\n";
    }
    
    tc.proof = result.proof;
    
    return tc;
}

Category TestGenerator::randomCategory() {
    std::uniform_int_distribution<int> dist(1, 8);
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

std::pair<std::vector<std::string>, std::vector<std::string>> 
TestGenerator::generateInputs(Complexity complexity) {
    std::set<std::string> empty_set;
    return generateSeeds(complexity, empty_set);
}

std::map<std::string, std::string> TestGenerator::generateFragments(Complexity complexity) {
    return {};
}

std::string TestGenerator::generateSimpleArg() {
    return "";
}

std::string TestGenerator::generateFlags(int count) {
    return "";
}

std::string TestGenerator::generatePath() {
    return "";
}

std::string TestGenerator::generatePattern(const std::vector<std::string>& matching_inputs, 
                                           const std::vector<std::string>& counter_inputs,
                                           const std::map<std::string, std::string>& fragments,
                                           Complexity complexity,
                                           std::string& proof_out) {
    PatternResult result = generateSeparatingPattern(matching_inputs, counter_inputs, complexity, rng);
    proof_out = result.proof;
    return result.pattern;
}

std::string TestGenerator::transformPart(const std::string& part,
                                        const std::map<std::string, std::string>& fragments,
                                        Complexity complexity,
                                        bool allow_wildcard,
                                        const std::vector<std::string>& counter_inputs,
                                        const std::string& current_pattern,
                                        std::string& proof_out) {
    proof_out = "no transformation";
    return part;
}

bool TestGenerator::wouldMatchWithoutOptional(const std::string& pattern_prefix, const std::string& counter_input) {
    return false;
}

bool TestGenerator::wouldMatchWithAlternation(const std::string& pattern_prefix, const std::string& literal_part, const std::string& counter_input) {
    return false;
}

std::string TestGenerator::makeLiteralPattern(const std::vector<std::string>& parts) {
    std::string result;
    for (const auto& p : parts) {
        if (!result.empty()) result += " ";
        result += p;
    }
    return result;
}

std::string TestGenerator::makeMediumPattern(const std::vector<std::string>& parts, const std::map<std::string, std::string>& fragments) {
    return makeLiteralPattern(parts);
}

std::string TestGenerator::makeComplexPattern(const std::vector<std::string>& parts, const std::map<std::string, std::string>& fragments) {
    return makeLiteralPattern(parts);
}

std::vector<std::string> TestGenerator::generateCounterInputsSimple(const std::string& arg, const std::string& cmd) {
    return {};
}

std::vector<std::string> TestGenerator::generateCounterInputsMedium(const std::string& flags, const std::string& arg, const std::string& cmd) {
    return {};
}

std::vector<std::string> TestGenerator::generateCounterInputsComplex(const std::string& flags, const std::vector<std::string>& args, const std::string& cmd) {
    return {};
}

bool TestGenerator::wouldPatternMatch(const std::string& input, const std::string& pattern) {
    return false;
}

void TestGenerator::writePatternFile(const std::vector<TestCase>& tests, const std::string& filename) {
    std::ofstream out(filename);
    out << "# Auto-generated test patterns\n\n";
    
    std::map<std::string, std::string> all_fragments;
    for (const auto& tc : tests) {
        for (const auto& f : tc.fragments) {
            if (all_fragments.find(f.first) == all_fragments.end()) {
                all_fragments[f.first] = f.second;
            }
        }
    }
    
    if (!all_fragments.empty()) {
        out << "# Fragment definitions\n";
        for (const auto& f : all_fragments) {
            out << "[fragment:" << f.first << "] " << f.second << "\n";
        }
        out << "\n";
    }
    
    // Write [CATEGORIES] section (0-indexed)
    out << "[CATEGORIES]\n";
    out << "0: safe\n";
    out << "1: caution\n";
    out << "2: modifying\n";
    out << "3: dangerous\n";
    out << "4: network\n";
    out << "5: admin\n";
    out << "6: build\n";
    out << "7: container\n";
    out << "\n";
    
    out << "# Patterns\n";
    for (const auto& tc : tests) {
        if (!tc.pattern.empty()) {
            // Write pattern with its category
            out << "[" << categoryToString(tc.category) << ":test" << tc.test_id << "] " << tc.pattern << "\n";
        }
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
        out << "    \"counter_category\": \"" << categoryToString(tc.counter_category) << "\",\n";
        out << "    \"matching_inputs\": [";
        for (size_t j = 0; j < tc.matching_inputs.size(); j++) {
            if (j > 0) out << ", ";
            out << "\"" << tc.matching_inputs[j] << "\"";
        }
        out << "],\n";
        out << "    \"counter_inputs\": [";
        for (size_t j = 0; j < tc.counter_inputs.size(); j++) {
            if (j > 0) out << ", ";
            out << "\"" << tc.counter_inputs[j] << "\"";
        }
        out << "],\n";
        out << "    \"proof\": \"";
        for (size_t p = 0; p < tc.proof.size(); p++) {
            char c = tc.proof[p];
            if (c == '\n') out << "\\n";
            else if (c == '"') out << "\\\"";
            else out << c;
        }
        out << "\",\n";
        out << "    \"complexity\": \"";
        switch (tc.complexity) {
            case Complexity::SIMPLE: out << "simple"; break;
            case Complexity::MEDIUM: out << "medium"; break;
            case Complexity::COMPLEX: out << "complex"; break;
        }
        out << "\",\n";
        out << "    \"fragments\": {";
        bool first_frag = true;
        for (const auto& f : tc.fragments) {
            if (!first_frag) out << ", ";
            out << "\"" << f.first << "\": \"" << f.second << "\"";
            first_frag = false;
        }
        out << "},\n";
        out << "    \"expectations\": [\n";
        for (size_t e = 0; e < tc.expectations.size(); e++) {
            const auto& exp = tc.expectations[e];
            out << "      {\n";
            out << "        \"type\": \"" << expectationTypeToString(exp.type) << "\",\n";
            out << "        \"input\": \"";
            for (size_t p = 0; p < exp.input.size(); p++) {
                char c = exp.input[p];
                if (c == '"') out << "\\\"";
                else out << c;
            }
            out << "\",\n";
            out << "        \"expected_match\": \"" << exp.expected_match << "\",\n";
            out << "        \"description\": \"";
            for (size_t p = 0; p < exp.description.size(); p++) {
                char c = exp.description[p];
                if (c == '"') out << "\\\"";
                else out << c;
            }
            out << "\",\n";
            out << "        \"meta\": {";
            bool first_meta = true;
            for (const auto& m : exp.meta) {
                if (!first_meta) out << ", ";
                out << "\"" << m.first << "\": \"";
                for (size_t p = 0; p < m.second.size(); p++) {
                    char c = m.second[p];
                    if (c == '"') out << "\\\"";
                    else out << c;
                }
                out << "\"";
                first_meta = false;
            }
            out << "}\n";
            out << "      }";
            if (e < tc.expectations.size() - 1) out << ",";
            out << "\n";
        }
        out << "    ]\n";
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
    
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == nullptr) {
        std::cerr << "Cannot get current directory\n";
        return 1;
    }
    std::string abs_cwd = cwd;
    std::string abs_pattern = abs_cwd + "/" + pattern_file;
    std::string output_dir = abs_pattern.substr(0, abs_pattern.rfind('/'));
    
    std::string tools_dir = getToolsDir();
    
    std::cout << "1. Building NFA...\n";
    std::string nfa_file = output_dir + "/test.nfa";
    std::string nfa_cmd = tools_dir + "/nfa_builder " + abs_pattern + " " + nfa_file + " 2>&1";
    int result = system(nfa_cmd.c_str());
    if (result != 0) {
        std::cerr << "NFA builder failed!\n";
        return 1;
    }
    std::cout << "   NFA built successfully\n\n";
    
    std::cout << "2. Building DFA...\n";
    std::string dfa_file = output_dir + "/test.dfa";
    result = system((tools_dir + "/nfa2dfa_advanced " + nfa_file + " " + dfa_file + " 2>&1").c_str());
    if (result != 0) {
        std::cerr << "DFA builder failed!\n";
        return 1;
    }
    std::cout << "   DFA built successfully\n\n";
    
    std::cout << "3. Testing patterns...\n";
    
    std::vector<TestCase>& tests = generated_tests;
    int passed = 0;
    int failed = 0;
    int skipped = 0;
    
    for (size_t i = 0; i < tests.size(); i++) {
        const auto& tc = tests[i];
        
        if (tc.pattern.empty()) {
            std::cout << "   SKIP #" << i << ": no pattern generated\n";
            skipped++;
            continue;
        }
        
        int expected_match_category = static_cast<int>(tc.category) - 1;
        int expected_counter_category = static_cast<int>(tc.counter_category) - 1;
        
        // Check: matching inputs MUST match with the MATCHING category
        bool all_matched = true;
        std::string match_fail_reason;
        for (const auto& match_in : tc.matching_inputs) {
            std::string cmd = tools_dir + "/dfa_eval_wrapper " + dfa_file + " \"" + match_in + "\"";
            CommandResult res = runCommand(cmd);
            
            if (res.exit_code != 0) {
                all_matched = false;
                match_fail_reason = "exit_code=" + std::to_string(res.exit_code);
                break;
            }
            
            bool matched = false;
            int category_mask = 0;
            
            // Parse stdout for matched, category, and category_mask
            // DEBUG: Print the actual stdout to diagnose parsing issues
            if (res.stdout.empty()) {
                all_matched = false;
                match_fail_reason = "stdout was empty";
                break;
            }
            
            size_t match_pos = res.stdout.find("matched=1");
            if (match_pos != std::string::npos) {
                matched = true;
            }
            
            // Parse reported category (1-indexed: 1=SAFE, 2=CAUTION, etc.)
            int reported_category = 0;
            size_t cat_pos = res.stdout.find("category=");
            if (cat_pos != std::string::npos) {
                std::string cat_str = res.stdout.substr(cat_pos + 9);
                size_t end_pos = cat_str.find(' ');
                if (end_pos == std::string::npos) end_pos = cat_str.find('(');
                if (end_pos != std::string::npos) cat_str = cat_str.substr(0, end_pos);
                reported_category = atoi(cat_str.c_str());
            }
            
            // Parse category_mask
            size_t mask_pos = res.stdout.find("category_mask=0x");
            if (mask_pos != std::string::npos) {
                std::string mask_str = res.stdout.substr(mask_pos + 16);  // "category_mask=0x" is 16 chars
                // Extract hex value up to space or end
                size_t end_pos = mask_str.find(' ');
                if (end_pos != std::string::npos) {
                    mask_str = mask_str.substr(0, end_pos);
                }
                category_mask = (int)strtol(mask_str.c_str(), nullptr, 16);
            }
            

            
            int category_bit = (1 << expected_match_category);
            bool mask_has_expected = (category_mask & category_bit);
            bool category_matches = (reported_category == (expected_match_category + 1));
            
            // Count bits in mask to detect multiple matches
            int mask_bits = __builtin_popcount((unsigned int)category_mask);
            
            // Check consistency between category and category_mask
            bool consistent = true;
            if (matched && reported_category > 0) {
                // Category value should correspond to a bit in the mask
                if (reported_category >= 1 && reported_category <= 8) {
                    int expected_bit = reported_category - 1;
                    if ((category_mask & (1 << expected_bit)) == 0) {
                        consistent = false;
                    }
                } else {
                    consistent = false;  // Invalid category value
                }
            }
            
            // FAIL if: not matched, or expected bit not in mask
            if (!matched || !mask_has_expected) {
                all_matched = false;
                char mask_hex[16];
                snprintf(mask_hex, sizeof(mask_hex), "0x%02x", category_mask);
                match_fail_reason = "matched=" + std::to_string(matched) + 
                    ", category=" + std::to_string(reported_category) + 
                    ", category_mask=" + std::string(mask_hex);
                break;
            }
            
            // If multiple patterns can match (multiple bits in mask), don't fail on category mismatch
            // The expected category is in the mask, which is sufficient for multi-match cases
            if (mask_bits > 1 && !category_matches && mask_has_expected) {
                // Multiple patterns match - this is valid, just log a note
                // Don't fail - the expected bit IS in the mask
            } else if (!category_matches) {
                all_matched = false;
                char mask_hex[16];
                snprintf(mask_hex, sizeof(mask_hex), "0x%02x", category_mask);
                match_fail_reason = "INCONSISTENCY: category=" + std::to_string(reported_category) + 
                    " but mask has bit for " + std::to_string(expected_match_category + 1) +
                    " (mask=" + std::string(mask_hex) + ")";
                break;
            }
            
            // Also fail if category and mask are inconsistent
            if (!consistent) {
                all_matched = false;
                char mask_hex[16];
                snprintf(mask_hex, sizeof(mask_hex), "0x%02x", category_mask);
                match_fail_reason = "INCONSISTENCY: category=" + std::to_string(reported_category) + 
                    " but mask=0x" + std::string(mask_hex);
                break;
            }
        }
        
        if (!all_matched) { 
            std::cout << "   FAIL #" << i << ": matching inputs didn't match with correct category";
            if (!match_fail_reason.empty()) {
                std::cout << " (" << match_fail_reason << ")";
            }
            std::cout << "\n";
            failed++;
            global_failed_count++;
            
            // Save failed test case
            std::string fail_file = output_dir + "/failed_case_" + std::to_string(global_failed_count) + ".json";
            std::ofstream ff(fail_file);
            ff << "{\n";
            ff << "  \"batch_file\": \"" << pattern_file << "\",\n";
            ff << "  \"test_id\": " << tc.test_id << ",\n";
            ff << "  \"pattern\": \"[" << categoryToString(tc.category) << ":test" << tc.test_id << "] " << tc.pattern << "\",\n";
            ff << "  \"category\": \"" << categoryToString(tc.category) << "\",\n";
            ff << "  \"counter_category\": \"" << categoryToString(tc.counter_category) << "\",\n";
            ff << "  \"matching_inputs\": [";
            for (size_t j = 0; j < tc.matching_inputs.size(); j++) {
                if (j > 0) ff << ", ";
                ff << "\"" << tc.matching_inputs[j] << "\"";
            }
            ff << "],\n";
            ff << "  \"counter_inputs\": [";
            for (size_t j = 0; j < tc.counter_inputs.size(); j++) {
                if (j > 0) ff << ", ";
                ff << "\"" << tc.counter_inputs[j] << "\"";
            }
            ff << "],\n";
            ff << "  \"error\": \"matching inputs did not match with correct category\"\n";
            ff << "}\n";
            ff.close();
            std::cout << "   Saved: " << fail_file << "\n";
            continue; 
        }
        
        // Check: counter inputs must NOT match with the matching category
        // (they may match with the counter category, which is fine)
        bool any_counter_matched = false;
        std::string counter_fail_reason;
        for (const auto& counter : tc.counter_inputs) {
            std::string counter_cmd = tools_dir + "/dfa_eval_wrapper " + dfa_file + " \"" + counter + "\"";
            CommandResult res = runCommand(counter_cmd);
            
            if (res.exit_code != 0) {
                any_counter_matched = true;  // Treat as failure
                counter_fail_reason = "exit_code=" + std::to_string(res.exit_code);
                break;
            }
            
            int last_counter_cat = 0;
            size_t cat_pos = res.stdout.find("category=");
            if (cat_pos != std::string::npos) {
                std::string cat_str = res.stdout.substr(cat_pos + 9);
                // Extract number up to space or parenthesis
                size_t end_pos = cat_str.find(' ');
                if (end_pos == std::string::npos) end_pos = cat_str.find('(');
                if (end_pos != std::string::npos) {
                    cat_str = cat_str.substr(0, end_pos);
                }
                last_counter_cat = atoi(cat_str.c_str());
            }
            // Counter input should NOT match with the matching category
            // Note: last_counter_cat is 1-indexed (from DFA), expected_match_category is 0-indexed
            if (last_counter_cat == expected_match_category + 1) any_counter_matched = true;
        }
        
        if (!any_counter_matched) {
            // Verify deep semantic expectations
            bool expectations_passed = true;
            std::string expectation_fail_reason;
            
            for (const auto& exp : tc.expectations) {
                std::string test_input = exp.input;
                
                if (exp.input.find("[[FRAGMENT:") != std::string::npos) {
                    continue;
                }
                if (exp.input == "[[CAPTURE_TEST]]") {
                    if (!tc.matching_inputs.empty()) {
                        test_input = tc.matching_inputs[0];
                    } else {
                        continue;
                    }
                }
                
                std::string cmd = tools_dir + "/dfa_eval_wrapper " + dfa_file + " \"" + test_input + "\"";
                CommandResult res = runCommand(cmd);
                
                // Check for errors (ignore LOADING DFA debug messages)
                if (res.exit_code != 0) {
                    expectations_passed = false;
                    expectation_fail_reason = "exit_code=" + std::to_string(res.exit_code) + ", stderr=" + res.stderr;
                    break;
                }
                bool matched = false;
                int matched_category = 0;
                
                // Parse stdout
                if (res.stdout.find("matched=1") != std::string::npos) {
                    matched = true;
                }
                size_t cat_pos = res.stdout.find("category=");
                if (cat_pos != std::string::npos) {
                    std::string cat_str = res.stdout.substr(cat_pos + 9);
                    size_t end_pos = cat_str.find(' ');
                    if (end_pos == std::string::npos) end_pos = cat_str.find('(');
                    if (end_pos != std::string::npos) {
                        cat_str = cat_str.substr(0, end_pos);
                    }
                    matched_category = atoi(cat_str.c_str());
                }
                
                bool expected_match = (exp.expected_match == "yes");
                
                // For quantifier expectations, check if it matches any valid category
                // Not just the specific pattern's category (since other patterns may also match)
                if (exp.type == ExpectationType::QUANTIFIER_STAR_EMPTY || 
                    exp.type == ExpectationType::QUANTIFIER_PLUS_MINONE) {
                    // For STAR_EMPTY: empty string should match if ANY * pattern exists
                    // For PLUS_MINONE: empty should NOT match the + pattern
                    if (exp.type == ExpectationType::QUANTIFIER_STAR_EMPTY) {
                        // Empty string should match with SOME category (any * pattern)
                        if (expected_match && !matched) {
                            expectations_passed = false;
                            expectation_fail_reason = "Expectation failed: type=" + expectationTypeToString(exp.type) + 
                                ", input='" + test_input + "', expected=" + exp.expected_match + 
                                ", got no match, desc=" + exp.description;
                            break;
                        }
                    } else {
                        // PLUS_MINONE: empty should NOT match with THIS pattern's category
                        // Note: matched_category is 1-indexed from DFA, tc.category is also 1-indexed
                        int exp_cat = static_cast<int>(tc.category);
                        bool matched_this_category = matched && (matched_category == exp_cat);
                        
                        if (expected_match && !matched_this_category) {
                            expectations_passed = false;
                            expectation_fail_reason = "Expectation failed: type=" + expectationTypeToString(exp.type) + 
                                ", input='" + test_input + "', expected=" + exp.expected_match + 
                                ", got category=" + std::to_string(matched_category) + 
                                ", desc=" + exp.description;
                            break;
                        } else if (!expected_match && matched_this_category) {
                            expectations_passed = false;
                            expectation_fail_reason = "Expectation failed: type=" + expectationTypeToString(exp.type) + 
                                ", input='" + test_input + "', expected=" + exp.expected_match + 
                                ", got category=" + std::to_string(matched_category) + 
                                ", desc=" + exp.description;
                            break;
                        }
                    }
                } else {
                    // Original logic for other expectation types
                    if (matched != expected_match) {
                        expectations_passed = false;
                        expectation_fail_reason = "Expectation failed: type=" + expectationTypeToString(exp.type) + 
                            ", input='" + test_input + "', expected=" + exp.expected_match + 
                            ", got=" + (matched ? "yes" : "no") + ", desc=" + exp.description;
                        break;
                    }
                }
            }
            
            if (!expectations_passed) {
                std::cout << "   FAIL #" << i << ": " << expectation_fail_reason << "\n";
                failed++;
                global_failed_count++;
                
                std::string fail_file = output_dir + "/failed_case_" + std::to_string(global_failed_count) + ".json";
                std::ofstream ff(fail_file);
                ff << "{\n";
                ff << "  \"batch_file\": \"" << pattern_file << "\",\n";
                ff << "  \"test_id\": " << tc.test_id << ",\n";
                ff << "  \"pattern\": \"" << tc.pattern << "\",\n";
                ff << "  \"category\": \"" << categoryToString(tc.category) << "\",\n";
                ff << "  \"error\": \"" << expectation_fail_reason << "\",\n";
                ff << "  \"expectations\": [\n";
                for (size_t e = 0; e < tc.expectations.size(); e++) {
                    const auto& exp = tc.expectations[e];
                    ff << "    {\"type\": \"" << expectationTypeToString(exp.type) << "\", ";
                    ff << "\"input\": \"" << exp.input << "\", ";
                    ff << "\"expected\": \"" << exp.expected_match << "\"}\n";
                }
                ff << "  ]\n";
                ff << "}\n";
                ff.close();
                std::cout << "   Saved: " << fail_file << "\n";
            } else {
                passed++;
            }
        } else {
            std::cout << "   FAIL #" << i << ": counter input matched with matching category\n";
            failed++;
            global_failed_count++;
            
            // Save failed test case
            std::string fail_file = output_dir + "/failed_case_" + std::to_string(global_failed_count) + ".json";
            std::ofstream ff(fail_file);
            ff << "{\n";
            ff << "  \"batch_file\": \"" << pattern_file << "\",\n";
            ff << "  \"test_id\": " << tc.test_id << ",\n";
            ff << "  \"pattern\": \"[" << categoryToString(tc.category) << ":test" << tc.test_id << "] " << tc.pattern << "\",\n";
            ff << "  \"category\": \"" << categoryToString(tc.category) << "\",\n";
            ff << "  \"counter_category\": \"" << categoryToString(tc.counter_category) << "\",\n";
            ff << "  \"matching_inputs\": [";
            for (size_t j = 0; j < tc.matching_inputs.size(); j++) {
                if (j > 0) ff << ", ";
                ff << "\"" << tc.matching_inputs[j] << "\"";
            }
            ff << "],\n";
            ff << "  \"counter_inputs\": [";
            for (size_t j = 0; j < tc.counter_inputs.size(); j++) {
                if (j > 0) ff << ", ";
                ff << "\"" << tc.counter_inputs[j] << "\"";
            }
            ff << "],\n";
            ff << "  \"error\": \"counter inputs matched with matching category\"\n";
            ff << "}\n";
            ff.close();
            std::cout << "   Saved: " << fail_file << "\n";
        }
    }
    
    std::cout << "\nResults: " << passed << " passed, " << failed << " failed, " << skipped << " skipped\n";
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
    std::string failed_dir = output_dir + "/failed_cases";
    
    // Create failed_cases directory
    mkdir(failed_dir.c_str(), 0755);
    
    std::vector<TestCase>& tests = generated_tests;
    int passed = 0;
    int failed = 0;
    int skipped = 0;
    static int failed_count = 0;
    failed_count = 0;
    
    for (size_t i = 0; i < tests.size(); i++) {
        const auto& tc = tests[i];
        
        if (tc.pattern.empty()) {
            std::cout << "   SKIP #" << i << ": no pattern generated\n";
            skipped++;
            continue;
        }
        
        std::string temp_pattern = output_dir + "/temp_pattern.txt";
        std::ofstream tp(temp_pattern);
        for (const auto& f : tc.fragments) {
            tp << "[fragment:" << f.first << "] " << f.second << "\n";
        }
        tp << "[" << categoryToString(tc.category) << "] " << tc.pattern << "\n";
        tp.close();
        
        std::string nfa_file = output_dir + "/temp.nfa";
        std::string dfa_file = output_dir + "/temp.dfa";
        
        std::string tools_dir = getToolsDir();
        CommandResult nfa_res = runCommand(tools_dir + "/nfa_builder " + temp_pattern + " " + nfa_file);
        if (nfa_res.exit_code != 0 || !nfa_res.stderr.empty()) { 
            std::cout << "   FAIL #" << i << ": nfa_builder failed (exit=" << nfa_res.exit_code << ")\n";
            failed++; 
            continue; 
        }
        
        CommandResult dfa_res = runCommand(tools_dir + "/nfa2dfa_advanced " + nfa_file + " " + dfa_file);
        if (dfa_res.exit_code != 0 || !dfa_res.stderr.empty()) { 
            std::cout << "   FAIL #" << i << ": nfa2dfa_advanced failed (exit=" << dfa_res.exit_code << ")\n";
            failed++; 
            continue; 
        }
        
        bool all_matched = true;
        int expected_category_0idx = static_cast<int>(tc.category) - 1;  // Convert 1-indexed to 0-indexed
        for (const auto& match_in : tc.matching_inputs) {
            CommandResult res = runCommand(tools_dir + "/dfa_eval_wrapper " + dfa_file + " \"" + match_in + "\"");
            
            // Check for errors (ignore LOADING DFA debug messages)
            if (res.exit_code != 0) {
                std::cout << "   FAIL #" << i << ": dfa_eval_wrapper error (exit=" << res.exit_code << ")\n";
                all_matched = false;
                break;
            }
            
            bool matched = false;
            int matched_category = 0;
            int category_mask = 0;
            
            // Parse stdout
            if (res.stdout.find("matched=1") != std::string::npos) {
                matched = true;
            }
            
            // Parse reported category (1-indexed from DFA)
            size_t cat_pos = res.stdout.find("category=");
            if (cat_pos != std::string::npos) {
                std::string cat_str = res.stdout.substr(cat_pos + 9);
                size_t end_pos = cat_str.find(' ');
                if (end_pos == std::string::npos) end_pos = cat_str.find('(');
                if (end_pos != std::string::npos) {
                    cat_str = cat_str.substr(0, end_pos);
                }
                matched_category = atoi(cat_str.c_str());
            }
            
            // Parse category_mask
            size_t mask_pos = res.stdout.find("category_mask=0x");
            if (mask_pos != std::string::npos) {
                std::string mask_str = res.stdout.substr(mask_pos + 16);
                size_t end_pos = mask_str.find(' ');
                if (end_pos != std::string::npos) mask_str = mask_str.substr(0, end_pos);
                category_mask = (int)strtol(mask_str.c_str(), nullptr, 16);
            }
            
            // Dual-verification: check both mask and category consistency
            int category_bit = (1 << expected_category_0idx);
            bool mask_has_expected = (category_mask & category_bit);
            bool category_matches = (matched_category == static_cast<int>(tc.category));
            
            // Count bits in mask to detect multiple matches
            int mask_bits = __builtin_popcount((unsigned int)category_mask);
            
            // Check consistency
            bool consistent = true;
            if (matched && matched_category > 0) {
                if (matched_category >= 1 && matched_category <= 8) {
                    int expected_bit = matched_category - 1;
                    if ((category_mask & (1 << expected_bit)) == 0) {
                        consistent = false;
                    }
                } else {
                    consistent = false;
                }
            }
            
            if (!matched || !mask_has_expected) {
                std::cout << "   FAIL #" << i << ": matched=" << matched << ", category=" << matched_category << ", category_mask=0x" << std::hex << category_mask << std::dec << "\n";
                all_matched = false;
                break;
            }
            
            // If multiple patterns can match (multiple bits in mask), don't fail on category mismatch
            if (mask_bits > 1 && !category_matches && mask_has_expected) {
                // Multiple patterns match - this is valid
            } else if (!category_matches || !consistent) {
                std::cout << "   FAIL #" << i << ": INCONSISTENCY - category=" << matched_category << " but expected " << static_cast<int>(tc.category) << " (mask=0x" << std::hex << category_mask << std::dec << ")\n";
                all_matched = false;
                break;
            }
        }
        
        bool any_counter_matched = false;
        for (const auto& counter : tc.counter_inputs) {
            CommandResult res = runCommand(tools_dir + "/dfa_eval_wrapper " + dfa_file + " \"" + counter + "\"");
            
            // Check for errors (ignore LOADING DFA debug messages)
            bool is_debug_only = (res.stderr.find("LOADING DFA:") != std::string::npos);
            if (res.exit_code != 0 || (!is_debug_only && !res.stderr.empty())) {
                any_counter_matched = true;  // Treat error as failure
                break;
            }
            
            int counter_cat = 0;
            size_t ccat_pos = res.stdout.find("category=");
            if (ccat_pos != std::string::npos) {
                std::string cat_str = res.stdout.substr(ccat_pos + 9);
                size_t end_pos = cat_str.find(' ');
                if (end_pos == std::string::npos) end_pos = cat_str.find('(');
                if (end_pos != std::string::npos) {
                    cat_str = cat_str.substr(0, end_pos);
                }
                counter_cat = atoi(cat_str.c_str()) - 1;  // Convert to 0-indexed
                if (counter_cat == expected_category_0idx) any_counter_matched = true;
            }
        }
        
        if (all_matched && !any_counter_matched) {
            passed++;
            std::cout << "   PASS #" << i << "\n";
        } else {
            failed++;
            failed_count++;
            std::cout << "   FAIL #" << i << ": pattern=" << tc.pattern << "\n";
            
            // Save failed test case
            std::string fail_file = failed_dir + "/case_" + std::to_string(failed_count) + ".json";
            std::ofstream ff(fail_file);
            ff << "{\n";
            ff << "  \"id\": " << failed_count << ",\n";
            ff << "  \"test_id\": " << tc.test_id << ",\n";
            ff << "  \"pattern\": \"[" << categoryToString(tc.category) << ":test" << tc.test_id << "] " << tc.pattern << "\",\n";
            ff << "  \"category\": \"" << categoryToString(tc.category) << "\",\n";
            ff << "  \"matching_inputs\": [";
            for (size_t j = 0; j < tc.matching_inputs.size(); j++) {
                if (j > 0) ff << ", ";
                ff << "\"" << tc.matching_inputs[j] << "\"";
            }
            ff << "],\n";
            ff << "  \"counter_inputs\": [";
            for (size_t j = 0; j < tc.counter_inputs.size(); j++) {
                if (j > 0) ff << ", ";
                ff << "\"" << tc.counter_inputs[j] << "\"";
            }
            ff << "],\n";
            ff << "  \"proof\": \"";
            for (size_t p = 0; p < tc.proof.size(); p++) {
                char c = tc.proof[p];
                if (c == '\n') ff << "\\n";
                else if (c == '"') ff << "\\\"";
                else ff << c;
            }
            ff << "\",\n";
            ff << "  \"error\": \"";
            if (!all_matched) ff << "matching inputs did not match";
            else if (any_counter_matched) ff << "counter inputs matched";
            ff << "\"\n";
            ff << "}\n";
            ff.close();
            std::cout << "   Saved failed case to: " << fail_file << "\n";
        }
        
        remove(temp_pattern.c_str());
        remove(nfa_file.c_str());
        remove(dfa_file.c_str());
    }
    
    std::cout << "\nResults: " << passed << " passed, " << failed << " failed, " << skipped << " skipped\n";
    if (failed > 0) {
        std::cout << "Failed cases saved to: " << failed_dir << "/\n";
    }
    return failed > 0 ? 1 : 0;
}
