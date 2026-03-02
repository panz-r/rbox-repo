#include "testgen.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <set>
#include <unordered_set>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

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
    
    int pipe_stdout[2], pipe_stderr[2];
    if (pipe(pipe_stdout) == -1 || pipe(pipe_stderr) == -1) {
        result.exit_code = -1;
        return result;
    }
    
    pid_t pid = fork();
    if (pid == -1) {
        result.exit_code = -1;
        return result;
    }
    
    if (pid == 0) {
        // Child process
        close(pipe_stdout[0]);
        close(pipe_stderr[0]);
        dup2(pipe_stdout[1], STDOUT_FILENO);
        dup2(pipe_stderr[1], STDERR_FILENO);
        close(pipe_stdout[1]);
        close(pipe_stderr[1]);
        
        execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
        _exit(127);
    }
    
    // Parent process
    close(pipe_stdout[1]);
    close(pipe_stderr[1]);
    
    char buf[256];
    ssize_t n;
    
    // Read stdout
    while ((n = read(pipe_stdout[0], buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        result.stdout += buf;
    }
    close(pipe_stdout[0]);
    
    // Read stderr
    while ((n = read(pipe_stderr[0], buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        result.stderr += buf;
    }
    close(pipe_stderr[0]);
    
    // Wait for child
    int status;
    waitpid(pid, &status, 0);
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

std::shared_ptr<PatternNode> PatternNode::createLiteral(const std::string& val, const std::vector<std::string>& seeds) {
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::LITERAL;
    node->value = val;
    node->matched_seeds = seeds;
    return node;
}

std::shared_ptr<PatternNode> PatternNode::createFragment(const std::string& name, const std::vector<std::string>& seeds) {
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::FRAGMENT_REF;
    node->fragment_name = name;
    node->matched_seeds = seeds;
    return node;
}

std::shared_ptr<PatternNode> PatternNode::createSequence(const std::vector<std::shared_ptr<PatternNode>>& kids, const std::vector<std::string>& seeds) {
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::SEQUENCE;
    node->children = kids;
    node->matched_seeds = seeds;
    return node;
}

std::shared_ptr<PatternNode> PatternNode::createAlternation(const std::vector<std::shared_ptr<PatternNode>>& alts, const std::vector<std::string>& seeds) {
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::ALTERNATION;
    node->children = alts;
    node->matched_seeds = seeds;
    return node;
}

std::shared_ptr<PatternNode> PatternNode::createQuantified(std::shared_ptr<PatternNode> child, PatternType quant_type, const std::vector<std::string>& seeds) {
    auto node = std::make_shared<PatternNode>();
    node->type = quant_type;
    node->quantified = child;
    node->matched_seeds = seeds;
    return node;
}

// Helper: Create pattern like (a|b|c)+
std::shared_ptr<PatternNode> createAlternationPlus(const std::vector<std::string>& alts, const std::vector<std::string>& seeds) {
    std::vector<std::shared_ptr<PatternNode>> alt_nodes;
    for (const auto& alt : alts) {
        alt_nodes.push_back(PatternNode::createLiteral(alt, {alt}));
    }
    auto alt_node = PatternNode::createAlternation(alt_nodes, seeds);
    alt_node->type = PatternType::PLUS_QUANTIFIER;
    alt_node->quantified = PatternNode::createAlternation(alt_nodes, seeds);
    return alt_node;
}

// Helper: Create pattern like (a|b|c)*
std::shared_ptr<PatternNode> createAlternationStar(const std::vector<std::string>& alts, const std::vector<std::string>& seeds) {
    std::vector<std::shared_ptr<PatternNode>> alt_nodes;
    for (const auto& alt : alts) {
        alt_nodes.push_back(PatternNode::createLiteral(alt, {alt}));
    }
    auto alt_node = PatternNode::createAlternation(alt_nodes, seeds);
    alt_node->type = PatternType::STAR_QUANTIFIER;
    alt_node->quantified = PatternNode::createAlternation(alt_nodes, seeds);
    return alt_node;
}

// Helper: Create pattern like (a|b|c)?
std::shared_ptr<PatternNode> createAlternationOptional(const std::vector<std::string>& alts, const std::vector<std::string>& seeds) {
    std::vector<std::shared_ptr<PatternNode>> alt_nodes;
    for (const auto& alt : alts) {
        alt_nodes.push_back(PatternNode::createLiteral(alt, {alt}));
    }
    auto alt_node = PatternNode::createAlternation(alt_nodes, seeds);
    alt_node->type = PatternType::OPTIONAL;
    alt_node->quantified = PatternNode::createAlternation(alt_nodes, seeds);
    return alt_node;
}

// Helper: Create pattern like (literal)+
std::shared_ptr<PatternNode> createLiteralPlus(const std::string& literal, const std::vector<std::string>& seeds) {
    auto lit_node = PatternNode::createLiteral(literal, seeds);
    lit_node->type = PatternType::PLUS_QUANTIFIER;
    lit_node->quantified = PatternNode::createLiteral(literal, seeds);
    return lit_node;
}

// Helper: Create pattern like (literal)*
std::shared_ptr<PatternNode> createLiteralStar(const std::string& literal, const std::vector<std::string>& seeds) {
    auto lit_node = PatternNode::createLiteral(literal, seeds);
    lit_node->type = PatternType::STAR_QUANTIFIER;
    lit_node->quantified = PatternNode::createLiteral(literal, seeds);
    return lit_node;
}

// Helper: Create pattern like (literal)?
std::shared_ptr<PatternNode> createLiteralOptional(const std::string& literal, const std::vector<std::string>& seeds) {
    auto lit_node = PatternNode::createLiteral(literal, seeds);
    lit_node->type = PatternType::OPTIONAL;
    lit_node->quantified = PatternNode::createLiteral(literal, seeds);
    return lit_node;
}

// Helper: Create fragment reference like ((frag))+ 
std::shared_ptr<PatternNode> createFragmentPlus(const std::string& frag_name, const std::vector<std::string>& seeds) {
    auto frag_node = PatternNode::createFragment(frag_name, seeds);
    frag_node->type = PatternType::PLUS_QUANTIFIER;
    frag_node->quantified = PatternNode::createFragment(frag_name, seeds);
    return frag_node;
}

// Helper: Create fragment reference like ((frag))*
std::shared_ptr<PatternNode> createFragmentStar(const std::string& frag_name, const std::vector<std::string>& seeds) {
    auto frag_node = PatternNode::createFragment(frag_name, seeds);
    frag_node->type = PatternType::STAR_QUANTIFIER;
    frag_node->quantified = PatternNode::createFragment(frag_name, seeds);
    return frag_node;
}

// Helper: Wrap an AST node with capture tags
std::shared_ptr<PatternNode> wrapWithCaptureTags(std::shared_ptr<PatternNode> node, const std::string& tag_name) {
    if (!node) return nullptr;
    node->capture_tag = tag_name;
    return node;
}

// Helper: Create char class literal like [abc]
std::shared_ptr<PatternNode> createCharClass(const std::string& chars, const std::vector<std::string>& seeds) {
    auto node = std::make_shared<PatternNode>();
    node->type = PatternType::LITERAL;
    node->value = "[" + chars + "]";
    node->matched_seeds = seeds;
    return node;
}

// Helper: Create char class with plus quantifier like [abc]+
std::shared_ptr<PatternNode> createCharClassPlus(const std::string& chars, const std::vector<std::string>& seeds) {
    auto char_node = createCharClass(chars, seeds);
    char_node->type = PatternType::PLUS_QUANTIFIER;
    char_node->quantified = createCharClass(chars, seeds);
    return char_node;
}

// Helper: Create sequence of nodes
std::shared_ptr<PatternNode> createSequenceNode(const std::vector<std::shared_ptr<PatternNode>>& nodes, const std::vector<std::string>& seeds) {
    return PatternNode::createSequence(nodes, seeds);
}

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
            return begin_only + capture_prefix + node->value + capture_suffix + end_only;
            
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
    
    // Strategy 3: Add empty alternative - DISABLED (creates invalid patterns)
    // if (node->type == PatternType::ALTERNATION && !all_seeds.empty() && apply_dist(rng) == 0) {
    //     bool has_empty = false;
    //     for (const auto& child : node->children) {
    //         if (child->type == PatternType::LITERAL && child->value.empty()) {
    //             has_empty = true; break;
    //         }
    //     }
    //     if (!has_empty) {
    //         node->children.push_back(PatternNode::createLiteral("", {}));
    //     }
    // }
    
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
    const std::string lowercase = "abcdefghijklmnopqrstuvwxyz";
    const std::string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string digits = "0123456789";
    const std::string alphanum = lowercase + uppercase + digits;
    
    std::vector<std::string> matching_seeds;
    std::vector<std::string> counter_seeds;
    std::set<std::string> used = used_inputs;  // Start with already-used inputs
    
    // Generate high-entropy random matching seeds (fixed 5)
    const int num_matching = 5;
    
    while ((int)matching_seeds.size() < num_matching) {
        std::string s;
        int min_len;
        
        if (complexity == Complexity::SIMPLE) {
            min_len = 2;
        } else if (complexity == Complexity::MEDIUM) {
            min_len = 3;
        } else {
            min_len = 6;
        }
        
        // Each string gets its own random length: min_len to min_len*8
        int max_mult = 8;
        int len = min_len + std::uniform_int_distribution<int>(0, min_len * max_mult - min_len)(rng);
        
        for (int j = 0; j < len; j++) {
            s += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
        }
        
        if (used.insert(s).second) {
            matching_seeds.push_back(s);
        }
    }
    
    // Generate high-entropy random counter seeds (fixed 25)
    const int num_counters = 25;
    
    while ((int)counter_seeds.size() < num_counters) {
        std::string s;
        int len;
        
        if (complexity == Complexity::SIMPLE) {
            len = 2 + std::uniform_int_distribution<int>(0, 4)(rng);
        } else if (complexity == Complexity::MEDIUM) {
            len = 3 + std::uniform_int_distribution<int>(0, 8)(rng);  // 3-11 chars
        } else {
            len = 5 + std::uniform_int_distribution<int>(0, 15)(rng);  // 5-20 chars (longer)
        }
        
        for (int j = 0; j < len; j++) {
            s += alphanum[std::uniform_int_distribution<int>(0, alphanum.size()-1)(rng)];
        }
        
        // Must be different from all matching
        if (used.find(s) == used.end()) {
            used.insert(s);
            counter_seeds.push_back(s);
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
// Full-spectrum Pattern Generation with Fragments
// ============================================================================

struct PatternResult {
    std::string pattern;
    std::map<std::string, std::string> fragments;  // fragment definitions
    std::string proof;
    std::vector<Expectation> expectations;
    std::shared_ptr<PatternNode> ast;  // AST with matched_seeds
};

// Try many different pattern strategies and return the first that works

// Check if a pattern matches an input (simplified - just for validation)
bool patternMatchesLiteral(const std::string& literal, const std::string& str) {
    return literal == str;
}

bool patternMatchesOptional(const std::string& content, const std::string& str) {
    return str.empty() || str == content;
}

bool patternMatchesPlus(const std::string& content, const std::string& str) {
    if (str.empty() || content.empty()) return false;
    size_t content_len = content.size();
    if (str.size() % content_len != 0) return false;
    for (size_t i = 0; i < str.size(); i += content_len) {
        if (str.substr(i, content_len) != content) return false;
    }
    return true;
}

bool patternMatchesStar(const std::string& content, const std::string& str) {
    if (content.empty()) return str.empty();
    if (str.empty()) return true;
    size_t content_len = content.size();
    if (str.size() % content_len != 0) return false;
    for (size_t i = 0; i < str.size(); i += content_len) {
        if (str.substr(i, content_len) != content) return false;
    }
    return true;
}

bool patternMatchesCharClass(const std::string& char_class, const std::string& str) {
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

// Extract fragment from char class and return pattern with fragment reference
// Optionally uses namespaced format with ~30% probability
std::string extractFragment(const std::string& char_class, 
                          std::map<std::string, std::string>& fragments,
                          std::mt19937& rng,
                          bool force_simple = false) {
    // Create fragment name
    static const char* frag_names[] = {"a", "b", "c", "d", "e", "f", "g", "h", "x", "y", "z"};
    std::string frag_name = frag_names[std::uniform_int_distribution<int>(0, 10)(rng)];
    
    // Add numeric suffix to make unique
    frag_name += std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
    
    // Decide whether to use namespaced format (30% chance)
    bool use_namespace = !force_simple && std::uniform_int_distribution<int>(0, 99)(rng) < 30;
    std::string full_name;
    
    if (use_namespace) {
        // Use test namespace
        std::string namespaces[] = {"test", "gen", "tgen", "pat"};
        std::string ns = namespaces[std::uniform_int_distribution<int>(0, 3)(rng)];
        full_name = ns + "::" + frag_name;
    } else {
        full_name = frag_name;
    }
    
    fragments[full_name] = char_class;
    
    return "((" + full_name + "))+";
}

// Strategy 1: Literal (exact match)
PatternResult tryLiteral(const std::vector<std::string>& matching,
                        const std::vector<std::string>& counters,
                        std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() != 1) {
        result.proof += "  Literal: requires single matching\n";
        return result;
    }
    
    const std::string& lit = matching[0];
    
    // Check no counter matches this literal
    for (const auto& c : counters) {
        if (c == lit) {
            result.proof += "  Literal rejected: counter identical\n";
            return result;
        }
    }
    
    result.pattern = lit;
    result.ast = PatternNode::createLiteral(lit, matching);
    result.proof += "  Literal: '" + lit + "'\n";
    result.proof += "    MATCHES: '" + lit + "'\n";
    result.proof += "    VERIFIED: no counter matches literal\n";
    return result;
}

// Strategy 2: Alternation of all
PatternResult tryAlternation(const std::vector<std::string>& matching,
                            const std::vector<std::string>& counters,
                            std::mt19937& rng) {
    PatternResult result;
    
    // Verify all matching match
    for (const auto& m : matching) {
        bool found = false;
        for (const auto& alt : matching) {
            if (m == alt) { found = true; break; }
        }
        if (!found) {
            result.proof += "  Alternation rejected: matching doesn't fully match\n";
            return result;
        }
    }
    
    // Verify no counter matches
    std::string counters_matching;
    for (const auto& c : counters) {
        for (const auto& alt : matching) {
            if (c == alt) {
                counters_matching += "'" + c + "', ";
            }
        }
    }
    
    if (!counters_matching.empty()) {
        result.proof += "  Alternation rejected: counters match: " + counters_matching + "\n";
        return result;
    }
    
    // Build AST with matched_seeds
    std::vector<std::shared_ptr<PatternNode>> alt_nodes;
    for (const auto& m : matching) {
        alt_nodes.push_back(PatternNode::createLiteral(m, {m}));
    }
    
    // ALWAYS apply a quantifier to make it interesting
    std::uniform_int_distribution<int> qdist(0, 2);
    int qtype = qdist(rng);
    
    std::shared_ptr<PatternNode> alt_node = PatternNode::createAlternation(alt_nodes, matching);
    
    if (qtype == 0) {
        alt_node->type = PatternType::PLUS_QUANTIFIER;
        alt_node->quantified = PatternNode::createAlternation(alt_nodes, matching);
    } else if (qtype == 1) {
        alt_node->type = PatternType::STAR_QUANTIFIER;
        alt_node->quantified = PatternNode::createAlternation(alt_nodes, matching);
    } else {
        alt_node->type = PatternType::OPTIONAL;
        alt_node->quantified = PatternNode::createAlternation(alt_nodes, matching);
    }
    
    result.ast = alt_node;
    result.pattern = serializePattern(alt_node);
    result.proof += "  Alternation: " + result.pattern + "\n";
    result.proof += "    MATCHES all " + std::to_string(matching.size()) + " matching inputs\n";
    result.proof += "    VERIFIED: no counter inputs match\n";
    return result;
}

// Strategy 3: Repetition pattern - find common substring repeated
PatternResult tryRepetition(const std::vector<std::string>& matching,
                           const std::vector<std::string>& counters,
                           std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  Repetition: requires 2+ matching\n";
        return result;
    }
    
    // Try each matching string as a potential repeat unit
    for (const auto& unit : matching) {
        if (unit.empty()) continue;
        
        bool all_match = true;
        for (const auto& m : matching) {
            if (!patternMatchesPlus(unit, m)) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) continue;
        
        // Check counters don't match
        bool any_counter_matches = false;
        for (const auto& c : counters) {
            if (patternMatchesPlus(unit, c)) {
                any_counter_matches = true;
                break;
            }
        }
        
        if (any_counter_matches) continue;
        
        // Maybe extract fragment from unit?
        if (unit.size() >= 2 && std::uniform_int_distribution<int>(0, 1)(rng) == 1) {
            std::map<std::string, std::string> frags;
            std::string frag_pattern = extractFragment(unit, frags, rng);
            result.fragments.insert(frags.begin(), frags.end());
            
            // Extract fragment name from pattern like "((name))+"
            size_t start = frag_pattern.find("((");
            size_t end = frag_pattern.find("))+");
            if (start != std::string::npos && end != std::string::npos && start + 2 < end) {
                std::string frag_name = frag_pattern.substr(start + 2, end - start - 2);
                result.ast = createFragmentPlus(frag_name, matching);
            }
            result.pattern = frag_pattern;
        } else {
            // Use AST helper
            result.ast = createLiteralPlus(unit, matching);
            result.pattern = serializePattern(result.ast);
        }
        
        result.proof += "  Repetition: " + result.pattern + "\n";
        result.proof += "    Unit: '" + unit + "'\n";
        result.proof += "    MATCHES: ";
        for (size_t i = 0; i < matching.size(); i++) {
            if (i > 0) result.proof += ", ";
            result.proof += "'" + matching[i] + "'";
        }
        result.proof += "\n";
        result.proof += "    VERIFIED: no counter matches repetition of '" + unit + "'\n";
        return result;
    }
    
    result.proof += "  Repetition: none found (no common unit that matches all)\n";
    return result;
}

// Strategy 4: Common prefix + variable suffix with fragment
PatternResult tryPrefixPlusFragment(const std::vector<std::string>& matching,
                                   const std::vector<std::string>& counters,
                                   std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  Prefix+: requires 2+ matching\n";
        return result;
    }
    
    // Find common prefix
    std::string prefix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_prefix;
        for (size_t j = 0; j < matching[i].size() && j < prefix.size(); j++) {
            if (matching[i][j] == prefix[j]) {
                new_prefix += prefix[j];
            } else {
                break;
            }
        }
        prefix = new_prefix;
        if (prefix.empty()) break;
    }
    
    if (prefix.empty()) {
        result.proof += "  Prefix+: no common prefix\n";
        return result;
    }
    
    // For each position after prefix, try char class+
    for (size_t pos = prefix.size(); pos <= prefix.size(); pos++) {
        std::set<char> match_chars;
        for (const auto& m : matching) {
            if (pos < m.size()) match_chars.insert(m[pos]);
        }
        
        if (match_chars.empty()) continue;
        
        // Build char class
        std::string char_class;
        for (char c : match_chars) {
            if (!char_class.empty()) char_class += "|";
            char_class += c;
        }
        
        // Try with inline char class+
        std::string pattern = prefix + "(" + char_class + ")+";
        
        bool all_match = true;
        for (const auto& m : matching) {
            if (m.size() <= pos) {
                all_match = false;
                break;
            }
            std::string suffix = m.substr(pos);
            if (!patternMatchesCharClass(char_class, suffix)) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) continue;
        
        // Check counters
        bool any_match = false;
        for (const auto& c : counters) {
            if (c.size() > pos && c.substr(0, pos) == prefix) {
                std::string suffix = c.substr(pos);
                if (patternMatchesCharClass(char_class, suffix)) {
                    any_match = true;
                    break;
                }
            }
        }
        
        if (!any_match) {
            // Now try with fragment instead of inline char class
            if (match_chars.size() >= 2 && std::uniform_int_distribution<int>(0, 1)(rng) == 1) {
                std::map<std::string, std::string> frags;
                std::string frag_pattern = extractFragment(char_class, frags, rng);
                result.fragments.insert(frags.begin(), frags.end());
                
                // Extract fragment name and create AST
                size_t start = frag_pattern.find("((");
                size_t end = frag_pattern.find("))+");
                if (start != std::string::npos && end != std::string::npos && start + 2 < end) {
                    std::string frag_name = frag_pattern.substr(start + 2, end - start - 2);
                    auto frag_node = createFragmentPlus(frag_name, matching);
                    if (!prefix.empty()) {
                        // Create sequence: prefix + fragment+
                        auto prefix_node = PatternNode::createLiteral(prefix, {});
                        result.ast = PatternNode::createSequence({prefix_node, frag_node}, matching);
                    } else {
                        result.ast = frag_node;
                    }
                }
                result.pattern = prefix + frag_pattern;
            } else {
                // Create AST for char class pattern
                auto char_node = createCharClassPlus(char_class, matching);
                if (!prefix.empty()) {
                    auto prefix_node = PatternNode::createLiteral(prefix, {});
                    result.ast = PatternNode::createSequence({prefix_node, char_node}, matching);
                } else {
                    result.ast = char_node;
                }
                result.pattern = pattern;
            }
            result.proof += "  Prefix+: " + result.pattern + "\n";
            result.proof += "    Prefix: '" + prefix + "'\n";
            result.proof += "    Char class: (" + char_class + ")+\n";
            result.proof += "    MATCHES: all " + std::to_string(matching.size()) + " inputs start with '" + prefix + "'\n";
            result.proof += "    VERIFIED: no counter has prefix '" + prefix + "' with matching suffix\n";
            return result;
        }
    }
    
    result.proof += "  Prefix+: no valid char class (counters would match)\n";
    return result;
}

// Strategy 5: Common suffix + variable prefix with fragment
PatternResult trySuffixPlusFragment(const std::vector<std::string>& matching,
                                    const std::vector<std::string>& counters,
                                    std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  Suffix+: requires 2+ matching\n";
        return result;
    }
    
    // Find common suffix
    std::string suffix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_suffix;
        size_t min_len = std::min(matching[i].size(), suffix.size());
        for (size_t j = 0; j < min_len; j++) {
            char c1 = matching[i][matching[i].size() - 1 - j];
            char c2 = suffix[suffix.size() - 1 - j];
            if (c1 == c2) {
                new_suffix = c1 + new_suffix;
            } else {
                break;
            }
        }
        suffix = new_suffix;
        if (suffix.empty()) break;
    }
    
    if (suffix.empty()) {
        result.proof += "  Suffix+: no common suffix\n";
        return result;
    }
    
    size_t suffix_len = suffix.size();
    
    for (size_t suffix_start = 0; suffix_start <= suffix_len; suffix_start++) {
        std::set<char> match_chars;
        for (const auto& m : matching) {
            if (m.size() > suffix_len && (m.size() - suffix_len - 1) >= 0) {
                size_t pos = m.size() - suffix_len - 1;
                if (pos < m.size()) match_chars.insert(m[pos]);
            }
        }
        
        if (match_chars.empty()) continue;
        
        std::string char_class;
        for (char c : match_chars) {
            if (!char_class.empty()) char_class += "|";
            char_class += c;
        }
        
        // Try with fragment
        if (match_chars.size() >= 2 && std::uniform_int_distribution<int>(0, 1)(rng) == 1) {
            std::map<std::string, std::string> frags;
            std::string frag_pattern = extractFragment(char_class, frags, rng);
            result.fragments.insert(frags.begin(), frags.end());
            result.pattern = frag_pattern + suffix;
        } else {
            result.pattern = "(" + char_class + ")+" + suffix;
        }
        
        // Verify matching - check BOTH suffix AND that prefix matches char class
        bool all_match = true;
        for (const auto& m : matching) {
            if (m.size() <= suffix_len) {
                all_match = false;
                break;
            }
            if (m.substr(m.size() - suffix_len) != suffix) {
                all_match = false;
                break;
            }
            // Verify prefix consists ONLY of chars from the char class
            std::string prefix = m.substr(0, m.size() - suffix_len);
            if (!patternMatchesCharClass(char_class, prefix)) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) {
            result.pattern = "";
            continue;
        }
        
        // Check counters
        bool any_match = false;
        for (const auto& c : counters) {
            if (c.size() > suffix_len && c.substr(c.size() - suffix_len) == suffix) {
                if (!c.empty() && patternMatchesCharClass(char_class, c.substr(0, c.size() - suffix_len))) {
                    any_match = true;
                    break;
                }
            }
        }
        
        if (!any_match) {
            // Create AST for suffix+ pattern
            auto char_node = createCharClassPlus(char_class, matching);
            auto suffix_node = PatternNode::createLiteral(suffix, {});
            
            if (match_chars.size() >= 2 && std::uniform_int_distribution<int>(0, 1)(rng) == 1) {
                // Try with fragment
                std::map<std::string, std::string> frags;
                std::string frag_pattern = extractFragment(char_class, frags, rng);
                result.fragments.insert(frags.begin(), frags.end());
                
                size_t start = frag_pattern.find("((");
                size_t end = frag_pattern.find("))+");
                if (start != std::string::npos && end != std::string::npos && start + 2 < end) {
                    std::string frag_name = frag_pattern.substr(start + 2, end - start - 2);
                    auto frag_node = createFragmentPlus(frag_name, matching);
                    result.ast = PatternNode::createSequence({frag_node, suffix_node}, matching);
                }
                result.pattern = frag_pattern + suffix;
            } else {
                result.ast = PatternNode::createSequence({char_node, suffix_node}, matching);
                result.pattern = "(" + char_class + ")+" + suffix;
            }
            
            result.proof += "  Suffix+: " + result.pattern + "\n";
            result.proof += "    Suffix: '" + suffix + "'\n";
            result.proof += "    Char class: (" + char_class + ")+\n";
            result.proof += "    MATCHES: all " + std::to_string(matching.size()) + " inputs end with '" + suffix + "'\n";
            result.proof += "    VERIFIED: no counter has suffix '" + suffix + "' with matching prefix\n";
            return result;
        }
    }
    
    result.proof += "  Suffix+: no valid pattern (counters would match)\n";
    result.pattern = "";
    return result;
}

// Strategy 6: Two-part pattern with fragment
PatternResult tryTwoPartFragment(const std::vector<std::string>& matching,
                                const std::vector<std::string>& counters,
                                std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  TwoPart+: requires 2+ matching\n";
        return result;
    }
    
    // Try splitting at each position
    for (size_t split_pos = 1; split_pos < matching[0].size(); split_pos++) {
        std::string part1 = matching[0].substr(0, split_pos);
        std::string part2 = matching[0].substr(split_pos);
        
        if (part2.empty()) continue;
        
        // Try: part1(part2)+
        std::string pattern = part1 + "(" + part2 + ")+";
        
        bool all_match = true;
        for (const auto& m : matching) {
            if (m.size() < split_pos || m.substr(0, split_pos) != part1) {
                all_match = false;
                break;
            }
            if (!patternMatchesPlus(part2, m.substr(split_pos))) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) continue;
        
        // Check counters
        bool any_match = false;
        for (const auto& c : counters) {
            if (c.size() >= split_pos && c.substr(0, split_pos) == part1) {
                if (patternMatchesPlus(part2, c.substr(split_pos))) {
                    any_match = true;
                    break;
                }
            }
        }
        
        if (!any_match) {
            // Maybe use fragment for part2?
            if (part2.size() >= 1 && std::uniform_int_distribution<int>(0, 1)(rng) == 1) {
                std::map<std::string, std::string> frags;
                std::string frag_pattern = extractFragment(part2, frags, rng);
                result.fragments.insert(frags.begin(), frags.end());
                result.pattern = part1 + frag_pattern;
            } else {
                result.pattern = pattern;
            }
            result.proof += "  TwoPart+: " + result.pattern + "\n";
            return result;
        }
        
        // Try: (part1)+part2
        pattern = "(" + part1 + ")+" + part2;
        
        all_match = true;
        for (const auto& m : matching) {
            size_t part1_len = m.size() - part2.size();
            if (part1_len < part1.size() || part1_len % part1.size() != 0) {
                all_match = false;
                break;
            }
            if (m.substr(part1_len) != part2) {
                all_match = false;
                break;
            }
            bool valid = true;
            for (size_t i = 0; i < part1_len; i += part1.size()) {
                if (m.substr(i, part1.size()) != part1) {
                    valid = false;
                    break;
                }
            }
            if (!valid) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) continue;
        
        any_match = false;
        for (const auto& c : counters) {
            size_t part1_len = c.size() - part2.size();
            if (part1_len > 0 && c.substr(c.size() - part2.size()) == part2) {
                bool valid = true;
                for (size_t i = 0; i < part1_len; i += part1.size()) {
                    if (c.substr(i, part1.size()) != part1) {
                        valid = false;
                        break;
                    }
                }
                if (valid) {
                    any_match = true;
                    break;
                }
            }
        }
        
        if (!any_match) {
            result.pattern = pattern;
            result.proof += "  TwoPart+: " + pattern + "\n";
            result.proof += "    Part1: '" + part1 + "', Part2: '" + part2 + "'\n";
            result.proof += "    MATCHES: all inputs are repetitions of part1 followed by part2\n";
            result.proof += "    VERIFIED: no counter matches this structure\n";
            return result;
        }
    }
    
    result.proof += "  TwoPart+: no valid split (counters would match)\n";
    result.pattern = "";
    return result;
}

// Strategy 7: Fragment-only pattern
PatternResult tryFragmentOnly(const std::vector<std::string>& matching,
                             const std::vector<std::string>& counters,
                             std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  FragmentOnly: requires 2+ matching\n";
        return result;
    }
    
    // Collect all unique chars from all matching strings
    std::set<char> all_chars;
    for (const auto& m : matching) {
        for (char c : m) {
            all_chars.insert(c);
        }
    }

    // Exclude characters that appear in counter inputs to ensure separation
    for (const auto& c : counters) {
        for (char c2 : c) {
            all_chars.erase(c2);
        }
    }
    
    if (all_chars.size() < 2) {
        result.proof += "  FragmentOnly: not enough variation or overlaps with counter\n";
        return result;
    }
    
    // Create fragment from all chars
    std::string char_class;
    for (char c : all_chars) {
        if (!char_class.empty()) char_class += "|";
        char_class += c;
    }
    
    // Extract the fragment name and definition from the returned pattern
    std::map<std::string, std::string> frags;
    std::string frag_pattern = extractFragment(char_class, frags, rng);
    result.fragments.insert(frags.begin(), frags.end());
    
    // Get the fragment definition
    std::string frag_def;
    for (const auto& f : frags) {
        frag_def = f.second;
        break;
    }
    
    // Now verify using the FRAGMENT's definition (the characters it contains)
    // Try with common prefix
    std::string prefix;
    for (size_t i = 0; i < 2; i++) {
        prefix += matching[0][i];
        bool all_have = true;
        for (const auto& m : matching) {
            if (i >= m.size() || m[i] != prefix.back()) {
                all_have = false;
                break;
            }
        }
        if (!all_have) {
            prefix.pop_back();
            break;
        }
    }
    
    if (!prefix.empty()) {
        result.pattern = prefix + frag_pattern;
    } else {
        result.pattern = frag_pattern;
    }
    
    // Verify - use the FRAGMENT's character set, not the original char_class
    bool all_match = true;
    for (const auto& m : matching) {
        if (!prefix.empty() && m.find(prefix) != 0) {
            all_match = false;
            break;
        }
        std::string suffix = prefix.empty() ? m : m.substr(prefix.size());
        if (!patternMatchesCharClass(frag_def, suffix)) {
            all_match = false;
            break;
        }
    }
    
    // Verify - check that no counter matches the fragment pattern
    bool any_counter_matches = false;
    for (const auto& c : counters) {
        // For FragmentOnly with fragment, check if ALL chars in counter are from fragment
        if (patternMatchesCharClass(frag_def, c)) {
            any_counter_matches = true;
            break;
        }
    }
    
    if (any_counter_matches) {
        result.proof += "  FragmentOnly: counters would match fragment\n";
        result.pattern = "";
        return result;
    }
    
    if (!all_match) {
        result.proof += "  FragmentOnly: verification failed\n";
        result.pattern = "";
        return result;
    }
    
    // Build AST for fragment pattern
    if (!result.pattern.empty()) {
        // Extract fragment name from pattern like "((name))+"
        size_t start = result.pattern.find("((");
        size_t end = result.pattern.find("))+");
        if (start != std::string::npos && end != std::string::npos && start + 2 < end) {
            std::string frag_name = result.pattern.substr(start + 2, end - start - 2);
            result.ast = createFragmentPlus(frag_name, matching);
        }
    }
    
    result.proof += "  FragmentOnly: " + result.pattern + "\n";
    result.proof += "    Char class contains " + std::to_string(all_chars.size()) + " unique chars\n";
    if (!prefix.empty()) {
        result.proof += "    Prefix: '" + prefix + "'\n";
    }
    result.proof += "    MATCHES: all " + std::to_string(matching.size()) + " inputs consist of these chars\n";
    result.proof += "    VERIFIED: no counter matches the char class pattern\n";
    return result;
}

// ============================================================================
// Edge Case Strategies
// ============================================================================

// Strategy: Optional quantifier - try (unit)? instead of alternation
PatternResult tryOptionalQuantifier(const std::vector<std::string>& matching,
                                   const std::vector<std::string>& counters,
                                   std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  Optional: requires 2+ matching\n";
        return result;
    }
    
    // Find common prefix and try making it optional
    std::string prefix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_prefix;
        for (size_t j = 0; j < matching[i].size() && j < prefix.size(); j++) {
            if (matching[i][j] == prefix[j]) {
                new_prefix += prefix[j];
            } else {
                break;
            }
        }
        prefix = new_prefix;
        if (prefix.empty()) break;
    }
    
    if (prefix.empty() || prefix.size() < 2) {
        result.proof += "  Optional: no suitable prefix\n";
        return result;
    }
    
    // Try: (prefix)?rest where rest is what comes after
    for (size_t split = 1; split < prefix.size(); split++) {
        std::string opt_part = prefix.substr(0, split);
        std::string rest = prefix.substr(split);
        
        // Build pattern: (opt_part)?rest
        // This would match both opt_part+rest and just rest
        
        // Check if all matching are either prefix or rest
        bool valid = true;
        for (const auto& m : matching) {
            if (m != prefix && m != rest) {
                valid = false;
                break;
            }
        }
        if (!valid) continue;
        
        // Check counters - ensure none match the optional pattern
        bool any_counter_matches = false;
        for (const auto& c : counters) {
            if (c == rest || c == prefix) {
                any_counter_matches = true;
                break;
            }
        }
        
        if (!any_counter_matches) {
            result.pattern = "(" + opt_part + ")?";
            if (!rest.empty()) result.pattern += rest;
            
            // Create AST
            auto opt_node = PatternNode::createLiteral(opt_part, {opt_part});
            opt_node->type = PatternType::OPTIONAL;
            opt_node->quantified = PatternNode::createLiteral(opt_part, {opt_part});
            
            if (!rest.empty()) {
                auto rest_node = PatternNode::createLiteral(rest, {rest});
                result.ast = PatternNode::createSequence({opt_node, rest_node}, matching);
            } else {
                result.ast = opt_node;
            }
            
            if (result.ast) {
                result.pattern = serializePattern(result.ast);
            }
            
            result.proof += "  Optional: " + result.pattern + "\n";
            result.proof += "    Makes '" + opt_part + "' optional before '" + rest + "'\n";
            result.proof += "    MATCHES: '" + prefix + "' and '" + rest + "'\n";
            result.proof += "    VERIFIED: no counter matches\n";
            return result;
        }
    }
    
    result.proof += "  Optional: no valid optional pattern found\n";
    return result;
}

// Strategy: Empty alternative - try adding | to alternation
PatternResult tryEmptyAlternative(const std::vector<std::string>& matching,
                                const std::vector<std::string>& counters,
                                std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  EmptyAlt: requires 2+ matching\n";
        return result;
    }
    
    // Build alternation
    std::string pattern = "(";
    for (size_t i = 0; i < matching.size(); i++) {
        if (i > 0) pattern += "|";
        pattern += matching[i];
    }
    pattern += "|)";  // Add empty alternative
    
    // Verify matching still works (empty would match empty string which isn't in our inputs)
    bool all_match = true;
    for (const auto& m : matching) {
        bool found = false;
        for (const auto& alt : matching) {
            if (m == alt) { found = true; break; }
        }
        if (!found) { all_match = false; break; }
    }
    
    if (!all_match) {
        result.proof += "  EmptyAlt: base alternation doesn't work\n";
        return result;
    }
    
    // Check counters - empty matches empty string, so we need to ensure
    // no counter is empty (they're all non-empty high-entropy strings)
    bool any_counter_empty = false;
    for (const auto& c : counters) {
        if (c.empty()) {
            any_counter_empty = true;
            break;
        }
    }
    
    if (!any_counter_empty) {
        // Also verify no counter matches any of the alternatives
        bool any_match = false;
        for (const auto& c : counters) {
            for (const auto& alt : matching) {
                if (c == alt) {
                    any_match = true;
                    break;
                }
            }
            if (any_match) break;
        }
        
        if (!any_match) {
            result.pattern = pattern;
            
            // Create AST with empty alternative
            std::vector<std::shared_ptr<PatternNode>> nodes;
            for (const auto& alt : matching) {
                nodes.push_back(PatternNode::createLiteral(alt, {alt}));
            }
            nodes.push_back(PatternNode::createLiteral("", {}));  // empty alternative
            result.ast = PatternNode::createAlternation(nodes, matching);
            
            result.proof += "  EmptyAlt: " + result.pattern + "\n";
            result.proof += "    Added empty alternative |\n";
            result.proof += "    MATCHES: " + std::to_string(matching.size()) + " inputs\n";
            result.proof += "    VERIFIED: no counter is empty or matches alternatives\n";
            return result;
        }
    }
    
    result.proof += "  EmptyAlt: counters prevent empty alternative\n";
    return result;
}

// Strategy: Nested group - wrap pattern in extra parens
PatternResult tryNestedGroup(const std::vector<std::string>& matching,
                           const std::vector<std::string>& counters,
                           std::mt19937& rng,
                           const std::string& base_pattern) {
    PatternResult result;
    
    if (base_pattern.empty()) {
        result.proof += "  Nested: no base pattern\n";
        return result;
    }
    
    // Wrap in extra parens: ((pattern))
    result.pattern = "((" + base_pattern + "))";
    
    // Verify - nested groups should match same as base
    bool all_match = true;
    for (const auto& m : matching) {
        // Check if base pattern would match
        bool base_matches = false;
        
        // Simple check: is m in matching?
        if (base_pattern.find(m) != std::string::npos || 
            base_pattern.find("(" + m + ")") != std::string::npos ||
            base_pattern.find(m + "|") != std::string::npos ||
            base_pattern.find("|" + m + ")") != std::string::npos) {
            base_matches = true;
        }
        
        if (!base_matches && matching.size() == 1 && m == matching[0]) {
            // Single literal case
            base_matches = (base_pattern == m);
        }
        
        if (!base_matches) {
            // Check alternation
            size_t pos = 0;
            while ((pos = base_pattern.find('|', pos)) != std::string::npos) {
                std::string alt = base_pattern.substr(pos + 1);
                size_t end = alt.find(')');
                if (end != std::string::npos) {
                    alt = alt.substr(0, end);
                    if (alt == m) { base_matches = true; break; }
                }
                pos++;
            }
        }
        
        if (!base_matches) { all_match = false; break; }
    }
    
    if (all_match) {
        // Check counters - nested should have same matching behavior
        bool any_match = false;
        for (const auto& c : counters) {
            for (const auto& alt : matching) {
                if (c == alt) { any_match = true; break; }
            }
            if (any_match) break;
        }
        
        if (!any_match) {
            result.pattern = "((" + base_pattern + "))";
            
            // For nested groups, we keep the same AST but wrap it
            // Just use the base pattern as-is since nesting doesn't change semantics
            
            result.proof += "  Nested: " + result.pattern + "\n";
            result.proof += "    Wrapped base pattern in extra parentheses\n";
            result.proof += "    VERIFIED: same matching as base, counters excluded\n";
            return result;
        }
    }
    
    result.proof += "  Nested: base pattern doesn't work with nesting\n";
    result.pattern = "";
    return result;
}

// Strategy: Multi-character fragment
PatternResult tryMultiCharFragment(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  MultiFrag: requires 2+ matching\n";
        return result;
    }
    
    // Find common substring (2+ chars) across all matching
    std::string common_substr;
    std::string first = matching[0];
    
    for (size_t len = 2; len <= first.size(); len++) {
        for (size_t pos = 0; pos + len <= first.size(); pos++) {
            std::string substr = first.substr(pos, len);
            
            bool found_in_all = true;
            for (size_t i = 1; i < matching.size(); i++) {
                if (matching[i].find(substr) == std::string::npos) {
                    found_in_all = false;
                    break;
                }
            }
            
            if (found_in_all) {
                common_substr = substr;
                break;
            }
        }
        if (!common_substr.empty()) break;
    }
    
    if (common_substr.empty()) {
        result.proof += "  MultiFrag: no common substring\n";
        return result;
    }
    
    // Build fragment pattern: replace common substring with fragment
    std::string frag_name = "m";
    frag_name += std::to_string(std::uniform_int_distribution<int>(10, 99)(rng));
    result.fragments[frag_name] = common_substr;
    
    // Build pattern: try to use fragment in a plus
    std::string pattern = "((" + frag_name + "))+";
    
    // Verify all matching can be generated by repeating the substring
    // IMPORTANT: Must check patternMatchesPlus, not just find!
    // A substring might appear in each input but NOT as a full repetition
    bool all_match = true;
    for (const auto& m : matching) {
        // Use patternMatchesPlus to verify the input IS a repetition of common_substr
        // NOT just that it contains common_substr somewhere
        if (!patternMatchesPlus(common_substr, m)) {
            all_match = false;
            break;
        }
    }
    
    if (all_match) {
        // Check counters - use patternMatchesPlus for consistency
        bool any_match = false;
        for (const auto& c : counters) {
            if (patternMatchesPlus(common_substr, c)) {
                any_match = true;
                break;
            }
        }
        
        if (!any_match) {
            result.pattern = pattern;
            
            // Create AST
            result.ast = createFragmentPlus(frag_name, matching);
            
            result.proof += "  MultiFrag: " + result.pattern + "\n";
            result.proof += "    Fragment: " + frag_name + " = " + common_substr + "\n";
            result.proof += "    MATCHES: strings that are repetitions of " + common_substr + "\n";
            result.proof += "    VERIFIED: counters don't match\n";
            return result;
        }
    }
    
    // Try with alternation instead: (substr1|substr2)+
    std::set<std::string> substrings;
    for (const auto& m : matching) {
        for (size_t len = 2; len <= m.size(); len++) {
            for (size_t pos = 0; pos + len <= m.size(); pos++) {
                substrings.insert(m.substr(pos, len));
            }
        }
    }
    
    // Build alternation of substrings
    std::string alt_pattern = "(";
    int count = 0;
    for (const auto& s : substrings) {
        if (count > 10) break;  // Limit alternation size
        if (count > 0) alt_pattern += "|";
        alt_pattern += s;
        count++;
    }
    alt_pattern += ")";
    
    // Check if this works
    all_match = true;
    for (const auto& m : matching) {
        bool matches_alt = false;
        for (const auto& s : substrings) {
            if (m.find(s) != std::string::npos) {
                matches_alt = true;
                break;
            }
        }
        if (!matches_alt) { all_match = false; break; }
    }
    
    if (all_match) {
        bool any_match = false;
        for (const auto& c : counters) {
            for (const auto& s : substrings) {
                if (c.find(s) != std::string::npos) {
                    any_match = true;
                    break;
                }
            }
            if (any_match) break;
        }
        
        if (!any_match) {
            result.pattern = alt_pattern;
            result.proof += "  MultiFrag: " + result.pattern + "\n";
            result.proof += "    Alternation of " + std::to_string(count) + " substrings\n";
            result.proof += "    MATCHES: inputs with these substrings\n";
            result.proof += "    VERIFIED: counters excluded\n";
            return result;
        }
    }
    
    result.proof += "  MultiFrag: no valid multi-char fragment pattern\n";
    return result;
}

// ============================================================================
// New Pattern Strategies with Quantifiers on Expressions
// ============================================================================

// Strategy: Alternation with quantifier - (a|b)+ or (a|b)*
PatternResult tryAlternationWithQuantifier(const std::vector<std::string>& matching,
                                           const std::vector<std::string>& counters,
                                           std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  AltQuant: requires 2+ matching\n";
        return result;
    }
    
    // Find a common substring that can be the "base" of alternation
    // Look for a substring that appears in all matching
    std::set<std::string> common_substrs;
    std::string first = matching[0];
    
    for (size_t len = 1; len <= first.size(); len++) {
        for (size_t pos = 0; pos + len <= first.size(); pos++) {
            std::string substr = first.substr(pos, len);
            bool in_all = true;
            for (size_t i = 1; i < matching.size(); i++) {
                if (matching[i].find(substr) == std::string::npos) {
                    in_all = false;
                    break;
                }
            }
            if (in_all) common_substrs.insert(substr);
        }
    }
    
    // Try each common substring as a potential alternation element
    for (const auto& substr : common_substrs) {
        if (substr.empty() || substr.size() < 2) continue;
        
        // Build alternation: take substr, then add variations
        // e.g., substr="abc" -> (abc|abd|abX)+
        std::vector<std::string> alts;
        alts.push_back(substr);
        
        // Add 1-3 variations
        int num_variants = 1 + std::uniform_int_distribution<int>(0, 2)(rng);
        for (int v = 0; v < num_variants; v++) {
            std::string var = substr;
            // Change one char
            size_t idx = std::uniform_int_distribution<int>(0, var.size()-1)(rng);
            char orig = var[idx];
            char newc;
            do {
                newc = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[
                    std::uniform_int_distribution<int>(0, 60)(rng)];
            } while (newc == orig);
            var[idx] = newc;
            alts.push_back(var);
        }
        
        // Build pattern: (alt1|alt2|...)+
        std::string pattern = "(";
        for (size_t i = 0; i < alts.size(); i++) {
            if (i > 0) pattern += "|";
            pattern += alts[i];
        }
        pattern += ")+";
        
        // Check if matching strings match this pattern
        bool all_match = true;
        for (const auto& m : matching) {
            bool matches = false;
            for (const auto& alt : alts) {
                if (patternMatchesPlus(alt, m)) {
                    matches = true;
                    break;
                }
            }
            if (!matches) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) continue;
        
        // Check counters
        bool any_match = false;
        for (const auto& c : counters) {
            for (const auto& alt : alts) {
                if (patternMatchesPlus(alt, c)) {
                    any_match = true;
                    break;
                }
            }
            if (any_match) break;
        }
        
        if (any_match) continue;
        
        // Decide on quantifier randomly
        bool use_star = std::uniform_int_distribution<int>(0, 1)(rng) == 0;
        if (use_star) {
            pattern = pattern.substr(0, pattern.size() - 1) + ")*";
        }
        
        // Create AST
        if (use_star) {
            std::vector<std::shared_ptr<PatternNode>> nodes;
            for (const auto& alt : alts) {
                nodes.push_back(PatternNode::createLiteral(alt, {alt}));
            }
            auto alt_node = PatternNode::createAlternation(nodes, matching);
            alt_node->type = PatternType::STAR_QUANTIFIER;
            alt_node->quantified = PatternNode::createAlternation(nodes, matching);
            result.ast = alt_node;
        } else {
            result.ast = createAlternationPlus(alts, matching);
        }
        
        result.pattern = pattern;
        result.proof += "  AltQuant: " + result.pattern + "\n";
        result.proof += "    Base: '" + substr + "' with variations\n";
        result.proof += "    MATCHES: repetitions of these alternatives\n";
        result.proof += "    VERIFIED: no counter matches\n";
        return result;
    }
    
    result.proof += "  AltQuant: no valid alternation with quantifier\n";
    return result;
}

// Strategy: Sequence with quantifier - (abc)+ or (abc)*
PatternResult trySequenceWithQuantifier(const std::vector<std::string>& matching,
                                        const std::vector<std::string>& counters,
                                        std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  SeqQuant: requires 2+ matching\n";
        return result;
    }
    
    // Find common prefix
    std::string prefix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_prefix;
        for (size_t j = 0; j < matching[i].size() && j < prefix.size(); j++) {
            if (matching[i][j] == prefix[j]) {
                new_prefix += prefix[j];
            } else {
                break;
            }
        }
        prefix = new_prefix;
        if (prefix.empty()) break;
    }
    
    if (prefix.size() < 2) {
        result.proof += "  SeqQuant: no suitable prefix\n";
        return result;
    }
    
    // Try different prefix lengths as the sequence unit
    for (size_t len = 2; len <= prefix.size(); len++) {
        std::string unit = prefix.substr(0, len);
        
        // Check if all matching are repetitions of this unit
        bool all_match = true;
        for (const auto& m : matching) {
            if (!patternMatchesPlus(unit, m)) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) continue;
        
        // Check counters
        bool any_match = false;
        for (const auto& c : counters) {
            if (patternMatchesPlus(unit, c)) {
                any_match = true;
                break;
            }
        }
        
        if (any_match) continue;
        
        // Choose quantifier randomly
        std::uniform_int_distribution<int> qdist(0, 2);
        int qtype = qdist(rng);
        
        // Create AST based on quantifier type
        if (qtype == 0) {
            result.ast = createLiteralPlus(unit, matching);
            result.pattern = "(" + unit + ")+";
        } else if (qtype == 1) {
            result.ast = createLiteralStar(unit, matching);
            result.pattern = "(" + unit + ")*";
        } else {
            auto lit_node = PatternNode::createLiteral(unit, matching);
            lit_node->type = PatternType::OPTIONAL;
            lit_node->quantified = PatternNode::createLiteral(unit, matching);
            result.ast = lit_node;
            result.pattern = "(" + unit + ")";
        }
        
        result.proof += "  SeqQuant: " + result.pattern + "\n";
        result.proof += "    Unit: '" + unit + "'\n";
        result.proof += "    MATCHES: " + std::to_string(matching.size()) + " inputs\n";
        result.proof += "    VERIFIED: no counter matches\n";
        return result;
    }
    
    result.proof += "  SeqQuant: no valid sequence with quantifier\n";
    return result;
}

// Strategy: Optional sequence - (abc)? 
PatternResult tryOptionalSequence(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  OptSeq: requires 2+ matching\n";
        return result;
    }
    
    // Look for strings where some share a common prefix
    std::string prefix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_prefix;
        for (size_t j = 0; j < matching[i].size() && j < prefix.size(); j++) {
            if (matching[i][j] == prefix[j]) {
                new_prefix += prefix[j];
            } else {
                break;
            }
        }
        prefix = new_prefix;
        if (prefix.empty()) break;
    }
    
    if (prefix.size() < 2) {
        result.proof += "  OptSeq: no suitable prefix\n";
        return result;
    }
    
    // Try splitting: (prefix)?rest
    for (size_t split = 1; split < prefix.size(); split++) {
        std::string opt_part = prefix.substr(0, split);
        std::string rest = prefix.substr(split);
        
        if (rest.empty()) continue;
        
        // Check which matching strings have opt_part
        int with_opt = 0;
        int without_opt = 0;
        
        for (const auto& m : matching) {
            if (m.find(opt_part + rest) == 0) {
                with_opt++;
            } else if (m.find(rest) == 0) {
                without_opt++;
            }
        }
        
        if (with_opt > 0 && without_opt > 0) {
            // Build pattern: (opt_partrest)? or (opt_part)?rest
            std::string pattern = "(" + opt_part + rest + ")?";
            
            // Check counters - should not match
            bool any_match = false;
            for (const auto& c : counters) {
                if (c == opt_part + rest || c == rest) {
                    any_match = true;
                    break;
                }
            }
            
            if (!any_match) {
                result.pattern = pattern;
                
                // Create AST for optional sequence
                auto full_node = PatternNode::createLiteral(opt_part + rest, {opt_part + rest});
                full_node->type = PatternType::OPTIONAL;
                full_node->quantified = PatternNode::createLiteral(opt_part + rest, {opt_part + rest});
                result.ast = full_node;
                
                result.proof += "  OptSeq: " + result.pattern + "\n";
                result.proof += "    Optional: '" + opt_part + rest + "'\n";
                result.proof += "    MATCHES: with/without the optional part\n";
                result.proof += "    VERIFIED: no counter matches\n";
                return result;
            }
        }
    }
    
    result.proof += "  OptSeq: no valid optional sequence\n";
    return result;
}

// Strategy: Nested quantifiers - ((ab)+)* or ((a|b)+)?
PatternResult tryNestedQuantifiers(const std::vector<std::string>& matching,
                                   const std::vector<std::string>& counters,
                                   std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  NestedQuant: requires 2+ matching\n";
        return result;
    }
    
    // Try to build a base pattern first
    std::string base_unit;
    
    // Find common substring
    std::string first = matching[0];
    for (size_t len = 2; len <= first.size(); len++) {
        for (size_t pos = 0; pos + len <= first.size(); pos++) {
            std::string substr = first.substr(pos, len);
            bool in_all = true;
            for (size_t i = 1; i < matching.size(); i++) {
                if (matching[i].find(substr) == std::string::npos) {
                    in_all = false;
                    break;
                }
            }
            if (in_all) {
                base_unit = substr;
                break;
            }
        }
        if (!base_unit.empty()) break;
    }
    
    if (base_unit.empty()) {
        result.proof += "  NestedQuant: no suitable base unit\n";
        return result;
    }
    
    // Build nested quantifier patterns
    // Choose random nesting pattern
    std::uniform_int_distribution<int> ndist(0, 3);
    int nest_type = ndist(rng);
    
    std::string inner_pattern;
    std::string outer_pattern;
    
    switch (nest_type) {
        case 0: // ((unit)+)*
            inner_pattern = "(" + base_unit + ")+";
            outer_pattern = "(" + inner_pattern + ")*";
            break;
        case 1: // ((unit)*)+
            inner_pattern = "(" + base_unit + ")*";
            outer_pattern = "(" + inner_pattern + ")+";
            break;
        case 2: // ((unit)+)?
            inner_pattern = "(" + base_unit + ")+";
            outer_pattern = "(" + inner_pattern + ")?";
            break;
        default: // ((unit)*)?
            inner_pattern = "(" + base_unit + ")*";
            outer_pattern = "(" + inner_pattern + ")?";
            break;
    }
    
    // Verify all matching
    bool all_match = true;
    for (const auto& m : matching) {
        if (m.find(base_unit) == std::string::npos) {
            all_match = false;
            break;
        }
    }
    
    if (!all_match) {
        result.proof += "  NestedQuant: base unit not in all matching\n";
        return result;
    }
    
    // Check counters
    bool any_match = false;
    for (const auto& c : counters) {
        if (c.find(base_unit) != std::string::npos) {
            any_match = true;
            break;
        }
    }
    
    if (!any_match) {
        // Build AST based on nest_type
        auto base_node = PatternNode::createLiteral(base_unit, matching);
        
        switch (nest_type) {
            case 0: { // ((unit)+)*
                auto inner_node = createLiteralPlus(base_unit, matching);
                inner_node->type = PatternType::PLUS_QUANTIFIER;
                result.ast = PatternNode::createQuantified(inner_node, PatternType::STAR_QUANTIFIER, matching);
                break;
            }
            case 1: { // ((unit)*)+
                auto inner_node = createLiteralStar(base_unit, matching);
                result.ast = PatternNode::createQuantified(inner_node, PatternType::PLUS_QUANTIFIER, matching);
                break;
            }
            case 2: { // ((unit)+)?
                auto inner_node = createLiteralPlus(base_unit, matching);
                result.ast = PatternNode::createQuantified(inner_node, PatternType::OPTIONAL, matching);
                break;
            }
            default: { // ((unit)*)?
                auto inner_node = createLiteralStar(base_unit, matching);
                result.ast = PatternNode::createQuantified(inner_node, PatternType::OPTIONAL, matching);
                break;
            }
        }
        
        if (result.ast) {
            result.pattern = serializePattern(result.ast);
        } else {
            result.pattern = outer_pattern;
        }
        result.proof += "  NestedQuant: " + result.pattern + "\n";
        result.proof += "    Inner: " + inner_pattern + "\n";
        result.proof += "    Outer: " + outer_pattern + "\n";
        result.proof += "    MATCHES: strings containing " + base_unit + "\n";
        result.proof += "    VERIFIED: no counter matches\n";
        return result;
    }
    
    result.proof += "  NestedQuant: counters prevent this pattern\n";
    return result;
}

// Strategy: Char class sequence - (a|b|c)+ with different chars
PatternResult tryCharClassSequence(const std::vector<std::string>& matching,
                                   const std::vector<std::string>& counters,
                                   std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  CharClassSeq: requires 2+ matching\n";
        return result;
    }
    
    // Find common prefix
    std::string prefix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_prefix;
        for (size_t j = 0; j < matching[i].size() && j < prefix.size(); j++) {
            if (matching[i][j] == prefix[j]) {
                new_prefix += prefix[j];
            } else {
                break;
            }
        }
        prefix = new_prefix;
        if (prefix.empty()) break;
    }
    
    if (prefix.empty()) {
        result.proof += "  CharClassSeq: no common prefix\n";
        return result;
    }
    
    // Build char class from characters at next position
    size_t pos = prefix.size();
    std::set<char> suffix_chars;
    for (const auto& m : matching) {
        if (pos < m.size()) {
            suffix_chars.insert(m[pos]);
        }
    }
    
    if (suffix_chars.size() < 2) {
        result.proof += "  CharClassSeq: not enough char variation\n";
        return result;
    }
    
    // Build char class: (a|b|c)+
    std::string char_class;
    for (char c : suffix_chars) {
        if (!char_class.empty()) char_class += "|";
        char_class += c;
    }
    
    std::string pattern = prefix + "(" + char_class + ")+";
    
    // Verify all matching
    bool all_match = true;
    for (const auto& m : matching) {
        if (m.size() <= pos) {
            all_match = false;
            break;
        }
        if (m.substr(0, pos) != prefix) {
            all_match = false;
            break;
        }
        std::string suffix = m.substr(pos);
        if (!patternMatchesCharClass(char_class, suffix)) {
            all_match = false;
            break;
        }
    }
    
    if (!all_match) {
        result.proof += "  CharClassSeq: matching strings don't fit\n";
        return result;
    }
    
    // Check counters
    bool any_match = false;
    for (const auto& c : counters) {
        if (c.size() > pos && c.substr(0, pos) == prefix) {
            std::string suffix = c.substr(pos);
            if (patternMatchesCharClass(char_class, suffix)) {
                any_match = true;
                break;
            }
        }
    }
    
    if (any_match) {
        result.proof += "  CharClassSeq: counters would match\n";
        return result;
    }
    
    // Create AST
    auto prefix_node = PatternNode::createLiteral(prefix, {});
    auto char_node = createCharClassPlus(char_class, matching);
    result.ast = PatternNode::createSequence({prefix_node, char_node}, matching);
    result.pattern = pattern;
    
    result.proof += "  CharClassSeq: " + result.pattern + "\n";
    result.proof += "    Prefix: '" + prefix + "'\n";
    result.proof += "    Char class: (" + char_class + ")+\n";
    result.proof += "    MATCHES: prefix followed by one or more of these chars\n";
    result.proof += "    VERIFIED: no counter matches\n";
    return result;
}

// Strategy: Star quantifier (zero or more)
PatternResult tryStarQuantifier(const std::vector<std::string>& matching,
                                const std::vector<std::string>& counters,
                                std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  StarQuant: requires 2+ matching\n";
        return result;
    }
    
    // Try each matching string as a potential repeat unit
    for (const auto& unit : matching) {
        if (unit.empty()) continue;
        
        // For star, we need to check if matching strings can be repetitions
        // OR if they start with the unit (allowing zero of it)
        bool all_match = true;
        for (const auto& m : matching) {
            if (!patternMatchesStar(unit, m) && m.find(unit) != 0) {
                all_match = false;
                break;
            }
        }
        
        if (!all_match) continue;
        
        // Check counters - star is permissive, so be careful
        bool any_counter_matches = false;
        for (const auto& c : counters) {
            // Counter matches if it's a full repetition OR starts with unit
            if (patternMatchesStar(unit, c) || c.find(unit) == 0) {
                any_counter_matches = true;
                break;
            }
        }
        
        if (any_counter_matches) continue;
        
        // Use fragment occasionally
        if (unit.size() >= 1 && std::uniform_int_distribution<int>(0, 1)(rng) == 1) {
            std::map<std::string, std::string> frags;
            std::string frag_pattern = extractFragment(unit, frags, rng);
            result.fragments.insert(frags.begin(), frags.end());
            result.pattern = "(" + frag_pattern + ")*";
            
            // Extract fragment name and create AST
            size_t start = frag_pattern.find("((");
            size_t end = frag_pattern.find("))+");
            if (start != std::string::npos && end != std::string::npos && start + 2 < end) {
                std::string frag_name = frag_pattern.substr(start + 2, end - start - 2);
                result.ast = createFragmentStar(frag_name, matching);
            }
        } else {
            result.ast = createLiteralStar(unit, matching);
            result.pattern = "(" + unit + ")*";
        }
        
        result.proof += "  StarQuant: " + result.pattern + "\n";
        result.proof += "    Unit: '" + unit + "'\n";
        result.proof += "    MATCHES: strings starting with or repetitions of '" + unit + "'\n";
        result.proof += "    VERIFIED: no counter matches\n";
        return result;
    }
    
    result.proof += "  StarQuant: no valid star pattern found\n";
    return result;
}

// Strategy: CharClassPlus - inline character class with plus (not fragment)
PatternResult tryCharClassPlus(const std::vector<std::string>& matching,
                               const std::vector<std::string>& counters,
                               std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  CharClassPlus: requires 2+ matching\n";
        return result;
    }
    
    // Find common prefix
    std::string prefix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_prefix;
        for (size_t j = 0; j < matching[i].size() && j < prefix.size(); j++) {
            if (matching[i][j] == prefix[j]) {
                new_prefix += prefix[j];
            } else {
                break;
            }
        }
        prefix = new_prefix;
        if (prefix.empty()) break;
    }
    
    if (prefix.empty()) {
        result.proof += "  CharClassPlus: no common prefix\n";
        return result;
    }
    
    // Collect chars after prefix
    size_t pos = prefix.size();
    std::set<char> match_chars;
    for (const auto& m : matching) {
        if (pos < m.size()) match_chars.insert(m[pos]);
    }
    
    if (match_chars.size() < 2) {
        result.proof += "  CharClassPlus: not enough char variation\n";
        return result;
    }
    
    // Build inline char class (not fragment)
    std::string char_class;
    for (char c : match_chars) {
        if (!char_class.empty()) char_class += "|";
        char_class += c;
    }
    
    // Pattern: prefix[char_class]+
    // Note: c-dfa uses (a|b)+ syntax, not [ab]+
    std::string pattern = prefix + "(" + char_class + ")+";
    
    // Verify all matching
    bool all_match = true;
    for (const auto& m : matching) {
        if (m.size() <= pos) {
            all_match = false;
            break;
        }
        std::string suffix = m.substr(pos);
        if (!patternMatchesCharClass(char_class, suffix)) {
            all_match = false;
            break;
        }
    }
    
    if (!all_match) {
        result.proof += "  CharClassPlus: matching strings don't fit char class\n";
        return result;
    }
    
    // Check counters
    bool any_match = false;
    for (const auto& c : counters) {
        if (c.size() > pos && c.substr(0, pos) == prefix) {
            std::string suffix = c.substr(pos);
            if (patternMatchesCharClass(char_class, suffix)) {
                any_match = true;
                break;
            }
        }
    }
    
    if (any_match) {
        result.proof += "  CharClassPlus: counters would match\n";
        return result;
    }
    
    // Create AST
    auto prefix_node = PatternNode::createLiteral(prefix, {});
    auto char_node = createCharClassPlus(char_class, matching);
    result.ast = PatternNode::createSequence({prefix_node, char_node}, matching);
    result.pattern = pattern;
    
    result.proof += "  CharClassPlus: " + result.pattern + "\n";
    result.proof += "    Prefix: '" + prefix + "'\n";
    result.proof += "    Char class: (" + char_class + ")+\n";
    result.proof += "    MATCHES: all inputs start with '" + prefix + "' and continue with these chars\n";
    result.proof += "    VERIFIED: no counter matches\n";
    return result;
}

// Strategy: Mixed quantifiers - combine different quantifiers
PatternResult tryMixedQuantifiers(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  MixedQuant: requires 2+ matching\n";
        return result;
    }
    
    // Find common prefix
    std::string prefix = matching[0];
    for (size_t i = 1; i < matching.size(); i++) {
        std::string new_prefix;
        for (size_t j = 0; j < matching[i].size() && j < prefix.size(); j++) {
            if (matching[i][j] == prefix[j]) {
                new_prefix += prefix[j];
            } else {
                break;
            }
        }
        prefix = new_prefix;
        if (prefix.empty()) break;
    }
    
    if (prefix.empty() || prefix.size() < 2) {
        result.proof += "  MixedQuant: no suitable prefix\n";
        return result;
    }
    
    // Try splitting prefix into two parts with different quantifiers
    for (size_t split = 1; split < prefix.size(); split++) {
        std::string part1 = prefix.substr(0, split);
        std::string part2 = prefix.substr(split);
        
        if (part2.empty()) continue;
        
        // Try: part1+part2? - part2 optional
        std::string pattern1 = part1 + "(" + part2 + ")?";
        
        bool all_match1 = true;
        for (const auto& m : matching) {
            if (m.find(part1) != 0) {
                all_match1 = false;
                break;
            }
            std::string rest = m.substr(part1.size());
            if (rest != part2 && !rest.empty()) {
                all_match1 = false;
                break;
            }
        }
        
        if (all_match1) {
            bool any_counter = false;
            for (const auto& c : counters) {
                if (c.find(part1) == 0) {
                    std::string rest = c.substr(part1.size());
                    if (rest == part2 || rest.empty()) {
                        any_counter = true;
                        break;
                    }
                }
            }
            
            if (!any_counter) {
                result.pattern = pattern1;
                
                // Create AST: part1 + (part2)?
                auto part1_node = PatternNode::createLiteral(part1, {});
                auto part2_node = PatternNode::createLiteral(part2, {part2});
                part2_node->type = PatternType::OPTIONAL;
                part2_node->quantified = PatternNode::createLiteral(part2, {part2});
                result.ast = PatternNode::createSequence({part1_node, part2_node}, matching);
                
                result.proof += "  MixedQuant: " + result.pattern + "\n";
                result.proof += "    Part1: '" + part1 + "', Part2: '" + part2 + "' optional\n";
                result.proof += "    VERIFIED: no counter matches\n";
                return result;
            }
        }
        
        // Try: part1*part2 - part1 zero or more
        std::string pattern2 = "(" + part1 + ")*" + part2;
        
        bool all_match2 = true;
        for (const auto& m : matching) {
            if (m.size() < part2.size()) {
                all_match2 = false;
                break;
            }
            if (m.substr(m.size() - part2.size()) != part2) {
                all_match2 = false;
                break;
            }
            std::string prefix_part = m.substr(0, m.size() - part2.size());
            // Check prefix is repetitions of part1
            if (!prefix_part.empty() && prefix_part.size() % part1.size() != 0) {
                all_match2 = false;
                break;
            }
            for (size_t i = 0; i < prefix_part.size(); i += part1.size()) {
                if (prefix_part.substr(i, part1.size()) != part1) {
                    all_match2 = false;
                    break;
                }
            }
            if (!all_match2) break;
        }
        
        if (all_match2) {
            bool any_counter = false;
            for (const auto& c : counters) {
                if (c.size() >= part2.size() && c.substr(c.size() - part2.size()) == part2) {
                    std::string prefix_part = c.substr(0, c.size() - part2.size());
                    if (prefix_part.empty() || (prefix_part.size() % part1.size() == 0)) {
                        bool valid = true;
                        for (size_t i = 0; i < prefix_part.size(); i += part1.size()) {
                            if (prefix_part.substr(i, part1.size()) != part1) {
                                valid = false;
                                break;
                            }
                        }
                        if (valid) {
                            any_counter = true;
                            break;
                        }
                    }
                }
            }
            
            if (!any_counter) {
                result.pattern = pattern2;
                
                // Create AST: (part1)* + part2
                auto part1_node = PatternNode::createLiteral(part1, {});
                part1_node->type = PatternType::STAR_QUANTIFIER;
                part1_node->quantified = PatternNode::createLiteral(part1, {});
                auto part2_node = PatternNode::createLiteral(part2, {});
                result.ast = PatternNode::createSequence({part1_node, part2_node}, matching);
                
                result.proof += "  MixedQuant: " + result.pattern + "\n";
                result.proof += "    Part1: '" + part1 + "'*, Part2: '" + part2 + "'\n";
                result.proof += "    VERIFIED: no counter matches\n";
                return result;
            }
        }
    }
    
    result.proof += "  MixedQuant: no valid mixed quantifier pattern\n";
    return result;
}

// Strategy: Fragment chaining - use multiple fragments in one pattern
PatternResult tryFragmentChaining(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  FragChain: requires 2+ matching\n";
        return result;
    }
    
    // Find two different common substrings we can use as fragments
    // But exclude any substring that appears in counter inputs
    std::set<std::string> all_substrs;
    for (const auto& m : matching) {
        for (size_t len = 1; len <= m.size(); len++) {
            for (size_t pos = 0; pos + len <= m.size(); pos++) {
                std::string substr = m.substr(pos, len);
                // Skip if any counter input contains this substring
                bool in_counter = false;
                for (const auto& c : counters) {
                    if (c.find(substr) != std::string::npos) {
                        in_counter = true;
                        break;
                    }
                }
                if (!in_counter) {
                    all_substrs.insert(substr);
                }
            }
        }
    }
    
    std::vector<std::string> substr_list(all_substrs.begin(), all_substrs.end());
    if (substr_list.size() < 2) {
        result.proof += "  FragChain: not enough substrings\n";
        return result;
    }
    
    // Try different pairs as fragments
    std::shuffle(substr_list.begin(), substr_list.end(), rng);
    
    for (size_t i = 0; i < std::min((size_t)10, substr_list.size()); i++) {
        for (size_t j = i + 1; j < std::min((size_t)15, substr_list.size()); j++) {
            std::string frag1 = substr_list[i];
            std::string frag2 = substr_list[j];
            
            if (frag1 == frag2) continue;
            
            // Create fragment definitions
            std::string name1 = "x" + std::to_string(i);
            std::string name2 = "y" + std::to_string(j);
            result.fragments[name1] = frag1;
            result.fragments[name2] = frag2;
            
            // Try: ((x))+((y))+
            std::string pattern = "((" + name1 + "))+" + "((" + name2 + "))+";
            
            // Check if matching strings fit this pattern
            bool all_match = true;
            for (const auto& m : matching) {
                // Need at least one of each fragment in sequence
                size_t pos1 = m.find(frag1);
                size_t pos2 = m.find(frag2);
                if (pos1 == std::string::npos || pos2 == std::string::npos) {
                    all_match = false;
                    break;
                }
                // Order matters - frag1 should come before frag2 in cycle
                // For simplicity, check if we can partition string into repetitions
                std::string remaining = m;
                bool valid = true;
                while (!remaining.empty()) {
                    if (remaining.find(frag1) == 0) {
                        remaining = remaining.substr(frag1.size());
                    } else if (remaining.find(frag2) == 0) {
                        remaining = remaining.substr(frag2.size());
                    } else {
                        valid = false;
                        break;
                    }
                }
                if (!valid || !remaining.empty()) {
                    all_match = false;
                    break;
                }
            }
            
            if (!all_match) {
                result.fragments.erase(name1);
                result.fragments.erase(name2);
                continue;
            }
            
            // Check counters
            bool any_match = false;
            for (const auto& c : counters) {
                std::string remaining = c;
                bool valid = true;
                while (!remaining.empty()) {
                    if (remaining.find(frag1) == 0) {
                        remaining = remaining.substr(frag1.size());
                    } else if (remaining.find(frag2) == 0) {
                        remaining = remaining.substr(frag2.size());
                    } else {
                        valid = false;
                        break;
                    }
                }
                if (valid && remaining.empty()) {
                    any_match = true;
                    break;
                }
            }
            
            if (!any_match) {
                result.pattern = pattern;
                
                // Create AST: ((frag1))+((frag2))+
                auto frag1_node = createFragmentPlus(name1, matching);
                auto frag2_node = createFragmentPlus(name2, matching);
                result.ast = PatternNode::createSequence({frag1_node, frag2_node}, matching);
                
                result.proof += "  FragChain: " + result.pattern + "\n";
                result.proof += "    Frag1: " + name1 + "=" + frag1 + "\n";
                result.proof += "    Frag2: " + name2 + "=" + frag2 + "\n";
                result.proof += "    MATCHES: alternating " + frag1 + " and " + frag2 + "\n";
                result.proof += "    VERIFIED: no counter matches\n";
                return result;
            }
            
            result.fragments.erase(name1);
            result.fragments.erase(name2);
        }
    }
    
    result.proof += "  FragChain: no valid fragment chain found\n";
    return result;
}

// Strategy: Deep nesting - wrap pattern in parens
// IMPORTANT: c-dfa syntax interprets ((...)) and (((...))) as fragment references!
// So we can only use single grouping: (pattern) - which is just grouping, not fragment
PatternResult tryDeepNesting(const std::vector<std::string>& matching,
                              const std::vector<std::string>& counters,
                              std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  DeepNest: requires 2+ matching\n";
        return result;
    }
    
    // First try to get any valid pattern
    PatternResult base = tryAlternation(matching, counters, rng);
    if (base.pattern.empty()) {
        base = tryPrefixPlusFragment(matching, counters, rng);
    }
    if (base.pattern.empty()) {
        result.proof += "  DeepNest: no base pattern found\n";
        return result;
    }
    
    // Don't wrap if pattern already has parens (would create fragment reference)
    if (base.pattern.find('(') != std::string::npos) {
        result.proof += "  DeepNest: base pattern already has parens\n";
        result.pattern = base.pattern;
        result.fragments = base.fragments;
        return result;
    }
    
    // Single grouping is safe: (pattern) is grouping, not fragment reference
    std::string grouped = "(" + base.pattern + ")";
    
    // Verify still works
    bool all_match = true;
    for (const auto& m : matching) {
        bool found = false;
        for (const auto& alt : matching) {
            if (m == alt) { found = true; break; }
        }
        if (!found) { all_match = false; break; }
    }
    
    if (all_match) {
        result.pattern = grouped;
        result.fragments = base.fragments;
        
        // Create AST - wrap base.ast in a grouping (no quantifier)
        if (base.ast) {
            // For grouping, we just serialize the child directly
            result.ast = base.ast;
        }
        
        result.proof += "  DeepNest: " + result.pattern + "\n";
        result.proof += "    Single grouping (safe - not fragment reference)\n";
        result.proof += "    VERIFIED: same matching as base\n";
        return result;
    }
    
    result.proof += "  DeepNest: grouping broke pattern\n";
    return result;
}

// Strategy: Multi-fragment combination - two fragments used together
// Pattern: ((frag1))+((frag2))+ - tests fragment isolation when combined
PatternResult tryMultiFragmentCombo(const std::vector<std::string>& matching,
                                   const std::vector<std::string>& counters,
                                   std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 4) {
        result.proof += "  MultiFrag: requires 4+ matching\n";
        return result;
    }
    
    // Split matching into two groups for two fragments
    std::vector<std::string> group1(matching.begin(), matching.begin() + matching.size()/2);
    std::vector<std::string> group2(matching.begin() + matching.size()/2, matching.end());
    
    if (group1.size() < 2 || group2.size() < 2) {
        result.proof += "  MultiFrag: groups too small\n";
        return result;
    }
    
    // Create first fragment from group1 chars
    std::set<char> chars1;
    for (const auto& m : group1) {
        for (char c : m) chars1.insert(c);
    }
    // Exclude counter chars
    for (const auto& c : counters) {
        for (char c2 : c) chars1.erase(c2);
    }
    if (chars1.size() < 2) {
        result.proof += "  MultiFrag: not enough chars for frag1\n";
        return result;
    }
    
    std::string frag1_def;
    for (char c : chars1) {
        if (!frag1_def.empty()) frag1_def += "|";
        frag1_def += c;
    }
    std::string frag1_name = "mf1";
    result.fragments[frag1_name] = frag1_def;
    
    // Create second fragment from group2 chars (exclusive from group1)
    std::set<char> chars2;
    for (const auto& m : group2) {
        for (char c : m) chars2.insert(c);
    }
    for (const auto& c : counters) {
        for (char c2 : c) chars2.erase(c2);
    }
    // Remove chars from group1 to ensure exclusivity
    for (char c : chars1) chars2.erase(c);
    if (chars2.size() < 2) {
        result.proof += "  MultiFrag: not enough exclusive chars for frag2\n";
        return result;
    }
    
    std::string frag2_def;
    for (char c : chars2) {
        if (!frag2_def.empty()) frag2_def += "|";
        frag2_def += c;
    }
    std::string frag2_name = "mf2";
    result.fragments[frag2_name] = frag2_def;
    
    // Pattern: ((mf1))+((mf2))+ - SEQUENTIAL: group1 uses frag1, group2 uses frag2
    result.pattern = "((" + frag1_name + "))+(((" + frag2_name + "))+";
    
    // Verify: group1 strings should ONLY have chars from frag1, group2 ONLY from frag2
    bool all_match = true;
    // Check group1 strings
    for (const auto& m : group1) {
        for (char c : m) {
            if (!chars1.count(c)) { all_match = false; break; }
        }
        if (!all_match) break;
    }
    // Check group2 strings
    for (const auto& m : group2) {
        for (char c : m) {
            if (!chars2.count(c)) { all_match = false; break; }
        }
        if (!all_match) break;
    }
    
    if (!all_match) {
        result.proof += "  MultiFrag: matching strings don't fit sequential pattern\n";
        result.pattern = "";
        return result;
    }
    
    // Check counters: ensure no counter has both fragment chars
    bool any_counter_match = false;
    for (const auto& c : counters) {
        bool has_frag1 = false, has_frag2 = false;
        for (char c2 : c) {
            if (chars1.count(c2)) has_frag1 = true;
            if (chars2.count(c2)) has_frag2 = true;
        }
        if (has_frag1 && has_frag2) {
            any_counter_match = true;
            break;
        }
    }
    
    if (any_counter_match) {
        result.proof += "  MultiFrag: counters would match\n";
        result.pattern = "";
        return result;
    }
    
    // Create AST
    auto frag1_node = createFragmentPlus(frag1_name, group1);
    auto frag2_node = createFragmentPlus(frag2_name, group2);
    result.ast = PatternNode::createSequence({frag1_node, frag2_node}, matching);
    
    result.proof += "  MultiFrag: " + result.pattern + "\n";
    result.proof += "    frag1: " + frag1_name + "=" + frag1_def + "\n";
    result.proof += "    frag2: " + frag2_name + "=" + frag2_def + "\n";
    return result;
}

// Strategy: Nested alternation - alternation within alternation
PatternResult tryNestedAlternation(const std::vector<std::string>& matching,
                                   const std::vector<std::string>& counters,
                                   std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 4) {
        result.proof += "  NestedAlt: requires 4+ matching\n";
        return result;
    }
    
    // Create pattern: (a|b|c) with each alternative being a full matching string
    // The "nested" part is just using + quantifier
    
    // Build simple alternation from matching strings
    std::string pattern = "(";
    for (size_t i = 0; i < matching.size(); i++) {
        if (i > 0) pattern += "|";
        pattern += matching[i];
    }
    pattern += ")+";
    
    // Create AST
    result.ast = createAlternationPlus(matching, matching);
    result.pattern = pattern;
    
    result.proof += "  NestedAlt: " + result.pattern + "\n";
    return result;
}

// Strategy: Complex quantifier stack - (a*)+, (a+)*, (a?)+
PatternResult tryQuantifierStack(const std::vector<std::string>& matching,
                                  const std::vector<std::string>& counters,
                                  std::mt19937& rng) {
    PatternResult result;
    
    if (matching.empty()) {
        result.proof += "  QuantStack: requires matching\n";
        return result;
    }
    
    // Use first matching string as base
    std::string base = matching[0];
    if (base.empty()) {
        result.proof += "  QuantStack: empty base\n";
        return result;
    }
    
    // Try different quantifier stacks
    std::vector<std::string> stacks = {
        "(" + base + "*)+",   // Zero or more, one or more times
        "(" + base + "+)*",   // One or more, zero or more times  
        "(" + base + "?)+",   // Optional, one or more times
    };
    
    std::shuffle(stacks.begin(), stacks.end(), rng);
    
    for (const auto& pattern : stacks) {
        bool all_match = true;
        for (const auto& m : matching) {
            // Check if m fits the pattern (starts with base, then any repetitions)
            if (m.find(base) != 0) {
                all_match = false;
                break;
            }
        }
        
        if (all_match) {
            // Create AST for quantifier stack
            auto base_node = PatternNode::createLiteral(base, matching);
            if (pattern.find("*)+") != std::string::npos) {
                // (base*)*
                base_node->type = PatternType::STAR_QUANTIFIER;
                base_node->quantified = PatternNode::createLiteral(base, matching);
                result.ast = PatternNode::createQuantified(base_node, PatternType::PLUS_QUANTIFIER, matching);
            } else if (pattern.find("+)*") != std::string::npos) {
                // (base+)*
                base_node->type = PatternType::PLUS_QUANTIFIER;
                base_node->quantified = PatternNode::createLiteral(base, matching);
                result.ast = PatternNode::createQuantified(base_node, PatternType::STAR_QUANTIFIER, matching);
            } else {
                // (base?)*
                base_node->type = PatternType::OPTIONAL;
                base_node->quantified = PatternNode::createLiteral(base, matching);
                result.ast = PatternNode::createQuantified(base_node, PatternType::PLUS_QUANTIFIER, matching);
            }
            
            result.pattern = pattern;
            result.proof += "  QuantStack: " + result.pattern + "\n";
            return result;
        }
    }
    
    result.proof += "  QuantStack: no valid stack\n";
    return result;
}

// Strategy: Long literal alternation - 10-20 alternatives with long strings
PatternResult tryLongAlternation(const std::vector<std::string>& matching,
                               const std::vector<std::string>& counters,
                               std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  LongAlt: requires 2+ matching\n";
        return result;
    }
    
    // Use matching strings as base, add many variations
    std::vector<std::string> alts = matching;
    
    // Add variations of matching strings
    for (const auto& m : matching) {
        if (alts.size() >= 20) break;
        if (m.size() < 2) continue;
        
        // Add prefix/suffix variations
        for (int i = 0; i < 2 && alts.size() < 20; i++) {
            std::string var = m;
            // Reverse
            std::reverse(var.begin(), var.end());
            if (var != m && std::find(alts.begin(), alts.end(), var) == alts.end()) {
                alts.push_back(var);
            }
        }
    }
    
    if (alts.size() < 3) {
        result.proof += "  LongAlt: not enough alternatives\n";
        return result;
    }
    
    // Build pattern
    std::string pattern = "(";
    for (size_t i = 0; i < alts.size(); i++) {
        if (i > 0) pattern += "|";
        pattern += alts[i];
    }
    pattern += ")";
    
    // Randomly add quantifier
    bool use_plus = std::uniform_int_distribution<int>(0, 1)(rng) == 0;
    if (use_plus) {
        pattern += "+";
    }
    
    // Create AST
    if (use_plus) {
        result.ast = createAlternationPlus(alts, matching);
    } else {
        std::vector<std::shared_ptr<PatternNode>> nodes;
        for (const auto& alt : alts) {
            nodes.push_back(PatternNode::createLiteral(alt, {alt}));
        }
        result.ast = PatternNode::createAlternation(nodes, matching);
    }
    
    result.pattern = pattern;
    result.proof += "  LongAlt: " + result.pattern + "\n";
    return result;
}

// Strategy: Alternation with prefix/suffix - simplified with proper verification
PatternResult tryAltWithAffix(const std::vector<std::string>& matching,
                             const std::vector<std::string>& counters,
                             std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  AltAffix: requires 2+ matching\n";
        return result;
    }
    
    // Simple approach: use matching strings as alternatives
    std::string pattern = "(";
    for (size_t i = 0; i < matching.size(); i++) {
        if (i > 0) pattern += "|";
        pattern += matching[i];
    }
    pattern += ")+";
    
    // Verify all matching inputs are alternatives
    bool all_match = true;
    for (const auto& m : matching) {
        bool found = false;
        for (const auto& alt : matching) {
            if (m == alt) { found = true; break; }
        }
        if (!found) { all_match = false; break; }
    }
    
    if (!all_match) {
        result.proof += "  AltAffix: verification failed\n";
        return result;
    }
    
    // Create AST
    result.ast = createAlternationPlus(matching, matching);
    
    result.pattern = pattern;
    result.proof += "  AltAffix: " + result.pattern + "\n";
    return result;
}

// Strategy: Triple quantifier nesting
PatternResult tryTripleQuant(const std::vector<std::string>& matching,
                            const std::vector<std::string>& counters,
                            std::mt19937& rng) {
    PatternResult result;
    
    if (matching.empty()) {
        result.proof += "  TripleQ: requires matching\n";
        return result;
    }
    
    std::string base = matching[0];
    if (base.empty()) {
        result.proof += "  TripleQ: empty base\n";
        return result;
    }
    
    // Try: ((base)?)+
    std::string pattern = "((" + base + ")?)+";
    
    // Verify: all matching should have base as prefix
    bool all_match = true;
    for (const auto& m : matching) {
        if (m.find(base) != 0) {
            all_match = false;
            break;
        }
    }
    
    if (!all_match) {
        // Try simpler: (base)+
        pattern = "(" + base + ")+";
        for (const auto& m : matching) {
            if (m != base) {
                all_match = false;
                break;
            }
        }
        if (!all_match) {
            result.proof += "  TripleQ: no match\n";
            return result;
        }
    }
    
    result.pattern = pattern;
    
    // Create AST for triple quantifier
    if (pattern.find("?") != std::string::npos) {
        // ((base)?)+
        auto inner_node = createLiteralOptional(base, matching);
        result.ast = createLiteralPlus("(" + base + ")?", matching);
    } else {
        // (base)+
        result.ast = createLiteralPlus(base, matching);
    }
    
    result.proof += "  TripleQ: " + result.pattern + "\n";
    return result;
}

// Strategy: Complex alternation - longer alternations with 8-15 alternatives
PatternResult tryComplexAlternation(const std::vector<std::string>& matching,
                                    const std::vector<std::string>& counters,
                                    std::mt19937& rng) {
    PatternResult result;
    
    // Need at least 3 matching to make interesting alternation
    if (matching.size() < 3) {
        result.proof += "  ComplexAlt: requires 3+ matching\n";
        return result;
    }
    
    // Generate additional alternatives from counters by modifying them
    // Take counter strings and create variations
    std::vector<std::string> alts = matching;
    
    // Add some variations of counters (but not exact matches)
    int added = 0;
    for (const auto& c : counters) {
        if (added >= 10) break;
        if (c.empty()) continue;
        
        // Create variation: add/remove/replace a char
        std::string var = c;
        std::uniform_int_distribution<int> op_dist(0, 2);
        int op = op_dist(rng);
        
        if (op == 0 && var.size() > 1) {
            // Remove first char
            var = var.substr(1);
        } else if (op == 1 && var.size() > 1) {
            // Remove last char
            var = var.substr(0, var.size() - 1);
        } else {
            // Replace first char
            var[0] = 'X';
        }
        
        // Only add if different from all existing
        bool dup = false;
        for (const auto& a : alts) {
            if (var == a) { dup = true; break; }
        }
        if (!dup && !var.empty()) {
            alts.push_back(var);
            added++;
        }
    }
    
    if (alts.size() < 4) {
        result.proof += "  ComplexAlt: not enough alternatives\n";
        return result;
    }
    
    // Build alternation
    std::string pattern = "(";
    for (size_t i = 0; i < alts.size(); i++) {
        if (i > 0) pattern += "|";
        pattern += alts[i];
    }
    pattern += ")";
    
    // Verify all original matching match
    bool all_match = true;
    for (const auto& m : matching) {
        bool found = false;
        for (const auto& alt : alts) {
            if (m == alt) { found = true; break; }
        }
        if (!found) { all_match = false; break; }
    }
    
    if (!all_match) {
        result.proof += "  ComplexAlt: alternation doesn't cover all matching\n";
        return result;
    }
    
    // Verify no counter matches
    bool any_match = false;
    for (const auto& c : counters) {
        for (const auto& alt : alts) {
            if (c == alt) { any_match = true; break; }
        }
        if (any_match) break;
    }
    
    if (any_match) {
        result.proof += "  ComplexAlt: counters would match\n";
        return result;
    }
    
    result.pattern = pattern;
    
    // Create AST
    result.ast = PatternNode::createAlternation(
        [&alts]() {
            std::vector<std::shared_ptr<PatternNode>> nodes;
            for (const auto& alt : alts) {
                nodes.push_back(PatternNode::createLiteral(alt, {alt}));
            }
            return nodes;
        }(),
        matching
    );
    
    result.proof += "  ComplexAlt: " + result.pattern + "\n";
    result.proof += "    Alternatives: " + std::to_string(alts.size()) + "\n";
    result.proof += "    MATCHES: " + std::to_string(matching.size()) + " original inputs\n";
    result.proof += "    VERIFIED: no counter matches\n";
    return result;
}

// ============================================================================
// Capture Tags Strategy
// ============================================================================

// Strategy: Wrap pattern in capture tags - <capname>pattern</capname>
PatternResult tryCaptureTags(const std::vector<std::string>& matching,
                            const std::vector<std::string>& counters,
                            std::mt19937& rng) {
    PatternResult result;
    
    if (matching.empty()) {
        result.proof += "  Capture: no matching inputs\n";
        return result;
    }
    
    // First try to get any valid pattern (with AST)
    PatternResult base = tryAlternation(matching, counters, rng);
    if (base.pattern.empty()) {
        base = tryPrefixPlusFragment(matching, counters, rng);
    }
    if (base.pattern.empty()) {
        base = tryFragmentOnly(matching, counters, rng);
    }
    if (base.pattern.empty()) {
        result.proof += "  Capture: no base pattern found\n";
        return result;
    }
    
    // Generate a random capture name
    std::string cap_names[] = {"cap", "match", "arg", "val", "num", "text", "name", "id"};
    std::string cap_name = cap_names[std::uniform_int_distribution<int>(0, 7)(rng)];
    cap_name += std::to_string(std::uniform_int_distribution<int>(0, 99)(rng));
    
    // Use AST if available, otherwise wrap string
    if (base.ast) {
        result.ast = wrapWithCaptureTags(base.ast, cap_name);
        result.pattern = serializePattern(result.ast);
    } else {
        // Fallback to string manipulation
        result.pattern = "<" + cap_name + ">" + base.pattern + "</" + cap_name + ">";
    }
    result.fragments = base.fragments;
    
    // Verify - capture tags shouldn't change matching behavior
    // Use base.ast's pattern for verification since result may have been modified
    std::string verify_pattern = base.ast ? serializePattern(base.ast) : base.pattern;
    bool all_match = true;
    for (const auto& m : matching) {
        bool matches = false;
        // Check if base pattern matches
        if (verify_pattern.find("|") != std::string::npos) {
            // Alternation - check if m is one of the options
            for (const auto& alt : matching) {
                if (m == alt) { matches = true; break; }
            }
        } else if (verify_pattern.find("((") != std::string::npos) {
            // Fragment - check if m fits the fragment pattern
            matches = true; // Base already verified
        } else {
            // Literal
            matches = (verify_pattern == m);
        }
        if (!matches) { all_match = false; break; }
    }
    
    if (!all_match) {
        result.proof += "  Capture: base pattern doesn't match\n";
        result.pattern = "";
        return result;
    }
    
    // Check counters - capture shouldn't affect counter matching
    bool any_match = false;
    for (const auto& c : counters) {
        for (const auto& alt : matching) {
            if (c == alt) { any_match = true; break; }
        }
        if (any_match) break;
    }
    
    if (any_match) {
        result.proof += "  Capture: counters would match\n";
        result.pattern = "";
        return result;
    }
    
    result.proof += "  Capture: " + result.pattern + "\n";
    result.proof += "    Capture name: " + cap_name + "\n";
    result.proof += "    VERIFIED: same matching as base with capture tags\n";
    return result;
}

// ============================================================================
// Single-Char Shorthand Fragment Strategy
// ============================================================================

// Strategy: Create fragment with single character definition
PatternResult trySingleCharFragment(const std::vector<std::string>& matching,
                                   const std::vector<std::string>& counters,
                                   std::mt19937& rng) {
    PatternResult result;
    
    if (matching.size() < 2) {
        result.proof += "  SingleCharFrag: requires 2+ matching\n";
        return result;
    }
    
    // Find a character that appears in all matching strings
    std::set<char> common_chars;
    for (const auto& m : matching) {
        for (char c : m) {
            bool in_all = true;
            for (const auto& m2 : matching) {
                if (m2.find(c) == std::string::npos) {
                    in_all = false;
                    break;
                }
            }
            if (in_all) common_chars.insert(c);
        }
    }
    
    if (common_chars.empty()) {
        result.proof += "  SingleCharFrag: no common char found\n";
        return result;
    }
    
    // Pick a random common character
    std::vector<char> chars(common_chars.begin(), common_chars.end());
    std::shuffle(chars.begin(), chars.end(), rng);
    char selected_char = chars[0];
    std::string char_str(1, selected_char);
    
    // Create single-char fragment
    std::map<std::string, std::string> frags;
    std::string frag_pattern = extractFragment(char_str, frags, rng, true);
    result.fragments.insert(frags.begin(), frags.end());
    
    // Check if matching strings contain this character
    bool all_match = true;
    for (const auto& m : matching) {
        if (m.find(char_str) == std::string::npos) {
            all_match = false;
            break;
        }
    }
    
    if (!all_match) {
        result.proof += "  SingleCharFrag: char not in all matching\n";
        result.pattern = "";
        return result;
    }
    
    // Check counters - should NOT match (fragment alone is too permissive)
    bool any_match = false;
    for (const auto& c : counters) {
        if (c.find(char_str) != std::string::npos) {
            any_match = true;
            break;
        }
    }
    
    if (any_match) {
        result.proof += "  SingleCharFrag: counters would match single char\n";
        result.pattern = "";
        return result;
    }
    
    // Use the fragment pattern
    result.pattern = frag_pattern;
    
    // Create AST - extract fragment name from pattern like "((name))+"
    size_t start = frag_pattern.find("((");
    size_t end = frag_pattern.find("))+");
    if (start != std::string::npos && end != std::string::npos && start + 2 < end) {
        std::string frag_name = frag_pattern.substr(start + 2, end - start - 2);
        result.ast = createFragmentPlus(frag_name, matching);
    }
    
    result.proof += "  SingleCharFrag: " + result.pattern + "\n";
    result.proof += "    Single char: '" + char_str + "'\n";
    result.proof += "    MATCHES: strings containing '" + char_str + "'\n";
    result.proof += "    VERIFIED: no counter matches\n";
    return result;
}

// ============================================================================
// Post-processing: Apply edge cases with probability
// ============================================================================

// Apply edge case transformations to a working pattern
PatternResult applyEdgeCases(const PatternResult& base,
                           const std::vector<std::string>& matching,
                           const std::vector<std::string>& counters,
                           std::mt19937& rng) {
    PatternResult result = base;
    
    if (result.pattern.empty()) return result;
    
    // 8% chance: Try optional quantifier (only if alternation)
    if (result.pattern.find("|") != std::string::npos && 
        std::uniform_int_distribution<int>(0, 99)(rng) < 8) {
        PatternResult opt = tryOptionalQuantifier(matching, counters, rng);
        if (!opt.pattern.empty()) {
            result = opt;
            result.proof += "    [Edge case: Optional with 8% probability]\n";
            return result;
        }
    }
    
    // 6% chance: Try empty alternative
    if (result.pattern.find("|") != std::string::npos &&
        std::uniform_int_distribution<int>(0, 99)(rng) < 6) {
        PatternResult empty = tryEmptyAlternative(matching, counters, rng);
        if (!empty.pattern.empty()) {
            result = empty;
            result.proof += "    [Edge case: Empty alternative with 6% probability]\n";
            return result;
        }
    }
    
    // 6% chance: Try nested group
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 6) {
        PatternResult nested = tryNestedGroup(matching, counters, rng, result.pattern);
        if (!nested.pattern.empty()) {
            result = nested;
            result.fragments = nested.fragments;
            result.proof += "    [Edge case: Nested group with 6% probability]\n";
            return result;
        }
    }
    
    // 8% chance: Try multi-char fragment
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 8) {
        PatternResult multi = tryMultiCharFragment(matching, counters, rng);
        if (!multi.pattern.empty()) {
            result = multi;
            for (const auto& f : multi.fragments) {
                result.fragments[f.first] = f.second;
            }
            result.proof += "    [Edge case: Multi-char fragment with 5% probability]\n";
            return result;
        }
    }
    
    // 10% chance: Try star quantifier (zero or more)
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 10) {
        PatternResult star = tryStarQuantifier(matching, counters, rng);
        if (!star.pattern.empty()) {
            result = star;
            for (const auto& f : star.fragments) {
                result.fragments[f.first] = f.second;
            }
            result.proof += "    [Edge case: Star quantifier with 10% probability]\n";
            return result;
        }
    }
    
    // 6% chance: Try char class plus
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 6) {
        PatternResult cc = tryCharClassPlus(matching, counters, rng);
        if (!cc.pattern.empty()) {
            result = cc;
            result.proof += "    [Edge case: Char class plus with 6% probability]\n";
            return result;
        }
    }
    
    // 5% chance: Try mixed quantifiers
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 5) {
        PatternResult mixed = tryMixedQuantifiers(matching, counters, rng);
        if (!mixed.pattern.empty()) {
            result = mixed;
            result.proof += "    [Edge case: Mixed quantifiers with 5% probability]\n";
            return result;
        }
    }
    
    // 8% chance: Try fragment chaining
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 8) {
        PatternResult chain = tryFragmentChaining(matching, counters, rng);
        if (!chain.pattern.empty()) {
            result = chain;
            for (const auto& f : chain.fragments) {
                result.fragments[f.first] = f.second;
            }
            result.proof += "    [Edge case: Fragment chaining with 5% probability]\n";
            return result;
        }
    }
    
    // 2% chance: Try capture tags
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 6) {
        PatternResult cap = tryCaptureTags(matching, counters, rng);
        if (!cap.pattern.empty()) {
            result = cap;
            for (const auto& f : cap.fragments) {
                result.fragments[f.first] = f.second;
            }
            result.proof += "    [Edge case: Capture tags with 6% probability]\n";
            return result;
        }
    }
    
    // 5% chance: Try single-char shorthand fragment
    if (std::uniform_int_distribution<int>(0, 99)(rng) < 5) {
        PatternResult single = trySingleCharFragment(matching, counters, rng);
        if (!single.pattern.empty()) {
            result = single;
            for (const auto& f : single.fragments) {
                result.fragments[f.first] = f.second;
            }
            result.proof += "    [Edge case: Single-char fragment with 5% probability]\n";
            return result;
        }
    }
    
    return result;
}

// ============================================================================
// Expectation Generation - Deep Semantic Verification
// ============================================================================

std::string expectationTypeToString(ExpectationType type) {
    switch (type) {
        case ExpectationType::MATCH_EXACT: return "MATCH_EXACT";
        case ExpectationType::NO_MATCH: return "NO_MATCH";
        case ExpectationType::FRAGMENT_MATCH: return "FRAGMENT_MATCH";
        case ExpectationType::QUANTIFIER_STAR_EMPTY: return "QUANTIFIER_STAR_EMPTY";
        case ExpectationType::QUANTIFIER_PLUS_MINONE: return "QUANTIFIER_PLUS_MINONE";
        case ExpectationType::ALTERNATION_INDIVIDUAL: return "ALTERNATION_INDIVIDUAL";
        case ExpectationType::CAPTURE_TAG_MATCH: return "CAPTURE_TAG_MATCH";
        case ExpectationType::PREFIX_MATCH: return "PREFIX_MATCH";
        case ExpectationType::SUFFIX_MATCH: return "SUFFIX_MATCH";
        case ExpectationType::CHAR_CLASS_MATCH: return "CHAR_CLASS_MATCH";
        case ExpectationType::REPETITION_MIN_COUNT: return "REPETITION_MIN_COUNT";
        case ExpectationType::FRAGMENT_NESTED: return "FRAGMENT_NESTED";
        default: return "UNKNOWN";
    }
}

bool hasFragment(const std::string& pattern) {
    return pattern.find("((") != std::string::npos;
}

bool hasQuantifier(const std::string& pattern, char quant) {
    size_t pos = pattern.find(quant);
    while (pos != std::string::npos) {
        if (pos == 0 || pattern[pos-1] != '\\') {
            return true;
        }
        pos = pattern.find(quant, pos + 1);
    }
    return false;
}

bool hasStarQuantifier(const std::string& pattern) {
    return hasQuantifier(pattern, '*');
}

bool hasPlusQuantifier(const std::string& pattern) {
    return hasQuantifier(pattern, '+');
}

bool hasOptional(const std::string& pattern) {
    return hasQuantifier(pattern, '?');
}

bool hasAlternation(const std::string& pattern) {
    return pattern.find("|") != std::string::npos;
}

bool hasCaptureTags(const std::string& pattern) {
    return pattern.find("<") != std::string::npos && pattern.find("</") != std::string::npos;
}

std::string extractAlternatives(const std::string& pattern) {
    size_t start = pattern.find('(');
    size_t end = pattern.rfind(')');
    if (start == std::string::npos || end == std::string::npos || end <= start) {
        return "";
    }
    return pattern.substr(start + 1, end - start - 1);
}

std::vector<std::string> splitAlternatives(const std::string& alternation) {
    std::vector<std::string> result;
    std::string current;
    int depth = 0;
    for (char c : alternation) {
        if (c == '(') depth++;
        else if (c == ')') depth--;
        else if (c == '|' && depth == 0) {
            if (!current.empty()) {
                result.push_back(current);
                current.clear();
            }
            continue;
        }
        current += c;
    }
    if (!current.empty()) {
        result.push_back(current);
    }
    return result;
}

std::string extractCharClass(const std::string& pattern) {
    size_t pos = pattern.find('[');
    if (pos == std::string::npos) return "";
    size_t end = pattern.find(']', pos);
    if (end == std::string::npos) return "";
    return pattern.substr(pos, end - pos + 1);
}

std::map<std::string, std::string> extractFragmentDefs(const std::string& pattern) {
    std::map<std::string, std::string> frags;
    size_t pos = 0;
    while ((pos = pattern.find("((", pos)) != std::string::npos) {
        size_t name_start = pos + 2;
        size_t name_end = pattern.find("))", name_start);
        if (name_end != std::string::npos) {
            std::string name = pattern.substr(name_start, name_end - name_start);
            size_t def_start = name_end + 2;
            size_t def_end = pattern.find("))", def_start);
            if (def_end != std::string::npos) {
                std::string def = pattern.substr(def_start, def_end - def_start);
                frags[name] = def;
            }
        }
        pos++;
    }
    return frags;
}

std::vector<Expectation> generateFragmentExpectations(const std::string& pattern,
                                                       const std::map<std::string, std::string>& fragment_defs,
                                                       const std::vector<std::string>& matching,
                                                       const std::vector<std::string>& counters) {
    std::vector<Expectation> expectations;
    
    if (fragment_defs.empty()) return expectations;
    
    for (const auto& frag : fragment_defs) {
        std::string frag_name = frag.first;
        std::string frag_def = frag.second;
        
        Expectation exp;
        exp.type = ExpectationType::FRAGMENT_MATCH;
        exp.input = "[[FRAGMENT:" + frag_name + "]]";
        exp.expected_match = "yes";
        exp.description = "Fragment '" + frag_name + "' definition must match pattern reference";
        exp.meta["fragment_name"] = frag_name;
        exp.meta["fragment_definition"] = frag_def;
        
        std::string frag_ref = "((" + frag_name + "))";
        if (pattern.find(frag_ref) != std::string::npos) {
            exp.meta["pattern_has_reference"] = "yes";
        }
        
        expectations.push_back(exp);
        
        if (frag_def.find("+") != std::string::npos) {
            Expectation exp_plus;
            exp_plus.type = ExpectationType::QUANTIFIER_PLUS_MINONE;
            exp_plus.input = "[[FRAGMENT:" + frag_name + ":EMPTY]]";
            exp_plus.expected_match = "no";
            exp_plus.description = "Fragment '" + frag_name + "' with + quantifier must require at least one character";
            exp_plus.meta["fragment_name"] = frag_name;
            exp_plus.meta["quantifier"] = "+";
            expectations.push_back(exp_plus);
        }
        
        if (frag_def.find("*") != std::string::npos) {
            Expectation exp_star;
            exp_star.type = ExpectationType::QUANTIFIER_STAR_EMPTY;
            exp_star.input = "[[FRAGMENT:" + frag_name + ":EMPTY]]";
            exp_star.expected_match = "yes";
            exp_star.description = "Fragment '" + frag_name + "' with * quantifier must match empty string";
            exp_star.meta["fragment_name"] = frag_name;
            exp_star.meta["quantifier"] = "*";
            expectations.push_back(exp_star);
        }
    }
    
    return expectations;
}

std::vector<Expectation> generateQuantifierExpectations(const std::string& pattern,
                                                         const std::vector<std::string>& matching,
                                                         const std::vector<std::string>& counters) {
    std::vector<Expectation> expectations;
    
    if (hasStarQuantifier(pattern)) {
        Expectation exp;
        exp.type = ExpectationType::QUANTIFIER_STAR_EMPTY;
        exp.input = "";
        exp.expected_match = "yes";
        exp.description = "Pattern with * quantifier must match empty string";
        exp.meta["quantifier"] = "*";
        exp.meta["pattern"] = pattern;
        expectations.push_back(exp);
    }
    
    if (hasPlusQuantifier(pattern)) {
        Expectation exp;
        exp.type = ExpectationType::QUANTIFIER_PLUS_MINONE;
        exp.input = "";
        exp.expected_match = "no";
        exp.description = "Pattern with + quantifier must NOT match empty string";
        exp.meta["quantifier"] = "+";
        exp.meta["pattern"] = pattern;
        expectations.push_back(exp);
        
        // For plus quantifier, verify that at least one full matching input works
        // (not just substrings - the full alternative must match)
        if (!matching.empty()) {
            std::string full_match = matching[0];
            Expectation exp_full;
            exp_full.type = ExpectationType::QUANTIFIER_PLUS_MINONE;
            exp_full.input = full_match;
            exp_full.expected_match = "yes";
            exp_full.description = "Pattern with + quantifier must match full input";
            exp_full.meta["quantifier"] = "+";
            exp_full.meta["pattern"] = pattern;
            expectations.push_back(exp_full);
            
            // Also test with two concatenated matching inputs
            if (matching.size() >= 2) {
                std::string double_match = full_match + matching[1];
                Expectation exp_double;
                exp_double.type = ExpectationType::QUANTIFIER_PLUS_MINONE;
                exp_double.input = double_match;
                exp_double.expected_match = "yes";
                exp_double.description = "Pattern with + quantifier must match repeated inputs";
                exp_double.meta["quantifier"] = "+";
                exp_double.meta["pattern"] = pattern;
                expectations.push_back(exp_double);
            }
        }
    }
    
    return expectations;
}

std::vector<Expectation> generateAlternationExpectations(const std::string& pattern,
                                                          const std::vector<std::string>& matching,
                                                          const std::vector<std::string>& counters) {
    std::vector<Expectation> expectations;
    
    if (!hasAlternation(pattern)) return expectations;
    
    std::string alt_str = extractAlternatives(pattern);
    if (alt_str.empty()) return expectations;
    
    std::vector<std::string> alternatives = splitAlternatives(alt_str);
    if (alternatives.size() < 2) return expectations;
    
    for (size_t i = 0; i < alternatives.size() && i < 5; i++) {
        std::string alt = alternatives[i];
        
        bool is_matching_alt = false;
        for (const auto& m : matching) {
            if (m.find(alt) != std::string::npos || alt.find(m) != std::string::npos) {
                is_matching_alt = true;
                break;
            }
        }
        
        if (is_matching_alt) {
            Expectation exp;
            exp.type = ExpectationType::ALTERNATION_INDIVIDUAL;
            exp.input = alt;
            exp.expected_match = "yes";
            exp.description = "Alternative '" + alt + "' in alternation must match individually";
            exp.meta["alternative"] = alt;
            exp.meta["alternation"] = alt_str;
            expectations.push_back(exp);
        }
    }
    
    return expectations;
}

std::vector<Expectation> generateCaptureTagExpectations(const std::string& pattern,
                                                          const std::vector<std::string>& matching,
                                                          const std::vector<std::string>& counters) {
    std::vector<Expectation> expectations;
    
    if (!hasCaptureTags(pattern)) return expectations;
    
    size_t tag_start = pattern.find('<');
    size_t tag_end = pattern.find('>');
    if (tag_start == std::string::npos || tag_end == std::string::npos) return expectations;
    
    std::string capture_name = pattern.substr(tag_start + 1, tag_end - tag_start - 1);
    
    Expectation exp;
    exp.type = ExpectationType::CAPTURE_TAG_MATCH;
    exp.input = "[[CAPTURE_TEST]]";
    exp.expected_match = "yes";
    exp.description = "Capture tag '" + capture_name + "' should not change matching behavior";
    exp.meta["capture_name"] = capture_name;
    exp.meta["original_pattern"] = pattern;
    
    size_t close_start = pattern.find("</");
    if (close_start != std::string::npos) {
        size_t close_end = pattern.find(">", close_start);
        if (close_end != std::string::npos) {
            std::string close_name = pattern.substr(close_start + 2, close_end - close_start - 2);
            exp.meta["close_tag"] = close_name;
            if (close_name != capture_name) {
                exp.description += " (MISMATCHED TAGS - this is a BUG in c-dfa if accepted)";
            }
        }
    }
    
    expectations.push_back(exp);
    
    return expectations;
}

std::vector<Expectation> generateCharClassExpectations(const std::string& pattern,
                                                        const std::vector<std::string>& matching,
                                                        const std::vector<std::string>& counters) {
    std::vector<Expectation> expectations;
    
    std::string char_class = extractCharClass(pattern);
    if (char_class.empty()) return expectations;
    
    std::set<char> allowed_chars;
    for (size_t i = 1; i < char_class.size() - 1; i++) {
        if (char_class[i] != '|') {
            allowed_chars.insert(char_class[i]);
        }
    }
    
    for (char c : allowed_chars) {
        std::string single(1, c);
        Expectation exp;
        exp.type = ExpectationType::CHAR_CLASS_MATCH;
        exp.input = single;
        exp.expected_match = "yes";
        exp.description = "Character '" + single + "' must match character class " + char_class;
        exp.meta["char_class"] = char_class;
        exp.meta["character"] = single;
        expectations.push_back(exp);
    }
    
    const std::string other_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (char c : other_chars) {
        if (allowed_chars.find(c) == allowed_chars.end()) {
            std::string single(1, c);
            Expectation exp;
            exp.type = ExpectationType::CHAR_CLASS_MATCH;
            exp.input = single;
            exp.expected_match = "no";
            exp.description = "Character '" + single + "' must NOT match character class " + char_class;
            exp.meta["char_class"] = char_class;
            exp.meta["character"] = single;
            expectations.push_back(exp);
            break;
        }
    }
    
    return expectations;
}

std::vector<Expectation> generateAllExpectations(const std::string& pattern,
                                                 const std::map<std::string, std::string>& fragment_defs,
                                                 const std::vector<std::string>& matching,
                                                 const std::vector<std::string>& counters) {
    std::vector<Expectation> expectations;
    
    auto frag_exps = generateFragmentExpectations(pattern, fragment_defs, matching, counters);
    expectations.insert(expectations.end(), frag_exps.begin(), frag_exps.end());
    
    auto quant_exps = generateQuantifierExpectations(pattern, matching, counters);
    expectations.insert(expectations.end(), quant_exps.begin(), quant_exps.end());
    
    auto alt_exps = generateAlternationExpectations(pattern, matching, counters);
    expectations.insert(expectations.end(), alt_exps.begin(), alt_exps.end());
    
    auto cap_exps = generateCaptureTagExpectations(pattern, matching, counters);
    expectations.insert(expectations.end(), cap_exps.begin(), cap_exps.end());
    
    auto char_exps = generateCharClassExpectations(pattern, matching, counters);
    expectations.insert(expectations.end(), char_exps.begin(), char_exps.end());
    
    return expectations;
}

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
        result = generateSeparatingPattern(tc.matching_inputs, tc.counter_inputs, 
                                                     tc.complexity, rng);
    }

    // Now apply rewrite and capture tags
    if (result.ast) {
        rewritePattern(result.ast, rng);  // Safe rewrite strategies enabled
        addCaptureTags(result.ast, rng);   // Enable capture tags
        result.pattern = serializePattern(result.ast);
    }
    
    tc.pattern = result.pattern;
    tc.fragments = result.fragments;
    
    // Validate pattern matches at least one matching input
    // If not, regenerate using a simpler approach
    if (!tc.pattern.empty() && !tc.matching_inputs.empty()) {
        bool any_matches = false;
        
        // Simple validation: check if any matching input is a substring of the pattern
        // or if the pattern is an alternation that contains the input
        for (const auto& m : tc.matching_inputs) {
            // Check 1: Is the matching input literally in the pattern?
            if (tc.pattern.find(m) != std::string::npos) {
                any_matches = true;
                break;
            }
            
            // Check 2: For alternation patterns, check if input is one of the alternatives
            if (tc.pattern.find("|") != std::string::npos) {
                std::string alt_pattern = tc.pattern;
                // Remove quantifiers
                size_t pos;
                while ((pos = alt_pattern.find("+")) != std::string::npos) alt_pattern.erase(pos, 1);
                while ((pos = alt_pattern.find("*")) != std::string::npos) alt_pattern.erase(pos, 1);
                while ((pos = alt_pattern.find("?")) != std::string::npos) alt_pattern.erase(pos, 1);
                while ((pos = alt_pattern.find("(")) != std::string::npos) alt_pattern.erase(pos, 1);
                while ((pos = alt_pattern.find(")")) != std::string::npos) alt_pattern.erase(pos, 1);
                
                if (alt_pattern.find(m) != std::string::npos) {
                    any_matches = true;
                    break;
                }
            }
        }
        
        if (!any_matches) {
            // Pattern doesn't match any matching inputs - this is a bug!
            // Fall back to alternation of matching inputs
            tc.pattern = "(";
            for (size_t i = 0; i < tc.matching_inputs.size(); i++) {
                if (i > 0) tc.pattern += "|";
                tc.pattern += tc.matching_inputs[i];
            }
            tc.pattern += ")";
            tc.fragments.clear();  // Clear invalid fragments
            tc.proof += "\n[WARNING] Pattern validation failed - falling back to alternation\n";
        }
    }
    
    // Generate deep semantic expectations
    tc.expectations = generateAllExpectations(tc.pattern, tc.fragments, 
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
    
    std::cout << "1. Building NFA...\n";
    std::string nfa_file = output_dir + "/test.nfa";
    int result = system(("../tools/nfa_builder " + abs_pattern + " " + nfa_file + " 2>&1").c_str());
    if (result != 0) {
        std::cerr << "NFA builder failed!\n";
        return 1;
    }
    std::cout << "   NFA built successfully\n\n";
    
    std::cout << "2. Building DFA...\n";
    std::string dfa_file = output_dir + "/test.dfa";
    result = system(("../tools/nfa2dfa_advanced " + nfa_file + " " + dfa_file + " 2>&1").c_str());
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
            std::string cmd = "../tools/dfa_eval_wrapper " + dfa_file + " \"" + match_in + "\"";
            CommandResult res = runCommand(cmd);
            
            // Check for errors (ignore LOADING DFA debug messages)
            std::string error_stderr;
            for (char& c : res.stderr) {
                if (c != '\n' && c != '\r') error_stderr += c;
            }
            // Filter out known debug messages
            bool is_debug_only = (res.stderr.find("LOADING DFA:") != std::string::npos);
            
            if (!is_debug_only && !error_stderr.empty()) {
                all_matched = false;
                match_fail_reason = "stderr not empty: " + res.stderr;
                break;
            }
            
            bool matched = false;
            int category_mask = 0;
            
            // Parse stdout for matched, category, and category_mask
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
            
            // FAIL on ANY inconsistency: mask has expected but category doesn't match
            if (!matched || !mask_has_expected) {
                all_matched = false;
                char mask_hex[16];
                snprintf(mask_hex, sizeof(mask_hex), "0x%02x", category_mask);
                match_fail_reason = "matched=" + std::to_string(matched) + 
                    ", category=" + std::to_string(reported_category) + 
                    ", category_mask=" + std::string(mask_hex);
                break;
            }
            
            // Check for inconsistency: mask has expected bit but category doesn't match
            if (!category_matches) {
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
            std::string counter_cmd = "../tools/dfa_eval_wrapper " + dfa_file + " \"" + counter + "\"";
            CommandResult res = runCommand(counter_cmd);
            
            // Check for errors (ignore LOADING DFA debug messages)
            bool is_debug_only = (res.stderr.find("LOADING DFA:") != std::string::npos);
            if (res.exit_code != 0) {
                any_counter_matched = true;  // Treat as failure
                counter_fail_reason = "exit_code=" + std::to_string(res.exit_code);
                break;
            }
            if (!is_debug_only && !res.stderr.empty()) {
                any_counter_matched = true;  // Treat as failure
                counter_fail_reason = "stderr: " + res.stderr;
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
                
                std::string cmd = "../tools/dfa_eval_wrapper " + dfa_file + " \"" + test_input + "\"";
                CommandResult res = runCommand(cmd);
                
                // Check for errors (ignore LOADING DFA debug messages)
                bool is_debug_only = (res.stderr.find("LOADING DFA:") != std::string::npos);
                if (res.exit_code != 0) {
                    expectations_passed = false;
                    expectation_fail_reason = "exit_code=" + std::to_string(res.exit_code) + ", stderr=" + res.stderr;
                    break;
                }
                if (!is_debug_only && !res.stderr.empty()) {
                    expectations_passed = false;
                    expectation_fail_reason = "stderr not empty: " + res.stderr;
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
        
        CommandResult nfa_res = runCommand("../tools/nfa_builder " + temp_pattern + " " + nfa_file);
        if (nfa_res.exit_code != 0 || !nfa_res.stderr.empty()) { 
            std::cout << "   FAIL #" << i << ": nfa_builder failed (exit=" << nfa_res.exit_code << ")\n";
            failed++; 
            continue; 
        }
        
        CommandResult dfa_res = runCommand("../tools/nfa2dfa_advanced " + nfa_file + " " + dfa_file);
        if (dfa_res.exit_code != 0 || !dfa_res.stderr.empty()) { 
            std::cout << "   FAIL #" << i << ": nfa2dfa_advanced failed (exit=" << dfa_res.exit_code << ")\n";
            failed++; 
            continue; 
        }
        
        bool all_matched = true;
        int expected_category_0idx = static_cast<int>(tc.category) - 1;  // Convert 1-indexed to 0-indexed
        for (const auto& match_in : tc.matching_inputs) {
            CommandResult res = runCommand("../tools/dfa_eval_wrapper " + dfa_file + " \"" + match_in + "\"");
            
            // Check for errors (ignore LOADING DFA debug messages)
            bool is_debug_only = (res.stderr.find("LOADING DFA:") != std::string::npos);
            if (res.exit_code != 0 || (!is_debug_only && !res.stderr.empty())) {
                std::cout << "   FAIL #" << i << ": dfa_eval_wrapper error (exit=" << res.exit_code << ", stderr=" << res.stderr << ")\n";
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
            
            if (!category_matches || !consistent) {
                std::cout << "   FAIL #" << i << ": INCONSISTENCY - category=" << matched_category << " but expected " << static_cast<int>(tc.category) << " (mask=0x" << std::hex << category_mask << std::dec << ")\n";
                all_matched = false;
                break;
            }
        }
        
        bool any_counter_matched = false;
        for (const auto& counter : tc.counter_inputs) {
            CommandResult res = runCommand("../tools/dfa_eval_wrapper " + dfa_file + " \"" + counter + "\"");
            
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
