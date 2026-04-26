// ============================================================================
// ValidationHelpers - Pattern matching validators and factory functions
// Extracted from pattern_strategies.cpp
// ============================================================================

#include "validation_helpers.h"
#include "testgen.h"

#include <algorithm>
#include <set>

using namespace std;

// ============================================================================
// Validation Helpers - Check if pattern matches input
// ============================================================================

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

// Create quantified alternation: (alt1|alt2|alt3)+
std::shared_ptr<PatternNode> createQuantifiedAlternation(
    const std::vector<std::string>& alts,
    PatternType type,
    const std::vector<std::string>& seeds) {
    
    std::vector<std::shared_ptr<PatternNode>> alt_nodes;
    for (const auto& alt : alts) {
        alt_nodes.push_back(PatternNode::createLiteral(alt, {alt}));
    }
    auto alt_node = PatternNode::createAlternation(alt_nodes, seeds);
    alt_node->type = type;
    alt_node->quantified = PatternNode::createAlternation(alt_nodes, seeds);
    return alt_node;
}

// Create quantified literal: (literal)+
std::shared_ptr<PatternNode> createQuantifiedLiteral(
    const std::string& literal,
    PatternType type,
    const std::vector<std::string>& seeds) {
    
    auto lit_node = PatternNode::createLiteral(literal, seeds);
    lit_node->type = type;
    lit_node->quantified = PatternNode::createLiteral(literal, seeds);
    return lit_node;
}

// Create quantified fragment: [[frag]]+
std::shared_ptr<PatternNode> createQuantifiedFragment(
    const std::string& frag_name,
    PatternType type,
    const std::vector<std::string>& seeds) {
    
    auto frag_node = PatternNode::createFragment(frag_name, seeds);
    frag_node->type = type;
    frag_node->quantified = PatternNode::createFragment(frag_name, seeds);
    return frag_node;
}

// Convenience wrappers for quantified alternations
std::shared_ptr<PatternNode> createAlternationPlus(const std::vector<std::string>& alts, const std::vector<std::string>& seeds) {
    return createQuantifiedAlternation(alts, PatternType::PLUS_QUANTIFIER, seeds);
}

std::shared_ptr<PatternNode> createAlternationStar(const std::vector<std::string>& alts, const std::vector<std::string>& seeds) {
    return createQuantifiedAlternation(alts, PatternType::STAR_QUANTIFIER, seeds);
}

std::shared_ptr<PatternNode> createAlternationOptional(const std::vector<std::string>& alts, const std::vector<std::string>& seeds) {
    return createQuantifiedAlternation(alts, PatternType::OPTIONAL, seeds);
}

// Convenience wrappers for quantified literals
std::shared_ptr<PatternNode> createLiteralPlus(const std::string& literal, const std::vector<std::string>& seeds) {
    return createQuantifiedLiteral(literal, PatternType::PLUS_QUANTIFIER, seeds);
}

std::shared_ptr<PatternNode> createLiteralStar(const std::string& literal, const std::vector<std::string>& seeds) {
    return createQuantifiedLiteral(literal, PatternType::STAR_QUANTIFIER, seeds);
}

std::shared_ptr<PatternNode> createLiteralOptional(const std::string& literal, const std::vector<std::string>& seeds) {
    return createQuantifiedLiteral(literal, PatternType::OPTIONAL, seeds);
}

// Convenience wrappers for quantified fragments
std::shared_ptr<PatternNode> createFragmentPlus(const std::string& frag_name, const std::vector<std::string>& seeds) {
    return createQuantifiedFragment(frag_name, PatternType::PLUS_QUANTIFIER, seeds);
}

std::shared_ptr<PatternNode> createFragmentStar(const std::string& frag_name, const std::vector<std::string>& seeds) {
    return createQuantifiedFragment(frag_name, PatternType::STAR_QUANTIFIER, seeds);
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

// Determine if a string looks like a character class definition (e.g., "abc", "[xyz]")
static bool looksLikeCharClass(const std::string& s) {
    if (s.empty()) return false;
    // If it starts with [ and contains ], it's a char class
    if (s[0] == '[') return s.find(']') != std::string::npos;
    // If it's short and all unique characters, it's likely intended as a char class
    if (s.size() <= 10) {
        std::set<char> unique_chars(s.begin(), s.end());
        return unique_chars.size() == s.size();  // All unique = intended as char class
    }
    return false;
}

// Determine if a string is a literal (fixed string, not a character class)
static bool looksLikeLiteral(const std::string& s) {
    if (s.empty()) return false;
    // If it starts with [ but has no closing ], it's a literal
    if (s[0] == '[' && s.find(']') == std::string::npos) return true;
    // If it contains characters that suggest it's meant to be literal (e.g., repeated chars)
    if (s.size() > 3) {
        std::set<char> unique_chars(s.begin(), s.end());
        // If many duplicates relative to size, likely literal
        if (unique_chars.size() < s.size() * 0.7) return true;
    }
    return false;
}

std::string extractFragment(const std::string& input, 
                          std::map<std::string, std::string>& fragments,
                          std::mt19937& rng,
                          bool force_simple) {
    // Create unique fragment name using incrementing counter
    static int frag_counter = 0;
    std::string full_name = "frag" + std::to_string(frag_counter++);
    
    // Ensure no collision with existing fragments
    while (fragments.count(full_name)) {
        full_name = "frag" + std::to_string(frag_counter++);
    }
    
    // Determine the fragment definition
    // If input looks like a literal string (repeating chars, fixed sequence),
    // use the literal form. Otherwise, use as-is (might be a char class).
    std::string frag_def = input;
    
    if (looksLikeLiteral(input) && !force_simple) {
        // Keep as literal - it's a fixed sequence
        // Don't convert to char class
    } else if (!looksLikeCharClass(input)) {
        // Not clearly a char class - could be a literal that should be kept
        // Only convert to char class if explicitly forced
        if (force_simple) {
            // When forced, try to create a sensible char class
            std::string chars;
            for (char c : input) {
                if (chars.find(c) == std::string::npos) {
                    chars += c;
                }
            }
            if (!chars.empty() && chars.size() < input.size()) {
                frag_def = chars;  // Use unique chars as char class
            }
        }
    }
    
    fragments[full_name] = frag_def;
    
    return "[[" + full_name + "]]+";
}
