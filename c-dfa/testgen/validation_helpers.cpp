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

// Create quantified fragment: ((frag))+
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

std::string extractFragment(const std::string& char_class, 
                          std::map<std::string, std::string>& fragments,
                          std::mt19937& rng,
                          bool force_simple) {
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
