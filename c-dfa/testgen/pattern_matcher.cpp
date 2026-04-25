// ============================================================================
// PatternMatcher - Fast in-memory pattern matching using NFA simulation
//
// Uses NFA-style set-of-positions tracking. Each match step takes a set of
// reachable input positions and returns the set of positions reachable after
// consuming the node. A full match = input.size() in the final set.
// ============================================================================

#include "pattern_matcher.h"
#include "testgen.h"
#include <algorithm>
#include <sstream>

// ============================================================================
// Internal match helpers (file scope)
// ============================================================================

// Match a literal string at all positions in the set
static std::set<size_t> matchLiteral(const std::string& lit,
                                     const std::string& input,
                                     const std::set<size_t>& positions) {
    std::set<size_t> result;
    size_t len = lit.size();
    if (len == 0) return positions;  // epsilon
    for (size_t pos : positions) {
        if (pos + len <= input.size() && input.compare(pos, len, lit) == 0) {
            result.insert(pos + len);
        }
    }
    return result;
}

// Forward declare for recursion
static std::set<size_t> nfaMatchImpl(
    const std::shared_ptr<PatternNode>& node,
    const std::string& input,
    const std::set<size_t>& positions,
    const std::map<std::string, std::string>& fragments);

// Match alternation: union of all alternatives
static std::set<size_t> matchAlternation(
    const std::shared_ptr<PatternNode>& node,
    const std::string& input,
    const std::set<size_t>& positions,
    const std::map<std::string, std::string>& fragments) {
    std::set<size_t> result;
    for (const auto& child : node->children) {
        auto child_result = nfaMatchImpl(child, input, positions, fragments);
        result.insert(child_result.begin(), child_result.end());
    }
    return result;
}

// Match sequence: thread positions through each child in order
static std::set<size_t> matchSequence(
    const std::shared_ptr<PatternNode>& node,
    const std::string& input,
    const std::set<size_t>& positions,
    const std::map<std::string, std::string>& fragments) {
    std::set<size_t> current = positions;
    for (const auto& child : node->children) {
        if (current.empty()) return {};
        current = nfaMatchImpl(child, input, current, fragments);
    }
    return current;
}

// Match optional X?: epsilon ∪ match(X)
static std::set<size_t> matchOptional(
    const std::shared_ptr<PatternNode>& node,
    const std::string& input,
    const std::set<size_t>& positions,
    const std::map<std::string, std::string>& fragments) {
    if (!node->quantified) return positions;  // epsilon only
    auto matched = nfaMatchImpl(node->quantified, input, positions, fragments);
    // Union with epsilon (positions pass through)
    std::set<size_t> result = positions;
    result.insert(matched.begin(), matched.end());
    return result;
}

// Match plus X+: one or more repetitions.
// Fixed-point: match once, then repeatedly match again from new positions.
static std::set<size_t> matchPlus(
    const std::shared_ptr<PatternNode>& node,
    const std::string& input,
    const std::set<size_t>& positions,
    const std::map<std::string, std::string>& fragments) {
    if (!node->quantified) return {};

    // First: must match at least once
    std::set<size_t> current = nfaMatchImpl(node->quantified, input, positions, fragments);
    if (current.empty()) return {};

    // Now greedily try more repetitions until no new positions are found
    std::set<size_t> all = current;
    for (;;) {
        std::set<size_t> next = nfaMatchImpl(node->quantified, input, current, fragments);
        size_t before = all.size();
        all.insert(next.begin(), next.end());
        if (all.size() == before) break;  // no new positions
        current = std::move(next);
        if (current.empty()) break;
    }
    return all;
}

// Match star X*: zero or more repetitions = epsilon ∪ X+
static std::set<size_t> matchStar(
    const std::shared_ptr<PatternNode>& node,
    const std::string& input,
    const std::set<size_t>& positions,
    const std::map<std::string, std::string>& fragments) {
    if (!node->quantified) return positions;  // epsilon only

    // Try to match at least once
    std::set<size_t> current = nfaMatchImpl(node->quantified, input, positions, fragments);

    // Greedily try more
    std::set<size_t> all = positions;  // epsilon: positions pass through
    all.insert(current.begin(), current.end());

    for (;;) {
        if (current.empty()) break;
        std::set<size_t> next = nfaMatchImpl(node->quantified, input, current, fragments);
        size_t before = all.size();
        all.insert(next.begin(), next.end());
        if (all.size() == before) break;
        current = std::move(next);
    }
    return all;
}

// Parse a simple fragment definition string into an AST.
// Handles: literals, alternations (|), quantifiers (+, *, ?),
// character classes ([abc]), groups with parentheses.
static std::shared_ptr<PatternNode> parseFragmentDef(const std::string& def) {
    if (def.empty()) {
        return PatternNode::createLiteral("");
    }
    // If the definition is just a plain string (no special chars), it's a literal
    if (def.find('(') == std::string::npos &&
        def.find('|') == std::string::npos &&
        def.find('[') == std::string::npos &&
        def.find('+') == std::string::npos &&
        def.find('*') == std::string::npos &&
        def.find('?') == std::string::npos) {
        return PatternNode::createLiteral(def);
    }
    // For complex fragment definitions, use the existing pattern parser
    return parsePatternToAST(def);
}

// Cache for parsed fragment definitions (thread-hostile, but testgen is single-threaded)
static std::map<std::string, std::shared_ptr<PatternNode>> frag_def_cache;

static std::set<size_t> matchFragmentRef(
    const std::string& frag_name,
    const std::string& input,
    const std::set<size_t>& positions,
    const std::map<std::string, std::string>& fragments) {
    auto it = fragments.find(frag_name);
    if (it == fragments.end()) return {};  // Unknown fragment = no match

    // Parse and cache the fragment definition
    std::shared_ptr<PatternNode>& cached = frag_def_cache[frag_name];
    if (!cached) {
        cached = parseFragmentDef(it->second);
    }

    return nfaMatchImpl(cached, input, positions, fragments);
}

// Main dispatch
static std::set<size_t> nfaMatchImpl(
    const std::shared_ptr<PatternNode>& node,
    const std::string& input,
    const std::set<size_t>& positions,
    const std::map<std::string, std::string>& fragments) {
    if (!node) return {};

    switch (node->type) {
    case PatternType::LITERAL:
        return matchLiteral(node->value, input, positions);
    case PatternType::ALTERNATION:
        return matchAlternation(node, input, positions, fragments);
    case PatternType::SEQUENCE:
        return matchSequence(node, input, positions, fragments);
    case PatternType::OPTIONAL:
        return matchOptional(node, input, positions, fragments);
    case PatternType::PLUS_QUANTIFIER:
        return matchPlus(node, input, positions, fragments);
    case PatternType::STAR_QUANTIFIER:
        return matchStar(node, input, positions, fragments);
    case PatternType::FRAGMENT_REF:
        return matchFragmentRef(node->fragment_name, input, positions, fragments);
    default:
        return {};
    }
}

// ============================================================================
// Public API
// ============================================================================

bool PatternMatcher::matches(const std::shared_ptr<PatternNode>& pattern,
                             const std::string& input) {
    if (!pattern) return false;
    std::set<size_t> start = {0};
    auto result = nfaMatchImpl(pattern, input, start, {});
    return result.count(input.size()) > 0;
}

bool PatternMatcher::validate(const std::shared_ptr<PatternNode>& pattern,
                              const std::vector<std::string>& matching_inputs,
                              const std::vector<std::string>& counter_inputs) {
    return validateWithFragments(pattern, matching_inputs, counter_inputs, {});
}

bool PatternMatcher::validateWithFragments(
    const std::shared_ptr<PatternNode>& pattern,
    const std::vector<std::string>& matching_inputs,
    const std::vector<std::string>& counter_inputs,
    const std::map<std::string, std::string>& fragments) {
    if (!pattern) return false;

    // Clear fragment cache for fresh validation
    frag_def_cache.clear();

    for (const auto& input : matching_inputs) {
        std::set<size_t> start = {0};
        auto result = nfaMatchImpl(pattern, input, start, fragments);
        if (result.count(input.size()) == 0) return false;
    }

    for (const auto& input : counter_inputs) {
        std::set<size_t> start = {0};
        auto result = nfaMatchImpl(pattern, input, start, fragments);
        if (result.count(input.size()) > 0) return false;
    }

    return true;
}

std::string PatternMatcher::explainFailure(
    const std::shared_ptr<PatternNode>& pattern,
    const std::vector<std::string>& matching_inputs,
    const std::vector<std::string>& counter_inputs,
    const std::map<std::string, std::string>& fragments) {
    if (!pattern) return "Pattern is null";

    frag_def_cache.clear();
    std::ostringstream reasons;

    for (const auto& input : matching_inputs) {
        std::set<size_t> start = {0};
        auto result = nfaMatchImpl(pattern, input, start, fragments);
        if (result.count(input.size()) == 0) {
            reasons << "Matching input '" << input << "' does NOT match\n";
        }
    }

    for (const auto& input : counter_inputs) {
        std::set<size_t> start = {0};
        auto result = nfaMatchImpl(pattern, input, start, fragments);
        if (result.count(input.size()) > 0) {
            reasons << "Counter input '" << input << "' MATCHES (should not)\n";
        }
    }

    return reasons.str();
}
