#include "testgen_operators.h"
#include "pattern_serializer.h"
#include "pattern_matcher.h"
#include <algorithm>
#include <map>
#include <set>
#include <functional>

namespace TestGen {

static bool findLiteralNode(std::shared_ptr<PatternNode> node, std::vector<std::shared_ptr<PatternNode>>& out) {
    if (!node) return false;
    if (node->type == PatternType::LITERAL && !node->value.empty()) {
        out.push_back(node);
        return true;
    }
    if (node->quantified) findLiteralNode(node->quantified, out);
    for (auto& child : node->children) findLiteralNode(child, out);
    return !out.empty();
}

static std::shared_ptr<PatternNode> copyNode(std::shared_ptr<PatternNode> node) {
    if (!node) return nullptr;
    auto copy = std::make_shared<PatternNode>();
    copy->type = node->type;
    copy->value = node->value;
    if (node->type == PatternType::FRAGMENT_REF) {
        copy->fragment_name = node->fragment_name;
    }
    copy->capture_tag = node->capture_tag;
    copy->capture_begin_only = node->capture_begin_only;
    copy->capture_end_only = node->capture_end_only;
    if (node->quantified) copy->quantified = copyNode(node->quantified);
    for (auto& child : node->children) copy->children.push_back(copyNode(child));
    return copy;
}

static void clearNodeSeeds(std::shared_ptr<PatternNode> node) {
    if (!node) return;
    node->matched_seeds.clear();
    node->counter_seeds.clear();
    if (node->quantified) clearNodeSeeds(node->quantified);
    for (auto& child : node->children) clearNodeSeeds(child);
}

static bool containsFragmentRef(std::shared_ptr<PatternNode> node) {
    if (!node) return false;
    if (node->type == PatternType::FRAGMENT_REF) return true;
    if (!node->fragment_name.empty()) return true;
    if (node->quantified && containsFragmentRef(node->quantified)) return true;
    for (auto& child : node->children) {
        if (containsFragmentRef(child)) return true;
    }
    return false;
}

static bool hasBalancedParens(const std::string& s) {
    int depth = 0;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            i++;
            continue;
        }
        if (s[i] == '(') depth++;
        else if (s[i] == ')') {
            depth--;
            if (depth < 0) return false;
        }
    }
    return depth == 0;
}

static bool isValidPattern(std::shared_ptr<PatternNode> node) {
    if (!node) return false;
    std::string serialized = serializePattern(node);
    return hasBalancedParens(serialized);
}

static bool hasAllFragmentDefs(std::shared_ptr<PatternNode> node, const std::map<std::string, std::string>& fragments) {
    if (!node) return true;
    if (node->type == PatternType::FRAGMENT_REF) {
        if (fragments.find(node->fragment_name) == fragments.end()) {
            return false;
        }
    }
    if (node->quantified && !hasAllFragmentDefs(node->quantified, fragments)) return false;
    for (auto& child : node->children) {
        if (!hasAllFragmentDefs(child, fragments)) return false;
    }
    return true;
}

// Ensure all FRAGMENT_REF nodes in AST have definitions in fragments map.
// When all matched_seeds are identical, uses the exact literal (sound).
// When seeds differ or are absent, marks the fragment as missing (returns false
// via a sentinel) so callers can reject the mutation/test case.
// Returns false if a fragment ref has no sound definition.
static bool ensureFragmentDefs(std::shared_ptr<PatternNode> node, std::map<std::string, std::string>& fragments) {
    if (!node) return true;
    if (node->type == PatternType::FRAGMENT_REF) {
        if (fragments.find(node->fragment_name) == fragments.end()) {
            // Only produce a sound definition when all seeds are identical
            if (!node->matched_seeds.empty()) {
                bool all_same = true;
                for (const auto& s : node->matched_seeds) {
                    if (s != node->matched_seeds[0]) { all_same = false; break; }
                }
                if (all_same) {
                    fragments[node->fragment_name] = node->matched_seeds[0];
                } else {
                    // Seeds differ — no sound definition possible, signal failure
                    return false;
                }
            } else {
                // No seeds — no sound definition possible
                return false;
            }
        }
    }
    if (node->quantified) {
        if (!ensureFragmentDefs(node->quantified, fragments)) return false;
    }
    for (auto& child : node->children) {
        if (!ensureFragmentDefs(child, fragments)) return false;
    }
    return true;
}

// Pattern matching is now handled by PatternMatcher (pattern_matcher.h)
// The old wouldMatchPattern and patternMatchesPlus/Star helpers are removed.

static std::string randomAlpha(int len, std::mt19937& rng) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result;
    for (int i = 0; i < len; i++) {
        result += charset[std::uniform_int_distribution<int>(0, sizeof(charset)-2)(rng)];
    }
    return result;
}

static std::shared_ptr<PatternNode> findTopLevelLiteral(std::shared_ptr<PatternNode> node) {
    if (!node) return nullptr;
    if (node->type == PatternType::LITERAL && !node->value.empty()) {
        return node;
    }
    if (node->type == PatternType::SEQUENCE) {
        for (auto& child : node->children) {
            if (child && child->type == PatternType::LITERAL && !child->value.empty()) {
                return child;
            }
        }
    }
    if (node->type == PatternType::ALTERNATION) {
        if (!node->children.empty() && node->children[0] &&
            node->children[0]->type == PatternType::LITERAL && !node->children[0]->value.empty()) {
            return node->children[0];
        }
    }
    return nullptr;
}

static bool findTopLevelLiterals(std::shared_ptr<PatternNode> node, std::vector<std::shared_ptr<PatternNode>>& out) {
    if (!node) return false;
    
    if (node->type == PatternType::LITERAL && !node->value.empty()) {
        out.push_back(node);
        return true;
    }
    
    if (node->type == PatternType::SEQUENCE) {
        for (auto& child : node->children) {
            if (child && child->type == PatternType::LITERAL && !child->value.empty()) {
                out.push_back(child);
            }
        }
        return !out.empty();
    }
    
    if (node->type == PatternType::ALTERNATION) {
        return false;
    }
    
    return false;
}

CoordinatedMutationResult CharSubstituteCoordOp::apply(const TestCaseCore& original, std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;
    
    if (!original.ast) return result;
    
    if (containsFragmentRef(original.ast)) return result;
    
    if (original.ast->type == PatternType::ALTERNATION ||
        original.ast->type == PatternType::PLUS_QUANTIFIER ||
        original.ast->type == PatternType::STAR_QUANTIFIER ||
        original.ast->type == PatternType::OPTIONAL) {
        return result;
    }
    
    std::vector<std::shared_ptr<PatternNode>> literals;
    if (!findTopLevelLiterals(original.ast, literals) || literals.empty()) {
        return result;
    }
    
    auto target = literals[std::uniform_int_distribution<size_t>(0, literals.size() - 1)(rng)];
    if (target->value.size() < 1) return result;
    
    int pos = std::uniform_int_distribution<int>(0, target->value.size() - 1)(rng);
    char old_char = target->value[pos];
    char new_char;
    do {
        new_char = randomAlpha(1, rng)[0];
    } while (new_char == old_char);
    
    auto mutated_ast = copyNode(original.ast);
    std::vector<std::shared_ptr<PatternNode>> copy_literals;
    findTopLevelLiterals(mutated_ast, copy_literals);
    for (auto& lit : copy_literals) {
        if (lit->value == target->value) {
            lit->value[pos] = new_char;
            break;
        }
    }
    
    std::vector<std::string> updated_matching;
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("matching")) {
            std::string updated = node.value;
            if (node.value == target->value) {
                updated[pos] = new_char;
            }
            result.mutated_tc.inputs.add(updated, {"matching"});
            updated_matching.push_back(updated);
        }
    }
    
    if (updated_matching.empty()) {
        return result;
    }
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("counter")) {
            result.mutated_tc.inputs.add(node.value, {"counter"});
        }
    }
    
    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    result.mutated_tc.proof = original.proof + " | CHAR_SUB(" + old_char + "→" + new_char + ")";
    
    Expectation e;
    e.type = ExpectationType::MATCH_EXACT;
    e.input = updated_matching[0];
    e.expected_match = "yes";
    e.description = "Char substitution at pos " + std::to_string(pos);
    result.mutated_tc.expectations.add(e);
    
    result.valid = true;
    return result;
}

CoordinatedMutationResult AddAlternativeCoordOp::apply(const TestCaseCore& original, std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;
    
    if (!original.ast) return result;
    if (containsFragmentRef(original.ast)) return result;
    
    auto ast_copy = copyNode(original.ast);
    auto first_alt = findTopLevelLiteral(ast_copy);
    if (!first_alt) {
        return result;
    }
    
    std::string new_alt_val = randomAlpha(2, rng);
    auto second_alt = PatternNode::createLiteral(new_alt_val);
    
    std::vector<std::shared_ptr<PatternNode>> new_alts = {first_alt, second_alt};
    auto alt_node = PatternNode::createAlternation(new_alts, {first_alt->value, new_alt_val});
    auto mutated_ast = PatternNode::createQuantified(alt_node, PatternType::PLUS_QUANTIFIER);
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("matching")) {
            result.mutated_tc.inputs.add(node.value, {"matching"});
        }
    }
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("counter")) {
            if (PatternMatcher::matches(mutated_ast, node.value)) {
                return result;
            }
            result.mutated_tc.inputs.add(node.value, {"counter"});
        }
    }
    
    bool has_matching = false;
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) {
            has_matching = true;
            break;
        }
    }
    if (!has_matching) return result;
    
    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    result.mutated_tc.proof = original.proof + " | ADD_ALT(+" + new_alt_val + ")";
    
    Expectation e;
    e.type = ExpectationType::ALTERNATION_INDIVIDUAL;
    e.description = "New alternative '" + new_alt_val + "'";
    e.meta["alternative"] = new_alt_val;
    e.meta["mutation"] = "ADD_ALTERNATIVE_COORD";
    result.mutated_tc.expectations.add(e);
    
    result.valid = true;
    result.proof = "Added alternative: " + new_alt_val;
    return result;
}

CoordinatedMutationResult NestQuantifierCoordOp::apply(const TestCaseCore& original, [[maybe_unused]] std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;
    
    if (!original.ast) return result;
    
    if (containsFragmentRef(original.ast)) return result;
    
    auto copy = copyNode(original.ast);
    if (!copy) return result;
    
    if (copy->type == PatternType::PLUS_QUANTIFIER || 
        copy->type == PatternType::STAR_QUANTIFIER ||
        copy->type == PatternType::OPTIONAL ||
        copy->type == PatternType::ALTERNATION) {
        return result;
    }
    
    auto mutated_ast = PatternNode::createQuantified(copy, PatternType::PLUS_QUANTIFIER);
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("matching")) {
            if (PatternMatcher::matches(mutated_ast, node.value)) {
                result.mutated_tc.inputs.add(node.value, {"matching"});
            }
        }
    }
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("counter")) {
            if (PatternMatcher::matches(mutated_ast, node.value)) {
                return result;
            }
            result.mutated_tc.inputs.add(node.value, {"counter"});
        }
    }
    
    bool has_matching = false;
    std::string sample_input;
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) {
            has_matching = true;
            sample_input = node.value;
            break;
        }
    }
    if (!has_matching) return result;
    
    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    result.mutated_tc.proof = original.proof + " | NEST_Q(+)";
    
    Expectation e;
    e.type = ExpectationType::QUANTIFIER_PLUS_MINONE;
    e.input = sample_input;
    e.expected_match = "yes";
    e.description = "Nested quantifier: at least one required";
    e.meta["mutation"] = "NEST_QUANTIFIER_COORD";
    result.mutated_tc.expectations.add(e);
    
    result.valid = true;
    result.proof = "Wrapped in + quantifier";
    return result;
}

CoordinatedMutationResult ExtendSequenceCoordOp::apply(const TestCaseCore& original, std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;
    
    if (!original.ast) return result;
    if (containsFragmentRef(original.ast)) return result;
    
    std::vector<std::shared_ptr<PatternNode>> literals;
    if (!findTopLevelLiterals(original.ast, literals) || literals.empty()) {
        return result;
    }
    
    auto copy = copyNode(original.ast);
    std::vector<std::shared_ptr<PatternNode>> copy_literals;
    findTopLevelLiterals(copy, copy_literals);
    if (copy_literals.empty()) return result;
    
    std::string original_literal = copy_literals[0]->value;
    char extra = randomAlpha(1, rng)[0];
    std::string extended_literal = original_literal + extra;
    copy_literals[0]->value = extended_literal;
    auto mutated_ast = copy;
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("matching")) {
            std::string updated_value = node.value;
            if (node.value == original_literal) {
                updated_value = extended_literal;
            } else if (node.value.find(original_literal) == 0) {
                updated_value = extended_literal + node.value.substr(original_literal.size());
            }
            result.mutated_tc.inputs.add(updated_value, {"matching"});
        }
    }
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("counter")) {
            result.mutated_tc.inputs.add(node.value, {"counter"});
        }
    }
    
    bool has_matching = false;
    std::string sample_input;
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) {
            has_matching = true;
            sample_input = node.value;
            break;
        }
    }
    if (!has_matching) return result;
    
    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    result.mutated_tc.proof = original.proof + " | EXTEND(+" + extra + ")";
    
    Expectation e;
    e.type = ExpectationType::REPETITION_MIN_COUNT;
    e.input = sample_input;
    e.expected_match = "yes";
    e.description = "Extended sequence with '" + std::string(1, extra) + "'";
    e.meta["mutation"] = "EXTEND_SEQUENCE_COORD";
    result.mutated_tc.expectations.add(e);
    
    result.valid = true;
    result.proof = "Extended sequence by one character";
    return result;
}

CoordinatedMutationResult DeepenNestingCoordOp::apply(const TestCaseCore& original, [[maybe_unused]] std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;
    
    if (!original.ast) return result;
    
    if (containsFragmentRef(original.ast)) return result;
    
    auto copy = copyNode(original.ast);
    if (!copy) return result;
    
    if (copy->type == PatternType::PLUS_QUANTIFIER || 
        copy->type == PatternType::STAR_QUANTIFIER ||
        copy->type == PatternType::OPTIONAL ||
        copy->type == PatternType::ALTERNATION) {
        return result;
    }
    
    auto mutated_ast = PatternNode::createQuantified(copy, PatternType::PLUS_QUANTIFIER);
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("matching")) {
            if (PatternMatcher::matches(mutated_ast, node.value)) {
                result.mutated_tc.inputs.add(node.value, {"matching"});
            }
        }
    }
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("counter")) {
            if (PatternMatcher::matches(mutated_ast, node.value)) {
                return result;
            }
            result.mutated_tc.inputs.add(node.value, {"counter"});
        }
    }
    
    bool has_matching = false;
    std::string sample_input;
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) {
            has_matching = true;
            sample_input = node.value;
            break;
        }
    }
    if (!has_matching) return result;
    
    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    result.mutated_tc.proof = original.proof + " | DEEPEN_NESTING";
    
    Expectation e;
    e.type = ExpectationType::QUANTIFIER_PLUS_MINONE;
    e.input = sample_input;
    e.expected_match = "yes";
    e.description = "Deeper nesting: at least one required";
    e.meta["mutation"] = "DEEPEN_NESTING_COORD";
    result.mutated_tc.expectations.add(e);
    
    result.valid = true;
    result.proof = "Added nesting level";
    return result;
}

CoordinatedMutationResult SplitAlternationCoordOp::apply([[maybe_unused]] const TestCaseCore& original, [[maybe_unused]] std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;
    return result;
}

struct CutPosition {
    std::vector<std::shared_ptr<PatternNode>> pre_children;
    std::shared_ptr<PatternNode> middle_node;
    std::vector<std::shared_ptr<PatternNode>> post_children;
    std::vector<std::string> pre_inputs;
    std::vector<std::string> post_inputs;
    std::vector<std::string> pre_counters;
    std::vector<std::string> post_counters;
};

static std::string serializeAstSimple(std::shared_ptr<PatternNode> node) {
    if (!node) return "";
    if (node->type == PatternType::LITERAL) {
        return node->value;
    }
    if (node->type == PatternType::SEQUENCE) {
        std::string result;
        for (auto& child : node->children) {
            result += serializeAstSimple(child);
        }
        return result;
    }
    if (node->type == PatternType::PLUS_QUANTIFIER) {
        return serializeAstSimple(node->quantified) + "+";
    }
    if (node->type == PatternType::STAR_QUANTIFIER) {
        return serializeAstSimple(node->quantified) + "*";
    }
    if (node->type == PatternType::OPTIONAL) {
        return serializeAstSimple(node->quantified) + "?";
    }
    if (node->type == PatternType::ALTERNATION) {
        std::string result = "(";
        for (size_t i = 0; i < node->children.size(); ++i) {
            if (i > 0) result += "|";
            result += serializeAstSimple(node->children[i]);
        }
        result += ")";
        return result;
    }
    return "";
}

static bool extractPrefixMatch(const std::string& input, std::shared_ptr<PatternNode> pattern, 
                              std::string& matched_prefix, std::string& remaining) {
    if (!pattern || input.empty()) {
        return false;
    }
    
    if (pattern->type == PatternType::LITERAL) {
        if (input.size() >= pattern->value.size() && 
            input.substr(0, pattern->value.size()) == pattern->value) {
            matched_prefix = pattern->value;
            remaining = input.substr(pattern->value.size());
            return true;
        }
        return false;
    }
    
    if (pattern->type == PatternType::SEQUENCE) {
        std::string remainder = input;
        std::string total_prefix;
        for (size_t i = 0; i < pattern->children.size(); ++i) {
            std::string child_prefix;
            std::string child_rem;
            if (!extractPrefixMatch(remainder, pattern->children[i], child_prefix, child_rem)) {
                return false;
            }
            total_prefix += child_prefix;
            remainder = child_rem;
        }
        matched_prefix = total_prefix;
        remaining = remainder;
        return true;
    }
    
    if (pattern->type == PatternType::PLUS_QUANTIFIER) {
        std::string remainder = input;
        std::string total_prefix;
        size_t count = 0;
        while (!remainder.empty()) {
            std::string child_prefix;
            std::string child_rem;
            if (extractPrefixMatch(remainder, pattern->quantified, child_prefix, child_rem)) {
                if (child_rem.size() >= remainder.size()) break;  // no progress guard
                total_prefix += child_prefix;
                remainder = child_rem;
                count++;
            } else {
                break;
            }
        }
        if (count >= 1) {
            matched_prefix = total_prefix;
            remaining = remainder;
            return true;
        }
        return false;
    }
    
    if (pattern->type == PatternType::STAR_QUANTIFIER) {
        std::string remainder = input;
        std::string total_prefix;
        while (!remainder.empty()) {
            std::string child_prefix;
            std::string child_rem;
            if (extractPrefixMatch(remainder, pattern->quantified, child_prefix, child_rem)) {
                if (child_rem.size() >= remainder.size()) break;  // no progress guard
                total_prefix += child_prefix;
                remainder = child_rem;
            } else {
                break;
            }
        }
        matched_prefix = total_prefix;
        remaining = remainder;
        return true;
    }
    
    if (pattern->type == PatternType::OPTIONAL) {
        std::string child_prefix;
        std::string child_rem;
        if (extractPrefixMatch(input, pattern->quantified, child_prefix, child_rem)) {
            matched_prefix = child_prefix;
            remaining = child_rem;
        } else {
            matched_prefix = "";
            remaining = input;
        }
        return true;
    }
    
    if (pattern->type == PatternType::ALTERNATION) {
        for (auto& child : pattern->children) {
            std::string child_prefix;
            std::string child_rem;
            if (extractPrefixMatch(input, child, child_prefix, child_rem)) {
                matched_prefix = child_prefix;
                remaining = child_rem;
                return true;
            }
        }
        return false;
    }
    
    return false;
}

static bool extractSuffixMatch(const std::string& input, std::shared_ptr<PatternNode> pattern,
                               std::string& remaining, std::string& matched_suffix) {
    if (!pattern || input.empty()) {
        return false;
    }
    
    if (pattern->type == PatternType::LITERAL) {
        if (input.size() >= pattern->value.size() && 
            input.substr(input.size() - pattern->value.size()) == pattern->value) {
            matched_suffix = pattern->value;
            remaining = input.substr(0, input.size() - pattern->value.size());
            return true;
        }
        return false;
    }
    
    if (pattern->type == PatternType::SEQUENCE) {
        std::string remainder = input;
        std::string total_suffix;
        for (size_t i = pattern->children.size(); i > 0; --i) {
            std::string child_suffix;
            std::string child_rem;
            if (!extractSuffixMatch(remainder, pattern->children[i-1], child_rem, child_suffix)) {
                return false;
            }
            total_suffix = child_suffix + total_suffix;
            remainder = child_rem;
        }
        remaining = remainder;
        matched_suffix = total_suffix;
        return true;
    }
    
    if (pattern->type == PatternType::PLUS_QUANTIFIER) {
        std::string remainder = input;
        std::string total_suffix;
        size_t count = 0;
        while (!remainder.empty()) {
            std::string child_suffix;
            std::string child_rem;
            if (extractSuffixMatch(remainder, pattern->quantified, child_rem, child_suffix)) {
                if (child_rem.size() >= remainder.size()) break;  // no progress guard
                total_suffix = child_suffix + total_suffix;
                remainder = child_rem;
                count++;
            } else {
                break;
            }
        }
        if (count >= 1) {
            remaining = remainder;
            matched_suffix = total_suffix;
            return true;
        }
        return false;
    }
    
    if (pattern->type == PatternType::STAR_QUANTIFIER) {
        std::string remainder = input;
        std::string total_suffix;
        while (!remainder.empty()) {
            std::string child_suffix;
            std::string child_rem;
            if (extractSuffixMatch(remainder, pattern->quantified, child_rem, child_suffix)) {
                if (child_rem.size() >= remainder.size()) break;  // no progress guard
                total_suffix = child_suffix + total_suffix;
                remainder = child_rem;
            } else {
                break;
            }
        }
        remaining = remainder;
        matched_suffix = total_suffix;
        return true;
    }
    
    if (pattern->type == PatternType::OPTIONAL) {
        std::string child_suffix;
        std::string child_rem;
        if (extractSuffixMatch(input, pattern->quantified, child_rem, child_suffix)) {
            remaining = child_rem;
            matched_suffix = child_suffix;
        } else {
            remaining = input;
            matched_suffix = "";
        }
        return true;
    }
    
    if (pattern->type == PatternType::ALTERNATION) {
        for (size_t i = pattern->children.size(); i > 0; --i) {
            std::string child_suffix;
            std::string child_rem;
            if (extractSuffixMatch(input, pattern->children[i-1], child_rem, child_suffix)) {
                remaining = child_rem;
                matched_suffix = child_suffix;
                return true;
            }
        }
        return false;
    }
    
    return false;
}

static std::vector<CutPosition> findSequenceCuts(std::shared_ptr<PatternNode> node,
                                                   const std::vector<std::string>& matching_inputs,
                                                   const std::vector<std::string>& counter_inputs) {
    std::vector<CutPosition> valid_cuts;
    
    if (!node || node->type != PatternType::SEQUENCE || node->children.size() < 2) {
        return valid_cuts;
    }
    
    for (size_t cut_idx = 0; cut_idx < node->children.size(); ++cut_idx) {
        std::vector<std::shared_ptr<PatternNode>> pre_children(node->children.begin(), node->children.begin() + cut_idx);
        std::vector<std::shared_ptr<PatternNode>> post_children(node->children.begin() + cut_idx + 1, node->children.end());
        
        auto pre_seq = PatternNode::createSequence(pre_children);
        auto post_seq = PatternNode::createSequence(post_children);
        
        if (containsFragmentRef(pre_seq) || containsFragmentRef(post_seq) || containsFragmentRef(node->children[cut_idx])) {
            continue;
        }
        
        std::vector<std::string> pre_ins, post_ins;
        bool all_inputs_valid = true;
        
        for (auto& inp : matching_inputs) {
            std::string matched_pre, remainder;
            if (!extractPrefixMatch(inp, pre_seq, matched_pre, remainder)) {
                all_inputs_valid = false;
                break;
            }
            
            std::string matched_post, rem_after_post;
            if (!extractSuffixMatch(remainder, post_seq, rem_after_post, matched_post)) {
                all_inputs_valid = false;
                break;
            }
            
            if (!rem_after_post.empty()) {
                all_inputs_valid = false;
                break;
            }
            
            pre_ins.push_back(matched_pre);
            post_ins.push_back(matched_post);
        }
        
        if (!all_inputs_valid) continue;
        
        std::vector<std::string> pre_cnts, post_cnts;
        bool counters_valid = true;
        for (auto& cnt : counter_inputs) {
            std::string matched_pre, remainder;
            bool pre_matches = extractPrefixMatch(cnt, pre_seq, matched_pre, remainder);
            
            std::string matched_post, rem_after_post;
            bool post_matches = extractSuffixMatch(remainder, post_seq, rem_after_post, matched_post);
            
            if (pre_matches && post_matches && rem_after_post.empty()) {
                counters_valid = false;
                break;
            }
            
            pre_cnts.push_back(matched_pre);
            post_cnts.push_back(matched_post);
        }
        
        if (!counters_valid) continue;
        
        CutPosition cut;
        cut.pre_children = pre_children;
        cut.middle_node = node->children[cut_idx];
        cut.post_children = post_children;
        cut.pre_inputs = pre_ins;
        cut.post_inputs = post_ins;
        cut.pre_counters = pre_cnts;
        cut.post_counters = post_cnts;
        valid_cuts.push_back(cut);
    }
    
    return valid_cuts;
}

static std::vector<CutPosition> findValidCuts(const TestCaseCore& tc) {
    std::vector<CutPosition> valid_cuts;
    
    if (!tc.ast) return valid_cuts;
    
    std::vector<std::string> matching_inputs;
    std::vector<std::string> counter_inputs;
    for (auto& node : tc.inputs.nodes) {
        if (node.categories.count("matching")) {
            matching_inputs.push_back(node.value);
        } else if (node.categories.count("counter")) {
            counter_inputs.push_back(node.value);
        }
    }
    
    if (matching_inputs.empty()) return valid_cuts;
    
    auto cuts = findSequenceCuts(tc.ast, matching_inputs, counter_inputs);
    valid_cuts.insert(valid_cuts.end(), cuts.begin(), cuts.end());
    
    return valid_cuts;
}

static std::shared_ptr<PatternNode> buildMutatedPattern(const CutPosition& cut, int mutation_type, [[maybe_unused]] std::mt19937& rng) {
    auto mutated = std::make_shared<PatternNode>();
    mutated->type = PatternType::SEQUENCE;
    
    for (auto& child : cut.pre_children) {
        clearNodeSeeds(child);
        mutated->children.push_back(child);
    }
    
    if (mutation_type == 0) {
        clearNodeSeeds(cut.middle_node);
        mutated->children.push_back(PatternNode::createQuantified(cut.middle_node, PatternType::PLUS_QUANTIFIER));
    } else if (mutation_type == 1) {
        clearNodeSeeds(cut.middle_node);
        mutated->children.push_back(PatternNode::createQuantified(cut.middle_node, PatternType::STAR_QUANTIFIER));
    } else {
        clearNodeSeeds(cut.middle_node);
        mutated->children.push_back(cut.middle_node);
    }
    
    for (auto& child : cut.post_children) {
        clearNodeSeeds(child);
        mutated->children.push_back(child);
    }
    
    return mutated;
}

static std::string generateMiddleExtension(std::shared_ptr<PatternNode> middle_node, std::mt19937& rng) {
    if (middle_node && middle_node->type == PatternType::LITERAL) {
        return middle_node->value + randomAlpha(1, rng);
    }
    return randomAlpha(2, rng);
}

CoordinatedMutationResult CutBasedCoordOp::apply(const TestCaseCore& original, [[maybe_unused]] std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;
    
    auto cuts = findValidCuts(original);
    if (cuts.empty()) {
        return result;
    }
    
    std::uniform_int_distribution<size_t> cut_dist(0, cuts.size() - 1);
    const CutPosition& cut = cuts[cut_dist(rng)];
    
    std::uniform_int_distribution<int> mut_dist(0, 2);
    int mutation_type = mut_dist(rng);
    
    auto mutated_ast = buildMutatedPattern(cut, mutation_type, rng);
    
    std::string middle_ext;
    if (mutation_type == 2) {
        middle_ext = generateMiddleExtension(cut.middle_node, rng);
        auto ext_lit = PatternNode::createLiteral(middle_ext);
        auto ext_seq = std::make_shared<PatternNode>();
        ext_seq->type = PatternType::SEQUENCE;
        ext_seq->children.push_back(cut.middle_node);
        ext_seq->children.push_back(ext_lit);
        mutated_ast = std::make_shared<PatternNode>();
        mutated_ast->type = PatternType::SEQUENCE;
        for (auto& child : cut.pre_children) {
            clearNodeSeeds(child);
            mutated_ast->children.push_back(child);
        }
        clearNodeSeeds(cut.middle_node);
        mutated_ast->children.push_back(PatternNode::createQuantified(ext_seq, PatternType::PLUS_QUANTIFIER));
        for (auto& child : cut.post_children) {
            clearNodeSeeds(child);
            mutated_ast->children.push_back(child);
        }
    }
    
    for (size_t i = 0; i < cut.pre_inputs.size(); ++i) {
        std::string new_input = cut.pre_inputs[i] + serializeAstSimple(cut.middle_node) + cut.post_inputs[i];
        result.mutated_tc.inputs.add(new_input, {"matching"});
    }
    
    if (mutation_type == 0 || mutation_type == 1) {
        std::string doubled = serializeAstSimple(cut.middle_node) + serializeAstSimple(cut.middle_node);
        result.mutated_tc.inputs.add(cut.pre_inputs[0] + doubled + cut.post_inputs[0], {"matching"});
    }
    
    for (size_t i = 0; i < cut.pre_counters.size(); ++i) {
        if (!cut.post_counters[i].empty()) {
            std::string new_counter = cut.pre_counters[i] + randomAlpha(2, rng) + cut.post_counters[i];
            result.mutated_tc.inputs.add(new_counter, {"counter"});
        } else {
            result.mutated_tc.inputs.add(cut.pre_counters[i], {"counter"});
        }
    }
    
    for (auto& frag : original.fragments) {
        result.mutated_tc.fragments[frag.first] = frag.second;
    }
    
    result.mutated_tc.ast = mutated_ast;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    result.valid = true;
    result.proof = original.proof + " | CUT_BASED(type=" + std::to_string(mutation_type) + ")";
    
    std::string sample_input;
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) {
            sample_input = node.value;
            break;
        }
    }
    
    Expectation e;
    e.type = ExpectationType::QUANTIFIER_PLUS_MINONE;
    e.input = sample_input;
    e.expected_match = "yes";
    e.description = "Cut-based mutation at SEQUENCE boundary";
    e.meta["mutation"] = "CUT_BASED";
    result.mutated_tc.expectations.add(e);
    
    return result;
}

CoordinatedMutationResult ExtendAlternationCoordOp::apply(const TestCaseCore& original, std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;
    
    if (!original.ast) return result;
    if (containsFragmentRef(original.ast)) return result;
    
    if (original.ast->type != PatternType::ALTERNATION) return result;
    
    auto ast_copy = copyNode(original.ast);
    if (!ast_copy) return result;
    
    std::string new_alt_val = randomAlpha(2, rng);
    auto new_alt = PatternNode::createLiteral(new_alt_val);
    
    auto mutated_ast = std::make_shared<PatternNode>();
    mutated_ast->type = PatternType::ALTERNATION;
    mutated_ast->children = ast_copy->children;
    mutated_ast->children.push_back(new_alt);
    
    if (!isValidPattern(mutated_ast)) return result;
    
    std::vector<std::string> new_seeds = ast_copy->matched_seeds;
    new_seeds.push_back(new_alt_val);
    mutated_ast->matched_seeds = new_seeds;
    mutated_ast->counter_seeds = ast_copy->counter_seeds;
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("matching")) {
            result.mutated_tc.inputs.add(node.value, {"matching"});
        }
    }
    result.mutated_tc.inputs.add(new_alt_val, {"matching"});
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("counter")) {
            if (PatternMatcher::matches(mutated_ast, node.value)) {
                return result;
            }
            result.mutated_tc.inputs.add(node.value, {"counter"});
        }
    }
    
    bool has_matching = false;
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) {
            has_matching = true;
            break;
        }
    }
    if (!has_matching) return result;
    
    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    result.mutated_tc.proof = original.proof + " | EXTEND_ALT(+" + new_alt_val + ")";
    
    Expectation e;
    e.type = ExpectationType::ALTERNATION_INDIVIDUAL;
    e.description = "Extended alternation with '" + new_alt_val + "'";
    e.meta["alternative"] = new_alt_val;
    e.meta["mutation"] = "EXTEND_ALTERNATION_COORD";
    result.mutated_tc.expectations.add(e);
    
    result.valid = true;
    result.proof = "Extended alternation: " + new_alt_val;
    return result;
}

CoordinatedMutationResult RemoveQuantifierCoordOp::apply(const TestCaseCore& original, std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;
    
    if (!original.ast) return result;
    
    if (original.ast->type != PatternType::PLUS_QUANTIFIER &&
        original.ast->type != PatternType::STAR_QUANTIFIER &&
        original.ast->type != PatternType::OPTIONAL) {
        return result;
    }
    
    if (!original.ast->quantified) return result;
    
    auto mutated_ast = copyNode(original.ast->quantified);
    if (!mutated_ast) return result;
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("matching")) {
            std::string mutated_val = node.value;
            if (node.value.size() > 1) {
                int pos = std::uniform_int_distribution<int>(0, node.value.size() - 1)(rng);
                mutated_val = node.value.substr(0, pos) + node.value.substr(pos + 1);
            }
            if (PatternMatcher::matches(mutated_ast, mutated_val)) {
                result.mutated_tc.inputs.add(mutated_val, {"matching"});
            } else {
                result.mutated_tc.inputs.add(node.value, {"matching"});
            }
        }
    }
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("counter")) {
            if (PatternMatcher::matches(mutated_ast, node.value)) {
                return result;
            }
            result.mutated_tc.inputs.add(node.value, {"counter"});
        }
    }
    
    bool has_matching = false;
    std::string sample_input;
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) {
            has_matching = true;
            sample_input = node.value;
            break;
        }
    }
    if (!has_matching) return result;
    
    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    result.mutated_tc.proof = original.proof + " | REMOVE_QUANTIFIER";
    
    Expectation e;
    e.type = ExpectationType::QUANTIFIER_PLUS_MINONE;
    e.input = sample_input;
    e.expected_match = "yes";
    e.description = "Removed quantifier wrapper";
    e.meta["mutation"] = "REMOVE_QUANTIFIER_COORD";
    result.mutated_tc.expectations.add(e);
    
    result.valid = true;
    result.proof = "Unwrapped quantifier";
    return result;
}

CoordinatedMutationResult AlterAlternativeCoordOp::apply(const TestCaseCore& original, std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;
    
    if (!original.ast) return result;
    if (original.ast->type != PatternType::ALTERNATION) return result;
    if (original.ast->children.size() < 2) return result;
    
    size_t alt_idx = std::uniform_int_distribution<size_t>(0, original.ast->children.size() - 1)(rng);
    auto alt_node = copyNode(original.ast->children[alt_idx]);
    if (!alt_node) return result;
    
    if (alt_node->type == PatternType::LITERAL && !alt_node->value.empty()) {
        int pos = std::uniform_int_distribution<int>(0, alt_node->value.size() - 1)(rng);
        char old_char = alt_node->value[pos];
        char new_char;
        do {
            new_char = randomAlpha(1, rng)[0];
        } while (new_char == old_char);
        alt_node->value[pos] = new_char;
        
        auto mutated_ast = copyNode(original.ast);
        mutated_ast->children[alt_idx] = alt_node;
        
        if (!isValidPattern(mutated_ast)) return result;
        
        for (auto& node : original.inputs.nodes) {
            if (node.categories.count("matching")) {
                if (PatternMatcher::matches(mutated_ast, node.value)) {
                    result.mutated_tc.inputs.add(node.value, {"matching"});
                }
            }
        }
        
        for (auto& node : original.inputs.nodes) {
            if (node.categories.count("counter")) {
                if (PatternMatcher::matches(mutated_ast, node.value)) {
                    return result;
                }
                result.mutated_tc.inputs.add(node.value, {"counter"});
            }
        }
        
        bool has_matching = false;
        std::string sample_input;
        for (auto& node : result.mutated_tc.inputs.nodes) {
            if (node.categories.count("matching")) {
                has_matching = true;
                sample_input = node.value;
                break;
            }
        }
        if (!has_matching) return result;
        
        result.mutated_tc.ast = mutated_ast;
        result.mutated_tc.fragments = original.fragments;
        if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
        result.mutated_tc.proof = original.proof + " | ALTER_ALT(" + std::string(1, old_char) + "→" + std::string(1, new_char) + ")";
        
        Expectation e;
        e.type = ExpectationType::MATCH_EXACT;
        e.input = sample_input;
        e.expected_match = "yes";
        e.description = "Altered alternative at index " + std::to_string(alt_idx);
        e.meta["mutation"] = "ALTER_ALTERNATIVE_COORD";
        result.mutated_tc.expectations.add(e);
        
        result.valid = true;
        result.proof = "Char substitute in alternative";
        return result;
    }
    
    if (alt_node->type == PatternType::SEQUENCE && !alt_node->children.empty()) {
        char extra = randomAlpha(1, rng)[0];
        
        auto first_lit = alt_node->children[0];
        if (first_lit && first_lit->type == PatternType::LITERAL && !first_lit->value.empty()) {
            first_lit->value += extra;
        } else {
            auto new_lit = PatternNode::createLiteral(std::string(1, extra));
            alt_node->children.insert(alt_node->children.begin(), new_lit);
        }
        
        auto mutated_ast = copyNode(original.ast);
        mutated_ast->children[alt_idx] = alt_node;
        
        if (!isValidPattern(mutated_ast)) return result;
        
        for (auto& node : original.inputs.nodes) {
            if (node.categories.count("matching")) {
                if (PatternMatcher::matches(mutated_ast, node.value)) {
                    result.mutated_tc.inputs.add(node.value, {"matching"});
                }
            }
        }
        
        for (auto& node : original.inputs.nodes) {
            if (node.categories.count("counter")) {
                if (PatternMatcher::matches(mutated_ast, node.value)) {
                    return result;
                }
                result.mutated_tc.inputs.add(node.value, {"counter"});
            }
        }
        
        bool has_matching = false;
        std::string sample_input;
        for (auto& node : result.mutated_tc.inputs.nodes) {
            if (node.categories.count("matching")) {
                has_matching = true;
                sample_input = node.value;
                break;
            }
        }
        if (!has_matching) return result;
        
        result.mutated_tc.ast = mutated_ast;
        result.mutated_tc.fragments = original.fragments;
        if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
        result.mutated_tc.proof = original.proof + " | ALTER_ALT_EXTEND(+" + std::string(1, extra) + ")";
        
        Expectation e;
        e.type = ExpectationType::REPETITION_MIN_COUNT;
        e.input = sample_input;
        e.expected_match = "yes";
        e.description = "Extended alternative sequence at index " + std::to_string(alt_idx);
        e.meta["mutation"] = "ALTER_ALTERNATIVE_COORD";
        result.mutated_tc.expectations.add(e);
        
        result.valid = true;
        result.proof = "Extended alternative sequence";
        return result;
    }
    
    return result;
}

CoordinatedMutationResult FlattenQuantifiedAltCoordOp::apply(const TestCaseCore& original, [[maybe_unused]] std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;
    
    if (!original.ast) return result;
    
    if (original.ast->type != PatternType::PLUS_QUANTIFIER &&
        original.ast->type != PatternType::STAR_QUANTIFIER) {
        return result;
    }
    
    if (!original.ast->quantified || original.ast->quantified->type != PatternType::ALTERNATION) {
        return result;
    }
    
    auto alt_node = original.ast->quantified;
    std::vector<std::shared_ptr<PatternNode>> new_alts;
    
    for (auto& child : alt_node->children) {
        if (child && child->type == PatternType::LITERAL && !child->value.empty()) {
            auto quantified_child = PatternNode::createQuantified(child, original.ast->type);
            new_alts.push_back(quantified_child);
        } else {
            new_alts.push_back(child);
        }
    }
    
    if (new_alts.empty()) return result;
    
    auto mutated_ast = std::make_shared<PatternNode>();
    mutated_ast->type = PatternType::ALTERNATION;
    mutated_ast->children = new_alts;
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("matching")) {
            result.mutated_tc.inputs.add(node.value, {"matching"});
        }
    }
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("counter")) {
            if (PatternMatcher::matches(mutated_ast, node.value)) {
                return result;
            }
            result.mutated_tc.inputs.add(node.value, {"counter"});
        }
    }
    
    bool has_matching = false;
    std::string sample_input;
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) {
            has_matching = true;
            sample_input = node.value;
            break;
        }
    }
    if (!has_matching) return result;
    
    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    result.mutated_tc.proof = original.proof + " | FLATTEN_QUANTIFIED_ALT";
    
    Expectation e;
    e.type = ExpectationType::ALTERNATION_INDIVIDUAL;
    e.input = sample_input;
    e.expected_match = "yes";
    e.description = "Flattened quantified alternation";
    e.meta["mutation"] = "FLATTEN_QUANTIFIED_ALT_COORD";
    result.mutated_tc.expectations.add(e);
    
    result.valid = true;
    result.proof = "Flattened quantified alternation to alternation of quantified items";
    return result;
}

CoordinatedMutationResult UnwrapFragmentRefCoordOp::apply(const TestCaseCore& original, [[maybe_unused]] std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;
    
    if (!original.ast) return result;
    
    bool has_fragment_ref = containsFragmentRef(original.ast);
    if (!has_fragment_ref) return result;
    
    auto mutated_ast = copyNode(original.ast);
    if (!mutated_ast) return result;
    
    std::string placeholder = "X";
    
    std::function<void(std::shared_ptr<PatternNode>)> replace_fragment_refs = 
        [&](std::shared_ptr<PatternNode> node) {
        if (!node) return;
        
        if (node->type == PatternType::FRAGMENT_REF || !node->fragment_name.empty()) {
            node->type = PatternType::LITERAL;
            node->value = placeholder;
            node->fragment_name.clear();
            node->children.clear();
            node->quantified.reset();
        }
        
        if (node->quantified) replace_fragment_refs(node->quantified);
        for (auto& child : node->children) replace_fragment_refs(child);
    };
    
    replace_fragment_refs(mutated_ast);
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("matching")) {
            if (PatternMatcher::matches(mutated_ast, node.value)) {
                result.mutated_tc.inputs.add(node.value, {"matching"});
            }
        }
    }
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("counter")) {
            if (PatternMatcher::matches(mutated_ast, node.value)) {
                return result;
            }
            result.mutated_tc.inputs.add(node.value, {"counter"});
        }
    }
    
    bool has_matching = false;
    std::string sample_input;
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) {
            has_matching = true;
            sample_input = node.value;
            break;
        }
    }
    if (!has_matching) return result;
    
    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    result.mutated_tc.proof = original.proof + " | UNWRAP_FRAGMENT_REF";
    
    Expectation e;
    e.type = ExpectationType::FRAGMENT_NESTED;
    e.input = sample_input;
    e.expected_match = "yes";
    e.description = "Unwrapped fragment references to literal placeholder";
    e.meta["mutation"] = "UNWRAP_FRAGMENT_REF_COORD";
    result.mutated_tc.expectations.add(e);
    
    result.valid = true;
    result.proof = "Unwrapped fragment references to literal placeholder";
    return result;
}

CoordinatedMutationResult SequenceToAlternationCoordOp::apply(const TestCaseCore& original, [[maybe_unused]] std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;
    
    if (!original.ast) return result;
    if (original.ast->type != PatternType::SEQUENCE) return result;
    if (original.ast->children.size() < 2) return result;
    
    std::vector<std::shared_ptr<PatternNode>> alt_items;
    
    for (auto& child : original.ast->children) {
        if (child && child->type == PatternType::LITERAL && !child->value.empty()) {
            auto quantified = PatternNode::createQuantified(child, PatternType::PLUS_QUANTIFIER);
            alt_items.push_back(quantified);
        } else {
            alt_items.push_back(child);
        }
    }
    
    auto mutated_ast = std::make_shared<PatternNode>();
    mutated_ast->type = PatternType::ALTERNATION;
    mutated_ast->children = alt_items;
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("matching")) {
            result.mutated_tc.inputs.add(node.value, {"matching"});
        }
    }
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("counter")) {
            if (PatternMatcher::matches(mutated_ast, node.value)) {
                return result;
            }
            result.mutated_tc.inputs.add(node.value, {"counter"});
        }
    }
    
    bool has_matching = false;
    std::string sample_input;
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) {
            has_matching = true;
            sample_input = node.value;
            break;
        }
    }
    if (!has_matching) return result;
    
    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    result.mutated_tc.proof = original.proof + " | SEQ_TO_ALT";
    
    Expectation e;
    e.type = ExpectationType::ALTERNATION_INDIVIDUAL;
    e.input = sample_input;
    e.expected_match = "yes";
    e.description = "Converted sequence to alternation";
    e.meta["mutation"] = "SEQUENCE_TO_ALTERNATION_COORD";
    result.mutated_tc.expectations.add(e);
    
    result.valid = true;
    result.proof = "Converted sequence to alternation of quantified items";
    return result;
}

CoordinatedMutationResult QuantifyAlternationCoordOp::apply(const TestCaseCore& original, std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;
    
    if (!original.ast) return result;
    if (containsFragmentRef(original.ast)) return result;
    
    if (original.ast->type != PatternType::ALTERNATION) return result;
    
    auto ast_copy = copyNode(original.ast);
    if (!ast_copy) return result;
    
    PatternType quant_types[] = {
        PatternType::PLUS_QUANTIFIER,
        PatternType::STAR_QUANTIFIER,
        PatternType::OPTIONAL
    };
    int idx = std::uniform_int_distribution<int>(0, 2)(rng);
    auto mutated_ast = PatternNode::createQuantified(ast_copy, quant_types[idx]);
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("matching")) {
            result.mutated_tc.inputs.add(node.value, {"matching"});
        }
    }
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("counter")) {
            if (PatternMatcher::matches(mutated_ast, node.value)) {
                return result;
            }
            result.mutated_tc.inputs.add(node.value, {"counter"});
        }
    }
    
    bool has_matching = false;
    std::string sample_input;
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) {
            has_matching = true;
            sample_input = node.value;
            break;
        }
    }
    if (!has_matching) return result;
    
    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    
    std::string quant_name = (idx == 0) ? "+" : (idx == 1) ? "*" : "?";
    result.mutated_tc.proof = original.proof + " | QUANTIFY_ALT(" + quant_name + ")";
    
    Expectation e;
    e.type = ExpectationType::ALTERNATION_INDIVIDUAL;
    e.input = sample_input;
    e.expected_match = "yes";
    e.description = "Quantified alternation with " + std::string(1, quant_name[0]);
    e.meta["mutation"] = "QUANTIFY_ALTERNATION_COORD";
    result.mutated_tc.expectations.add(e);
    
    result.valid = true;
    result.proof = "Quantified alternation with " + std::string(1, quant_name[0]);
    return result;
}

CoordinatedMutationResult PrefixSuffixAlternationCoordOp::apply(const TestCaseCore& original, std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;
    
    if (!original.ast) return result;
    if (containsFragmentRef(original.ast)) return result;
    
    if (original.ast->type != PatternType::ALTERNATION) return result;
    
    auto ast_copy = copyNode(original.ast);
    if (!ast_copy) return result;
    
    std::string prefix = randomAlpha(1, rng) + randomAlpha(1, rng);
    std::string suffix = randomAlpha(1, rng) + randomAlpha(1, rng);
    
    std::vector<std::shared_ptr<PatternNode>> seq_children;
    seq_children.push_back(PatternNode::createLiteral(prefix, {prefix}));
    seq_children.push_back(ast_copy);
    seq_children.push_back(PatternNode::createLiteral(suffix, {suffix}));
    
    auto mutated_ast = PatternNode::createSequence(seq_children);
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("matching")) {
            std::string with_affix = prefix + node.value + suffix;
            result.mutated_tc.inputs.add(with_affix, {"matching"});
        }
    }
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("counter")) {
            std::string with_affix = prefix + node.value + suffix;
            if (PatternMatcher::matches(mutated_ast, with_affix)) {
                return result;
            }
            result.mutated_tc.inputs.add(with_affix, {"counter"});
        }
    }
    
    bool has_matching = false;
    std::string sample_input;
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) {
            has_matching = true;
            sample_input = node.value;
            break;
        }
    }
    if (!has_matching) return result;
    
    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    result.mutated_tc.proof = original.proof + " | PREFIX_SUFFIX_ALT(+" + prefix + ", +" + suffix + ")";
    
    Expectation e;
    e.type = ExpectationType::MATCH_EXACT;
    e.input = sample_input;
    e.expected_match = "yes";
    e.description = "Added prefix/suffix to alternation";
    e.meta["mutation"] = "PREFIX_SUFFIX_ALT_COORD";
    e.meta["prefix"] = prefix;
    e.meta["suffix"] = suffix;
    result.mutated_tc.expectations.add(e);
    
    result.valid = true;
    result.proof = "Added prefix/suffix to alternation";
    return result;
}

CoordinatedMutationResult ExtractFragmentCoordOp::apply(const TestCaseCore& original, std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;

    if (!original.ast) return result;

    // Only works on literal or alternation patterns (no existing fragments)
    if (containsFragmentRef(original.ast)) return result;

    // Find a literal node with enough characters to extract a substring
    std::vector<std::shared_ptr<PatternNode>> literals;
    findTopLevelLiterals(original.ast, literals);
    if (literals.empty()) return result;

    auto target = literals[std::uniform_int_distribution<size_t>(0, literals.size() - 1)(rng)];
    if (target->value.size() < 3) return result;

    // Pick a substring to extract (1-2 chars from middle)
    int substr_len = std::uniform_int_distribution<int>(1, std::min(2, (int)target->value.size() - 2))(rng);
    int substr_pos = std::uniform_int_distribution<int>(1, (int)target->value.size() - substr_len - 1)(rng);
    std::string extracted = target->value.substr(substr_pos, substr_len);
    std::string prefix = target->value.substr(0, substr_pos);
    std::string suffix = target->value.substr(substr_pos + substr_len);

    // Create fragment
    static int frag_id = 0;
    std::string frag_name = "ext" + std::to_string(frag_id++);

    auto mutated_ast = copyNode(original.ast);
    std::vector<std::shared_ptr<PatternNode>> mut_literals;
    findTopLevelLiterals(mutated_ast, mut_literals);
    for (auto& lit : mut_literals) {
        if (lit->value == target->value) {
            // Replace literal with sequence: prefix + frag_ref + suffix
            auto pre = PatternNode::createLiteral(prefix, {});
            auto frag_ref = PatternNode::createFragment(frag_name, {});
            auto suf = PatternNode::createLiteral(suffix, {});
            auto seq = PatternNode::createSequence({pre, frag_ref, suf}, {});
            *lit = *seq;
            break;
        }
    }

    if (!isValidPattern(mutated_ast)) return result;

    // Copy inputs unchanged
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("matching")) {
            result.mutated_tc.inputs.add(node.value, {"matching"});
        } else if (node.categories.count("counter")) {
            result.mutated_tc.inputs.add(node.value, {"counter"});
        }
    }

    bool has_matching = false;
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) { has_matching = true; break; }
    }
    if (!has_matching) return result;

    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    result.mutated_tc.fragments[frag_name] = extracted;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    result.mutated_tc.proof = original.proof + " | EXTRACT_FRAG(" + extracted + "->" + frag_name + ")";

    Expectation e;
    e.type = ExpectationType::FRAGMENT_MATCH;
    e.description = "Extracted substring '" + extracted + "' as fragment " + frag_name;
    e.meta["fragment"] = frag_name;
    e.meta["mutation"] = "EXTRACT_FRAGMENT_COORD";
    result.mutated_tc.expectations.add(e);

    result.valid = true;
    result.proof = "Extracted fragment: " + frag_name + "=" + extracted;
    return result;
}

CoordinatedMutationResult RedundantGroupCoordOp::apply(const TestCaseCore& original, [[maybe_unused]] std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;

    if (!original.ast) return result;
    if (containsFragmentRef(original.ast)) return result;

    // Wrap the entire AST in a redundant group (parens)
    auto mutated_ast = copyNode(original.ast);
    if (!mutated_ast) return result;

    // Wrapping in group doesn't change semantics, so inputs remain valid
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("matching")) {
            result.mutated_tc.inputs.add(node.value, {"matching"});
        } else if (node.categories.count("counter")) {
            result.mutated_tc.inputs.add(node.value, {"counter"});
        }
    }

    bool has_matching = false;
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) { has_matching = true; break; }
    }
    if (!has_matching) return result;

    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    result.mutated_tc.proof = original.proof + " | REDUNDANT_GROUP";

    Expectation e;
    e.type = ExpectationType::MATCH_EXACT;
    e.description = "Wrapped in redundant group";
    e.meta["mutation"] = "REDUNDANT_GROUP_COORD";
    // Use a sample matching input for the expectation
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) {
            e.input = node.value;
            break;
        }
    }
    e.expected_match = "yes";
    result.mutated_tc.expectations.add(e);

    result.valid = true;
    result.proof = "Added redundant grouping";
    return result;
}

CoordinatedMutationResult SwapAlternativesCoordOp::apply(const TestCaseCore& original, std::mt19937& rng) const {
    CoordinatedMutationResult result;
    result.valid = false;

    if (!original.ast) return result;
    if (original.ast->type != PatternType::ALTERNATION) return result;
    if (original.ast->children.size() < 2) return result;

    auto mutated_ast = copyNode(original.ast);
    if (!mutated_ast) return result;

    // Swap two random alternatives
    size_t i = std::uniform_int_distribution<size_t>(0, mutated_ast->children.size() - 1)(rng);
    size_t j = std::uniform_int_distribution<size_t>(0, mutated_ast->children.size() - 1)(rng);
    while (j == i) j = std::uniform_int_distribution<size_t>(0, mutated_ast->children.size() - 1)(rng);
    std::swap(mutated_ast->children[i], mutated_ast->children[j]);

    if (!isValidPattern(mutated_ast)) return result;

    // Alternation order doesn't affect matching, inputs remain valid
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("matching")) {
            result.mutated_tc.inputs.add(node.value, {"matching"});
        } else if (node.categories.count("counter")) {
            result.mutated_tc.inputs.add(node.value, {"counter"});
        }
    }

    bool has_matching = false;
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) { has_matching = true; break; }
    }
    if (!has_matching) return result;

    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    if (!ensureFragmentDefs(mutated_ast, result.mutated_tc.fragments)) { result.valid = false; return result; }
    result.mutated_tc.proof = original.proof + " | SWAP_ALTS(" + std::to_string(i) + "<->" + std::to_string(j) + ")";

    Expectation e;
    e.type = ExpectationType::ALTERNATION_INDIVIDUAL;
    e.description = "Swapped alternatives at positions " + std::to_string(i) + " and " + std::to_string(j);
    e.meta["mutation"] = "SWAP_ALTERNATIVES_COORD";
    result.mutated_tc.expectations.add(e);

    result.valid = true;
    result.proof = "Swapped alternative order";
    return result;
}

CoordinatedMutationEngine::CoordinatedMutationEngine() {
    operators.push_back(std::make_unique<CharSubstituteCoordOp>());
    operators.push_back(std::make_unique<NestQuantifierCoordOp>());
    operators.push_back(std::make_unique<ExtendSequenceCoordOp>());
    operators.push_back(std::make_unique<CutBasedCoordOp>());
    operators.push_back(std::make_unique<AlterAlternativeCoordOp>());
    operators.push_back(std::make_unique<RemoveQuantifierCoordOp>());
    operators.push_back(std::make_unique<FlattenQuantifiedAltCoordOp>());
    operators.push_back(std::make_unique<UnwrapFragmentRefCoordOp>());
    operators.push_back(std::make_unique<SequenceToAlternationCoordOp>());
    operators.push_back(std::make_unique<QuantifyAlternationCoordOp>());
    operators.push_back(std::make_unique<PrefixSuffixAlternationCoordOp>());
    operators.push_back(std::make_unique<ExtractFragmentCoordOp>());
    operators.push_back(std::make_unique<RedundantGroupCoordOp>());
    operators.push_back(std::make_unique<SwapAlternativesCoordOp>());
}

std::vector<CoordinatedMutationResult> CoordinatedMutationEngine::mutate(
    const TestCaseCore& tc,
    size_t max_results,
    std::mt19937& rng
) const {
    std::vector<CoordinatedMutationResult> all_results;
    
    for (auto& op : operators) {
        auto result = op->apply(tc, rng);
        if (result.valid) {
            if (isValidPattern(result.mutated_tc.ast) && 
                hasAllFragmentDefs(result.mutated_tc.ast, result.mutated_tc.fragments)) {
                // Validate with PatternMatcher: ensure all matching inputs match
                // and no counter inputs match the mutated AST
                std::vector<std::string> match_inputs;
                std::vector<std::string> counter_inputs;
                for (auto& node : result.mutated_tc.inputs.nodes) {
                    if (node.categories.count("matching")) match_inputs.push_back(node.value);
                    else if (node.categories.count("counter")) counter_inputs.push_back(node.value);
                }
                if (PatternMatcher::validateWithFragments(
                        result.mutated_tc.ast, match_inputs, counter_inputs,
                        result.mutated_tc.fragments)) {
                    all_results.push_back(result);
                }
            }
        }
    }
    
    if (all_results.empty()) return {};
    if (all_results.size() <= max_results) return all_results;
    
    std::vector<double> weights;
    for (auto& result : all_results) {
        double w = 1.0;
        if (result.proof.find("CHAR_SUB") != std::string::npos) {
            w = 1.0;
        } else if (result.proof.find("QUANTIFY_ALT") != std::string::npos ||
                   result.proof.find("PREFIX_SUFFIX_ALT") != std::string::npos) {
            w = 10.0;
        } else if (result.proof.find("ALTER_ALT") != std::string::npos) {
            w = 5.0;
        } else if (result.proof.find("NEST_Q") != std::string::npos ||
                   result.proof.find("EXTEND_SEQUENCE") != std::string::npos ||
                   result.proof.find("FLATTEN") != std::string::npos) {
            w = 8.0;
        }
        weights.push_back(w);
    }
    
    std::discrete_distribution<size_t> dist(weights.begin(), weights.end());
    std::vector<CoordinatedMutationResult> results;
    std::set<size_t> used;
    
    for (size_t i = 0; i < max_results; i++) {
        size_t idx = dist(rng);
        if (used.count(idx)) {
            for (size_t j = 0; j < all_results.size(); j++) {
                if (used.count(j) == 0) {
                    idx = j;
                    break;
                }
            }
        }
        used.insert(idx);
        results.push_back(all_results[idx]);
    }
    
    return results;
}

std::vector<std::unique_ptr<CoordinatedMutationOperator>> CoordinatedMutationEngine::allOperators() {
    CoordinatedMutationEngine engine;
    return std::move(engine.operators);
}

} // namespace TestGen