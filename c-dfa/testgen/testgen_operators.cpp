#include "testgen_operators.h"
#include "pattern_serializer.h"
#include <algorithm>

namespace TestGen {

static std::string randomChar(std::mt19937& rng) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::uniform_int_distribution<int> dist(0, sizeof(charset) - 2);
    return std::string(1, charset[dist(rng)]);
}

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
    copy->fragment_name = node->fragment_name;
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

static bool patternMatchesPlus(const std::string& content, const std::string& str) {
    if (str.empty() || content.empty()) return false;
    size_t content_len = content.size();
    if (str.size() % content_len != 0) return false;
    for (size_t i = 0; i < str.size(); i += content_len) {
        if (str.substr(i, content_len) != content) return false;
    }
    return true;
}

static bool patternMatchesStar(const std::string& content, const std::string& str) {
    if (content.empty()) return str.empty();
    if (str.empty()) return true;
    size_t content_len = content.size();
    if (str.size() % content_len != 0) return false;
    for (size_t i = 0; i < str.size(); i += content_len) {
        if (str.substr(i, content_len) != content) return false;
    }
    return true;
}

static bool wouldMatchPattern(const std::string& input, std::shared_ptr<PatternNode> pattern) {
    if (!pattern) return false;
    if (input.empty()) return false;
    
    switch (pattern->type) {
        case PatternType::LITERAL:
            return input == pattern->value;
        case PatternType::PLUS_QUANTIFIER:
            if (pattern->quantified) {
                if (pattern->quantified->type == PatternType::LITERAL) {
                    return patternMatchesPlus(pattern->quantified->value, input);
                }
                if (pattern->quantified->type == PatternType::ALTERNATION) {
                    for (auto& child : pattern->quantified->children) {
                        if (child && child->type == PatternType::LITERAL) {
                            if (patternMatchesPlus(child->value, input)) return true;
                        }
                    }
                    return false;
                }
                return wouldMatchPattern(input, pattern->quantified);
            }
            return !input.empty();
        case PatternType::STAR_QUANTIFIER:
            if (pattern->quantified) {
                if (pattern->quantified->type == PatternType::LITERAL) {
                    return patternMatchesStar(pattern->quantified->value, input);
                }
                if (pattern->quantified->type == PatternType::ALTERNATION) {
                    for (auto& child : pattern->quantified->children) {
                        if (child && child->type == PatternType::LITERAL) {
                            if (patternMatchesStar(child->value, input)) return true;
                        }
                    }
                    return false;
                }
            }
            return true;
        case PatternType::OPTIONAL:
            if (pattern->quantified) {
                if (pattern->quantified->type == PatternType::LITERAL) {
                    return input.empty() || input == pattern->quantified->value;
                }
                return input.empty() || wouldMatchPattern(input, pattern->quantified);
            }
            return true;
        case PatternType::ALTERNATION:
            for (auto& child : pattern->children) {
                if (wouldMatchPattern(input, child)) return true;
            }
            return false;
        case PatternType::SEQUENCE: {
            if (pattern->children.empty()) return false;
            std::string remaining = input;
            for (auto& child : pattern->children) {
                bool matched = false;
                for (size_t len = 0; len <= remaining.size(); ++len) {
                    std::string prefix = remaining.substr(0, len);
                    if (wouldMatchPattern(prefix, child)) {
                        remaining = remaining.substr(len);
                        matched = true;
                        break;
                    }
                }
                if (!matched) return false;
            }
            return remaining.empty() ? true : (wouldMatchPattern(remaining, pattern->children.back()) ? true : false);
        }
        case PatternType::FRAGMENT_REF:
            return false;
        default:
            return false;
    }
}

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
    result.mutated_tc.proof = original.proof + " | CHAR_SUB(" + old_char + "→" + new_char + ")";
    
    Expectation e;
    e.type = ExpectationType::MATCH_EXACT;
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
            if (wouldMatchPattern(node.value, mutated_ast)) {
                result.mutated_tc.inputs.add(node.value, {"matching"});
            }
        }
    }
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("counter")) {
            if (wouldMatchPattern(node.value, mutated_ast)) {
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

CoordinatedMutationResult NestQuantifierCoordOp::apply(const TestCaseCore& original, std::mt19937& rng) const {
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
            if (wouldMatchPattern(node.value, mutated_ast)) {
                result.mutated_tc.inputs.add(node.value, {"matching"});
            }
        }
    }
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("counter")) {
            if (wouldMatchPattern(node.value, mutated_ast)) {
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
    result.mutated_tc.proof = original.proof + " | NEST_Q(+)";
    
    Expectation e;
    e.type = ExpectationType::QUANTIFIER_PLUS_MINONE;
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
    for (auto& node : result.mutated_tc.inputs.nodes) {
        if (node.categories.count("matching")) {
            has_matching = true;
            break;
        }
    }
    if (!has_matching) return result;
    
    result.mutated_tc.ast = mutated_ast;
    result.mutated_tc.fragments = original.fragments;
    result.mutated_tc.proof = original.proof + " | EXTEND(+" + extra + ")";
    
    Expectation e;
    e.type = ExpectationType::REPETITION_MIN_COUNT;
    e.description = "Extended sequence with '" + std::string(1, extra) + "'";
    e.meta["mutation"] = "EXTEND_SEQUENCE_COORD";
    result.mutated_tc.expectations.add(e);
    
    result.valid = true;
    result.proof = "Extended sequence by one character";
    return result;
}

    CoordinatedMutationResult DeepenNestingCoordOp::apply(const TestCaseCore& original, std::mt19937& rng) const {
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
            if (wouldMatchPattern(node.value, mutated_ast)) {
                result.mutated_tc.inputs.add(node.value, {"matching"});
            }
        }
    }
    
    for (auto& node : original.inputs.nodes) {
        if (node.categories.count("counter")) {
            if (wouldMatchPattern(node.value, mutated_ast)) {
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
    result.mutated_tc.proof = original.proof + " | DEEPEN_NESTING";
    
    Expectation e;
    e.type = ExpectationType::QUANTIFIER_PLUS_MINONE;
    e.description = "Deeper nesting: at least one required";
    e.meta["mutation"] = "DEEPEN_NESTING_COORD";
    result.mutated_tc.expectations.add(e);
    
    result.valid = true;
    result.proof = "Added nesting level";
    return result;
}

CoordinatedMutationResult SplitAlternationCoordOp::apply(const TestCaseCore& original, std::mt19937& rng) const {
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

static bool wouldMatchPattern(const std::string& input, std::shared_ptr<PatternNode> pattern);

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

static std::shared_ptr<PatternNode> buildMutatedPattern(const CutPosition& cut, int mutation_type, std::mt19937& rng) {
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

CoordinatedMutationResult CutBasedCoordOp::apply(const TestCaseCore& original, std::mt19937& rng) const {
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
    result.valid = true;
    result.proof = original.proof + " | CUT_BASED(type=" + std::to_string(mutation_type) + ")";
    
    Expectation e;
    e.type = ExpectationType::QUANTIFIER_PLUS_MINONE;
    e.description = "Cut-based mutation at SEQUENCE boundary";
    e.meta["mutation"] = "CUT_BASED";
    result.mutated_tc.expectations.add(e);
    
    return result;
}

CoordinatedMutationEngine::CoordinatedMutationEngine() {
    operators.push_back(std::make_unique<CharSubstituteCoordOp>());
    operators.push_back(std::make_unique<AddAlternativeCoordOp>());
    operators.push_back(std::make_unique<NestQuantifierCoordOp>());
    operators.push_back(std::make_unique<ExtendSequenceCoordOp>());
    operators.push_back(std::make_unique<DeepenNestingCoordOp>());
    operators.push_back(std::make_unique<CutBasedCoordOp>());
    // SplitAlternationCoordOp always returns invalid
    // operators.push_back(std::make_unique<SplitAlternationCoordOp>());
}

std::vector<CoordinatedMutationResult> CoordinatedMutationEngine::mutate(
    const TestCaseCore& tc,
    size_t max_results,
    std::mt19937& rng
) const {
    std::vector<CoordinatedMutationResult> results;
    for (auto& op : operators) {
        auto result = op->apply(tc, rng);
        if (result.valid) {
            results.push_back(result);
            if (results.size() >= max_results) break;
        }
    }
    return results;
}

std::vector<std::unique_ptr<CoordinatedMutationOperator>> CoordinatedMutationEngine::allOperators() {
    CoordinatedMutationEngine engine;
    return std::move(engine.operators);
}

} // namespace TestGen