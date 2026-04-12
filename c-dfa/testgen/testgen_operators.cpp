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
    copy->matched_seeds = node->matched_seeds;
    copy->counter_seeds = node->counter_seeds;
    if (node->quantified) copy->quantified = copyNode(node->quantified);
    for (auto& child : node->children) copy->children.push_back(copyNode(child));
    return copy;
}

MutationResult CharSubstituteOp::apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    MutationResult result;
    result.success = false;
    
    std::vector<std::shared_ptr<PatternNode>> literals;
    if (!findLiteralNode(ast, literals)) return result;
    
    auto target = literals[std::uniform_int_distribution<size_t>(0, literals.size() - 1)(rng)];
    if (target->value.empty()) return result;
    
    int pos = std::uniform_int_distribution<int>(0, target->value.size() - 1)(rng);
    char original = target->value[pos];
    char replacement;
    do {
        replacement = randomChar(rng)[0];
    } while (replacement == original);
    
    auto copy = copyNode(ast);
    for (auto& lit : literals) {
        if (lit == target) {
            lit->value[pos] = replacement;
            break;
        }
    }
    
    result.ast = copy;
    result.description = "Substituted '" + std::string(1, original) + "' with '" + std::string(1, replacement) + "'";
    result.success = true;
    return result;
}

MutationResult CharInsertOp::apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    MutationResult result;
    result.success = false;
    
    std::vector<std::shared_ptr<PatternNode>> literals;
    if (!findLiteralNode(ast, literals)) return result;
    
    auto target = literals[std::uniform_int_distribution<size_t>(0, literals.size() - 1)(rng)];
    int pos = std::uniform_int_distribution<int>(0, target->value.size())(rng);
    
    auto copy = copyNode(ast);
    for (auto& lit : literals) {
        if (lit == target) {
            lit->value.insert(pos, randomChar(rng));
            break;
        }
    }
    
    result.ast = copy;
    result.description = "Inserted character at position " + std::to_string(pos);
    result.success = true;
    return result;
}

MutationResult CharDeleteOp::apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    MutationResult result;
    result.success = false;
    
    std::vector<std::shared_ptr<PatternNode>> literals;
    if (!findLiteralNode(ast, literals)) return result;
    
    auto target = literals[std::uniform_int_distribution<size_t>(0, literals.size() - 1)(rng)];
    if (target->value.size() <= 1) return result;
    
    int pos = std::uniform_int_distribution<int>(0, target->value.size() - 1)(rng);
    
    auto copy = copyNode(ast);
    for (auto& lit : literals) {
        if (lit == target) {
            lit->value.erase(pos, 1);
            break;
        }
    }
    
    result.ast = copy;
    result.description = "Deleted character at position " + std::to_string(pos);
    result.success = true;
    return result;
}

MutationResult ClassExpandOp::apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    MutationResult result;
    result.success = false;
    result.ast = ast;
    return result;
}

MutationResult ClassReduceOp::apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    MutationResult result;
    result.success = false;
    result.ast = ast;
    return result;
}

MutationResult QuantifierGreedyLazyOp::apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    MutationResult result;
    result.success = false;
    result.ast = ast;
    return result;
}

MutationResult OptionalInsertOp::apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    MutationResult result;
    result.success = false;
    
    auto copy = copyNode(ast);
    
    auto makeOptional = [](std::shared_ptr<PatternNode> node) -> std::shared_ptr<PatternNode> {
        auto opt = PatternNode::createQuantified(node, PatternType::OPTIONAL);
        return opt;
    };
    
    std::function<void(std::shared_ptr<PatternNode>)> visit = [&](std::shared_ptr<PatternNode> node) {
        if (!node || result.success) return;
        if (node->type == PatternType::LITERAL && !node->value.empty()) {
            node->type = PatternType::OPTIONAL;
            node->quantified = PatternNode::createLiteral(node->value, node->matched_seeds, node->counter_seeds);
            node->value.clear();
            result.success = true;
            return;
        }
        if (node->quantified) visit(node->quantified);
        for (auto& child : node->children) visit(child);
    };
    visit(copy);
    
    if (result.success) {
        result.ast = copy;
        result.description = "Made element optional with ?";
    } else {
        result.ast = ast;
    }
    return result;
}

MutationResult GroupInsertOp::apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    MutationResult result;
    result.success = false;
    result.ast = ast;
    return result;
}

MutationResult GroupRemoveOp::apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    MutationResult result;
    result.success = false;
    result.ast = ast;
    return result;
}

MutationResult EscapeInsertOp::apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    MutationResult result;
    result.success = false;
    
    std::vector<std::shared_ptr<PatternNode>> literals;
    if (!findLiteralNode(ast, literals)) return result;
    
    auto target = literals[std::uniform_int_distribution<size_t>(0, literals.size() - 1)(rng)];
    static const char metachars[] = ".^$*+?{}[]\\|()";
    std::string chars(metachars);
    
    auto copy = copyNode(ast);
    for (auto& lit : literals) {
        if (lit == target) {
            for (char c : chars) {
                size_t pos = lit->value.find(c);
                if (pos != std::string::npos) {
                    lit->value.insert(pos, "\\");
                    result.description = "Escaped '" + std::string(1, c) + "'";
                    result.success = true;
                    break;
                }
            }
            break;
        }
    }
    
    if (result.success) {
        result.ast = copy;
    } else {
        result.ast = ast;
    }
    return result;
}

MutationResult EscapeRemoveOp::apply(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    MutationResult result;
    result.success = false;
    result.ast = ast;
    return result;
}

MutationEngine::MutationEngine() {
    operators.push_back(std::make_unique<CharSubstituteOp>());
    operators.push_back(std::make_unique<CharInsertOp>());
    operators.push_back(std::make_unique<CharDeleteOp>());
    operators.push_back(std::make_unique<ClassExpandOp>());
    operators.push_back(std::make_unique<ClassReduceOp>());
    operators.push_back(std::make_unique<QuantifierGreedyLazyOp>());
    operators.push_back(std::make_unique<OptionalInsertOp>());
    operators.push_back(std::make_unique<GroupInsertOp>());
    operators.push_back(std::make_unique<GroupRemoveOp>());
    operators.push_back(std::make_unique<EscapeInsertOp>());
    operators.push_back(std::make_unique<EscapeRemoveOp>());
}

std::vector<MutationResult> MutationEngine::mutate(
    std::shared_ptr<PatternNode> ast,
    size_t max_mutations,
    std::mt19937& rng
) const {
    std::vector<MutationResult> results;
    for (auto& op : operators) {
        auto result = op->apply(ast, rng);
        if (result.success) {
            results.push_back(result);
            if (results.size() >= max_mutations) break;
        }
    }
    return results;
}

std::vector<std::unique_ptr<MutationOperator>> MutationEngine::allOperators() {
    MutationEngine engine;
    return std::move(engine.operators);
}

GenerationResult AddAlternativeOp::generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    GenerationResult result;
    result.success = false;
    
    if (ast->type == PatternType::LITERAL) {
        std::string newAlt = randomChar(rng) + randomChar(rng);
        auto alts = std::vector<std::shared_ptr<PatternNode>>{
            PatternNode::createLiteral(ast->value, ast->matched_seeds, ast->counter_seeds),
            PatternNode::createLiteral(newAlt)
        };
        auto altNode = PatternNode::createAlternation(alts, {ast->value, newAlt});
        altNode->type = PatternType::PLUS_QUANTIFIER;
        altNode->quantified = PatternNode::createAlternation(alts, {ast->value, newAlt});
        result.ast = altNode;
        result.description = "Added alternative '" + newAlt + "'";
        result.success = true;
    }
    
    return result;
}

GenerationResult ExtendSequenceOp::generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    GenerationResult result;
    result.success = false;
    
    if (ast->type == PatternType::LITERAL) {
        auto copy = copyNode(ast);
        copy->value += randomChar(rng);
        result.ast = copy;
        result.description = "Extended sequence with character";
        result.success = true;
    }
    
    return result;
}

GenerationResult NestQuantifierOp::generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    GenerationResult result;
    result.success = false;
    
    auto copy = copyNode(ast);
    auto quantified = PatternNode::createQuantified(copy, PatternType::PLUS_QUANTIFIER);
    result.ast = quantified;
    result.description = "Wrapped with + quantifier";
    result.success = true;
    
    return result;
}

GenerationResult AddPrefixOp::generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    GenerationResult result;
    result.success = false;
    result.ast = ast;
    return result;
}

GenerationResult AddSuffixOp::generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    GenerationResult result;
    result.success = false;
    result.ast = ast;
    return result;
}

GenerationResult LiteralToFragmentOp::generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    GenerationResult result;
    result.success = false;
    result.ast = ast;
    return result;
}

GenerationResult SplitAlternationOp::generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    GenerationResult result;
    result.success = false;
    
    if (ast->type == PatternType::LITERAL && ast->value.size() >= 2) {
        std::string s1(1, ast->value[0]);
        std::string s2 = ast->value.substr(1);
        auto alts = std::vector<std::shared_ptr<PatternNode>>{
            PatternNode::createLiteral(s1),
            PatternNode::createLiteral(s2)
        };
        result.ast = PatternNode::createAlternation(alts);
        result.description = "Split into alternation";
        result.success = true;
    }
    
    return result;
}

GenerationResult DeepenNestingOp::generate(std::shared_ptr<PatternNode> ast, std::mt19937& rng) const {
    GenerationResult result;
    result.success = false;
    
    auto copy = copyNode(ast);
    auto star = PatternNode::createQuantified(copy, PatternType::STAR_QUANTIFIER);
    auto plus = PatternNode::createQuantified(star, PatternType::PLUS_QUANTIFIER);
    result.ast = plus;
    result.description = "Deepened nesting with + and *";
    result.success = true;
    
    return result;
}

GenerationEngine::GenerationEngine() {
    operators.push_back(std::make_unique<AddAlternativeOp>());
    operators.push_back(std::make_unique<ExtendSequenceOp>());
    operators.push_back(std::make_unique<NestQuantifierOp>());
    operators.push_back(std::make_unique<AddPrefixOp>());
    operators.push_back(std::make_unique<AddSuffixOp>());
    operators.push_back(std::make_unique<LiteralToFragmentOp>());
    operators.push_back(std::make_unique<SplitAlternationOp>());
    operators.push_back(std::make_unique<DeepenNestingOp>());
}

std::vector<GenerationResult> GenerationEngine::generate(
    std::shared_ptr<PatternNode> ast,
    size_t max_variants,
    std::mt19937& rng
) const {
    std::vector<GenerationResult> results;
    for (auto& op : operators) {
        auto result = op->generate(ast, rng);
        if (result.success) {
            results.push_back(result);
            if (results.size() >= max_variants) break;
        }
    }
    return results;
}

std::vector<std::unique_ptr<GenerationOperator>> GenerationEngine::allOperators() {
    GenerationEngine engine;
    return std::move(engine.operators);
}

} // namespace TestGen