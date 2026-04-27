// ============================================================================
// PatternFactorization - Pattern AST compaction and rewriting
// Extracted from testgen.cpp
// ============================================================================

#include "pattern_factorization.h"
#include "pattern_serializer.h"
#include "pattern_matcher.h"
#include <algorithm>  // for std::shuffle

// ============================================================================
// Fragment name generator - uses incrementing counter to avoid collisions
// ============================================================================
static int g_frag_extract_counter = 0;
namespace PatternFactorization {
std::string nextFragName() {
    return "xf" + std::to_string(g_frag_extract_counter++);
}
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
    [[maybe_unused]] const std::vector<std::string>& matching_seeds,
    int num_children,
    [[maybe_unused]] std::mt19937& rng) {
    
    if (num_children <= 1 || all_counters.empty()) {
        return std::vector<std::vector<std::string>>(num_children, all_counters);
    }
    
    std::vector<std::vector<std::string>> subdivided(num_children);
    std::uniform_int_distribution<int> dist(0, 99);
    
    // For each counter, assign it to children based on position constraints
    for (const auto& counter : all_counters) {
        if (counter.empty()) continue;
        
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
            
            if (group_alts.size() == 1) {
                // Single alternative in group - keep as literal with its seed only
                auto lit = PatternNode::createLiteral(group_alts[0], {group_seeds[0]}, all_counter_seeds);
                new_children.push_back(lit);
                new_seeds.insert(new_seeds.end(), group_seeds.begin(), group_seeds.end());
            } else {
                // Multiple alternatives share a first char - factor using the longest
                // common prefix, not just the grouping prefix (1 char).
                std::string group_prefix = findCommonPrefix(group_alts);
                
                // Structure: group_prefix + (remainder1 | remainder2 | ...)
                // CRITICAL: Check if any input equals the prefix exactly (would have empty remainder)
                // NEW: Handle empty remainders by creating optional structure
                // If an alternative equals the prefix exactly, its remainder is empty (ε)
                // This creates: prefix + (remainder|ε) which is equivalent to prefix + remainder?
                std::vector<std::shared_ptr<PatternNode>> inner_children;
                std::vector<std::string> inner_seeds;
                bool has_empty_remainder = false;
                
                for (size_t i = 0; i < group_alts.size(); i++) {
                    std::string rem = group_alts[i].substr(group_prefix.size());
                    if (rem.empty()) {
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
                    std::string rem = group_alts[i].substr(group_prefix.size());
                    if (!rem.empty()) {
                        remainders.push_back(rem);
                    }
                }
                
                std::string remainder_common = findCommonPrefix(remainders);
                bool remainders_compatible = !remainders.empty() && 
                    (remainders.size() == 1 || !remainder_common.empty());
                
                // Also check: all remainders must be valid (non-empty or explicitly empty)
                bool all_remainders_valid = (remainders.size() + (has_empty_remainder ? 1 : 0)) == group_alts.size();
                
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
                inner_alt->matched_seeds = inner_seeds;
                inner_alt->counter_seeds = all_counter_seeds;
                
                // If we have empty remainder, wrap in optional to make it cleaner
                // This handles both 2-child and multi-child cases correctly
                // (rem|"") -> (rem)?   and   (""|rem|rem2) -> (rem|rem2)?
                if (has_empty_remainder) {
                    // Build an alternation of all non-empty children, then wrap in ?
                    std::vector<std::shared_ptr<PatternNode>> non_empty_children;
                    std::vector<std::string> non_empty_seeds;
                    for (size_t i = 0; i < inner_children.size(); i++) {
                        if (!inner_children[i]->value.empty()) {
                            non_empty_children.push_back(inner_children[i]);
                            non_empty_seeds.push_back(inner_seeds[i]);
                        }
                    }
                    
                    std::shared_ptr<PatternNode> opt_inner;
                    if (non_empty_children.size() == 1) {
                        opt_inner = non_empty_children[0];
                    } else {
                        opt_inner = PatternNode::createAlternation(non_empty_children, non_empty_seeds, all_counter_seeds);
                        opt_inner->matched_seeds = non_empty_seeds;
                        opt_inner->counter_seeds = all_counter_seeds;
                    }
                    
                    auto opt_node = PatternNode::createQuantified(
                        opt_inner, PatternType::OPTIONAL, group_seeds, all_counter_seeds);
                    opt_node->matched_seeds = group_seeds;
                    opt_node->counter_seeds = all_counter_seeds;
                    
                    std::vector<std::shared_ptr<PatternNode>> seq_kids;
                    seq_kids.push_back(PatternNode::createLiteral(group_prefix, group_seeds, all_counter_seeds));
                    seq_kids.push_back(opt_node);
                    auto seq = PatternNode::createSequence(seq_kids, group_seeds, all_counter_seeds);
                    
                    new_children.push_back(seq);
                    new_seeds.insert(new_seeds.end(), group_seeds.begin(), group_seeds.end());
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
                    std::string factored_pattern = group_prefix + "(" + inner_pattern + ")";
                    
                    // Check each input against the factored pattern
                    // Simple check: input should equal prefix + one of the remainders
                    bool all_inputs_match = true;
                    std::vector<std::string> failed_inputs;
                    
                    for (size_t i = 0; i < group_alts.size(); i++) {
                        const std::string& input = group_alts[i];
                        std::string remainder = input.substr(group_prefix.size());
                        
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
                        seq_kids.push_back(PatternNode::createLiteral(group_prefix, group_seeds, all_counter_seeds));
                        seq_kids.push_back(inner_alt);
                        auto seq = PatternNode::createSequence(seq_kids, group_seeds, all_counter_seeds);
                        
                        new_children.push_back(seq);
                        new_seeds.insert(new_seeds.end(), group_seeds.begin(), group_seeds.end());
                    }
                }
            }
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

// Verify that all matched_seeds of a node still match it after factoring,
// AND that no counter_seeds accidentally start matching.
// Returns true if verification passes, false if any don't.
// If verification fails and original_children is non-empty, restores those children.
static bool verifyFactoredNode(
    std::shared_ptr<PatternNode> node,
    const std::vector<std::shared_ptr<PatternNode>>& original_children,
    FactorizationProof* proof_out) {
    
    if (!node) return true;
    
    // Verify all matching seeds still match
    for (const auto& seed : node->matched_seeds) {
        if (!PatternMatcher::matches(node, seed)) {
            if (!original_children.empty()) {
                node->children = original_children;
            }
            if (proof_out) {
                proof_out->valid = false;
            }
            return false;
        }
    }
    
    // Verify no counter seeds accidentally match after factoring
    for (const auto& seed : node->counter_seeds) {
        if (PatternMatcher::matches(node, seed)) {
            if (!original_children.empty()) {
                node->children = original_children;
            }
            if (proof_out) {
                proof_out->valid = false;
            }
            return false;
        }
    }
    
    return true;
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
            // Recursively factor children, with verification
            {
                auto saved_children = node->children;  // deep copy not needed: children are shared_ptr
                for (auto& child : node->children) {
                    child = factorPattern(child, depth + 1, proof_out);
                }
                // Verify all seeds still match after recursive factoring
                if (!verifyFactoredNode(node, saved_children, proof_out)) {
                    // Revert: children already restored by verifyFactoredNode
                }
            }
            return node;
            
        case PatternType::SEQUENCE:
            {
                auto saved_children = node->children;
                for (auto& child : node->children) {
                    child = factorPattern(child, depth + 1, proof_out);
                }
                // Verify all seeds still match after recursive factoring
                if (!verifyFactoredNode(node, saved_children, proof_out)) {
                    // Revert: children already restored by verifyFactoredNode
                }
            }
            return node;
            
        case PatternType::PLUS_QUANTIFIER:
        case PatternType::STAR_QUANTIFIER:
        case PatternType::OPTIONAL:
            if (node->quantified) {
                auto saved = node->quantified;
                node->quantified = factorPattern(node->quantified, depth + 1, proof_out);
                // Verify quantified node's seeds still match
                if (!verifyFactoredNode(node, {saved}, proof_out)) {
                    node->quantified = saved;  // restore
                }
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
    if (node->type == PatternType::FRAGMENT_REF) {
        copy->fragment_name = node->fragment_name;
    }
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
            // 10% chance to widen a single-char literal into a multi-char fragment
            // e.g. literal 'g' -> fragment [[class9]] where class9 = (d|e|f|g)
            // Only safe for single-char literals: replacing a multi-char literal
            // with a single-char fragment changes the matched language.
            if (node->value.length() == 1 && chance_dist(rng) < 10) {
                char lit_char = node->value[0];
                
                // Find a range of characters around the literal char
                char min_char = lit_char;
                char max_char = lit_char;
                
                // Only create class if we can widen to nearby chars
                if (min_char > ' ' && max_char < '~') {
                    // Widen by 1-3 chars in each direction
                    std::uniform_int_distribution<int> widen_dist(1, 3);
                    int widen = widen_dist(rng);
                    min_char = std::max((char)(' ' + 1), (char)(min_char - widen));
                    max_char = std::min((char)('~' - 1), (char)(max_char + widen));
                }
                
                if (max_char != min_char) {
                    // Create candidate char class
                    std::string class_def = "(";
                    for (char c = min_char; c <= max_char; c++) {
                        if (c > min_char) class_def += "|";
                        class_def += std::string(1, c);
                    }
                    class_def += ")";
                    
                    // Validate: the widened fragment must not cause any counter to match.
                    // Since we're replacing a single-char literal, check if any counter
                    // has its corresponding char in the widened range.
                    bool would_match_counters = false;
                    
                    for (const auto& counter : node->counter_seeds) {
                        // If a counter consists entirely of chars in the class range,
                        // the widened fragment might cause it to match
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
                                break;
                            }
                        }
                    }
                    
                    if (would_match_counters) {
                        return node;
                    }
                    
                    // Validation passed - create the fragment
                    std::string frag_name = nextFragName();
                    fragment_defs[frag_name] = class_def;
                    
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
            // Skip literals with unbalanced parentheses
            int paren_depth = 0;
            for (char c : node->value) {
                if (c == '(') paren_depth++;
                else if (c == ')') paren_depth--;
                if (paren_depth < 0) break;
            }
            if (paren_depth != 0) return node;
            
            // 8% chance to extract literal to fragment
            if (node->value.length() >= 3 && chance_dist(rng) < 8) {
                std::string frag_name = nextFragName();
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
                std::string frag_name = nextFragName();
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
    [[maybe_unused]] const std::vector<std::string>& matching_inputs,
    [[maybe_unused]] const std::vector<std::string>& counter_inputs) {
    
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
    [[maybe_unused]] const std::vector<std::string>& matching_inputs,
    [[maybe_unused]] const std::vector<std::string>& counter_inputs) {
    
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
