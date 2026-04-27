// ============================================================================
// InductiveBuilder - Constraint-Propagating Pattern AST Construction
//
// Strategies (in order of preference):
// 1. Distinguishing prefix (multi-char)
// 2. Distinguishing char class at any position
// 2b. Fragment-based char class (40% chance, wraps char class in fragment def)
// 2c. Fragment-based LCS splitting (30% chance, wraps longest common substring in fragment)
// 3. Distinguishing char at any position
// 4-6. [Randomized order] Distinguishing suffix, length partition, first-char partition
// 7. Distinguishing substring (anywhere in string, not just prefix/suffix)
// 8. Common substring split (no counter check)
// 9. Repetition detection
// 10. Simultaneous prefix+suffix factorization
// Fallback: flat alternation
// ============================================================================

#include "inductive_builder.h"
#include "testgen.h"
#include "pattern_factorization.h"

#include <algorithm>

using namespace std;

namespace InductiveBuilder {

InputState::InputState(const std::string& input, bool matching) 
    : full_input(input), remaining(input), is_matching(matching) {}

BuildResult::BuildResult() : ast(nullptr), success(false) {}

BuildResult::BuildResult(std::shared_ptr<PatternNode> a, const std::string& p, bool s) 
    : ast(a), proof(p), success(s) {}

// Find common prefix among all strings
std::string commonPrefix(const std::vector<std::string>& strings) {
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

// Find common suffix among all strings
static std::string commonSuffix(const std::vector<std::string>& strings) {
    if (strings.empty()) return "";
    std::string suffix = strings[0];
    for (size_t i = 1; i < strings.size() && !suffix.empty(); i++) {
        size_t j = 0;
        while (j < strings[i].size() && j < suffix.size() &&
               strings[i][strings[i].size() - 1 - j] == suffix[suffix.size() - 1 - j]) {
            j++;
        }
        suffix = suffix.substr(suffix.size() - j);
    }
    return suffix;
}

// Find the longest prefix P such that:
// - All matching inputs start with P
// - P distinguishes from counters (either counter doesn't have P, or remainder differs)
std::string findDistinguishingPrefix(const std::vector<InputState>& matching_states,
                                     const std::vector<InputState>& counter_states) {
    std::vector<std::string> match_remainders;
    for (const auto& ms : matching_states) {
        if (!ms.remaining.empty()) {
            match_remainders.push_back(ms.remaining);
        }
    }
    
    if (match_remainders.empty()) return "";
    
    std::string common = commonPrefix(match_remainders);
    
    for (size_t len = common.size(); len > 0; len--) {
        std::string trial = common.substr(0, len);
        
        bool distinguishes = true;
        for (const auto& cs : counter_states) {
            if (cs.remaining.find(trial) == 0) {
                std::string counter_rem = cs.remaining.substr(trial.size());
                // Reject if ANY matching remainder equals the counter remainder.
                // The old logic only rejected when ALL matched, which allowed
                // counters that shared a remainder with one matching input.
                bool found_match = false;
                for (const auto& ms : matching_states) {
                    if (ms.remaining.find(trial) == 0) {
                        std::string match_rem = ms.remaining.substr(trial.size());
                        if (match_rem == counter_rem) {
                            found_match = true;
                            break;
                        }
                    }
                }
                if (found_match) {
                    distinguishes = false;
                    break;
                }
            }
        }
        
        if (distinguishes) return trial;
    }
    
    return "";
}

// Find the longest suffix S such that:
// - All matching inputs end with S
// - S distinguishes from counters
static std::string findDistinguishingSuffix(const std::vector<InputState>& matching_states,
                                            const std::vector<InputState>& counter_states) {
    std::vector<std::string> match_remainders;
    for (const auto& ms : matching_states) {
        if (!ms.remaining.empty()) {
            match_remainders.push_back(ms.remaining);
        }
    }
    if (match_remainders.empty()) return "";

    std::string common = commonSuffix(match_remainders);
    
    for (size_t len = common.size(); len > 0; len--) {
        std::string trial = common.substr(common.size() - len);
        
        bool distinguishes = true;
        for (const auto& cs : counter_states) {
            if (cs.remaining.size() >= trial.size() &&
                cs.remaining.substr(cs.remaining.size() - trial.size()) == trial) {
                // Counter also ends with trial
                std::string counter_pre = cs.remaining.substr(0, cs.remaining.size() - trial.size());
                // Reject if ANY matching prefix equals the counter prefix.
                // The old logic only rejected when ALL matched, which allowed
                // counters that shared a prefix with one matching input.
                bool found_match = false;
                for (const auto& ms : matching_states) {
                    if (ms.remaining.size() >= trial.size() &&
                        ms.remaining.substr(ms.remaining.size() - trial.size()) == trial) {
                        std::string match_pre = ms.remaining.substr(0, ms.remaining.size() - trial.size());
                        if (match_pre == counter_pre) {
                            found_match = true;
                            break;
                        }
                    }
                }
                if (found_match) {
                    distinguishes = false;
                    break;
                }
            }
        }
        
        if (distinguishes) return trial;
    }
    return "";
}

// Find a substring (not at ends) that appears in ALL matching remainders
// but in NO counter remainder. Returns the longest such substring.
// Unlike prefix/suffix, this can be anywhere in the string.
static std::string findDistinguishingSubstring(
    const std::vector<InputState>& matching_states,
    const std::vector<InputState>& counter_states) {
    
    if (matching_states.size() < 2) return "";
    
    // Collect remainders
    std::vector<std::string> match_rem;
    for (const auto& s : matching_states) {
        if (!s.remaining.empty()) match_rem.push_back(s.remaining);
    }
    if (match_rem.empty()) return "";
    
    size_t min_len = match_rem[0].size();
    for (const auto& r : match_rem) min_len = std::min(min_len, r.size());
    if (min_len < 2) return "";
    
    std::string best;
    
    // Try all substrings of the first matching remainder (longest first)
    for (size_t len = min_len; len >= 2 && best.empty(); len--) {
        for (size_t start = 0; start + len <= match_rem[0].size(); start++) {
            std::string candidate = match_rem[0].substr(start, len);
            
            // Check: present in ALL matching remainders
            bool in_all = true;
            for (size_t j = 1; j < match_rem.size(); j++) {
                if (match_rem[j].find(candidate) == std::string::npos) {
                    in_all = false;
                    break;
                }
            }
            if (!in_all) continue;
            
            // Check: absent from ALL counter remainders
            bool in_any_counter = false;
            for (const auto& cs : counter_states) {
                if (cs.remaining.find(candidate) != std::string::npos) {
                    in_any_counter = true;
                    break;
                }
            }
            if (in_any_counter) continue;
            
            // Found the longest distinguishing substring
            return candidate;
        }
    }
    
    return "";
}

// Find the distinguishing character at position that splits matching vs counter
static std::pair<size_t, char> findDistinguishingChar(
    const std::vector<InputState>& matching_states,
    const std::vector<InputState>& counter_states) {
    
    std::vector<std::string> match_remainders;
    for (const auto& s : matching_states) {
        if (!s.remaining.empty()) {
            match_remainders.push_back(s.remaining);
        }
    }
    if (match_remainders.empty()) return {0, '\0'};
    
    size_t min_len = match_remainders[0].size();
    for (const auto& r : match_remainders) {
        min_len = std::min(min_len, r.size());
    }
    if (min_len == 0) return {0, '\0'};
    
    for (size_t pos = 0; pos < min_len; pos++) {
        char common_char = match_remainders[0][pos];
        bool all_match_same = true;
        
        for (const auto& r : match_remainders) {
            if (r[pos] != common_char) {
                all_match_same = false;
                break;
            }
        }
        
        if (!all_match_same) continue;
        
        bool counter_has_char = false;
        for (const auto& cs : counter_states) {
            if (!cs.remaining.empty() && cs.remaining.size() > pos) {
                if (cs.remaining[pos] == common_char) {
                    counter_has_char = true;
                    break;
                }
            }
        }
        
        if (!counter_has_char) return {pos, common_char};
    }
    
    return {0, '\0'};
}

// Find character class at position that splits matching vs counter
static std::set<char> findDistinguishingCharClass(
    const std::vector<InputState>& matching_states,
    const std::vector<InputState>& counter_states) {
    
    std::vector<std::string> match_remainders;
    for (const auto& s : matching_states) {
        if (!s.remaining.empty()) {
            match_remainders.push_back(s.remaining);
        }
    }
    if (match_remainders.empty()) return {};
    
    size_t min_len = match_remainders[0].size();
    for (const auto& r : match_remainders) {
        min_len = std::min(min_len, r.size());
    }
    if (min_len == 0) return {};
    
    for (size_t pos = 0; pos < min_len; pos++) {
        std::set<char> match_chars;
        bool all_match_same = true;
        
        for (const auto& r : match_remainders) {
            match_chars.insert(r[pos]);
        }
        
        char first_char = match_remainders[0][pos];
        for (const auto& r : match_remainders) {
            if (r[pos] != first_char) {
                all_match_same = false;
                break;
            }
        }
        
        if (all_match_same) {
            bool counter_has_char = false;
            for (const auto& cs : counter_states) {
                if (!cs.remaining.empty() && cs.remaining.size() > pos) {
                    if (cs.remaining[pos] == first_char) {
                        counter_has_char = true;
                        break;
                    }
                }
            }
            if (!counter_has_char) return {first_char};
        }
        
        if (match_chars.size() > 1) {
            std::set<char> counter_chars;
            for (const auto& cs : counter_states) {
                if (!cs.remaining.empty() && cs.remaining.size() > pos) {
                    counter_chars.insert(cs.remaining[pos]);
                }
            }
            
            bool any_intersection = false;
            for (char mc : match_chars) {
                if (counter_chars.count(mc)) {
                    any_intersection = true;
                    break;
                }
            }
            
            if (!any_intersection && !match_chars.empty()) return match_chars;
        }
    }
    
    return {};
}

// Fallback: create alternation of all remainders
static BuildResult makeAlternation(const std::vector<InputState>& matching_states,
                                   const std::vector<InputState>& counter_states,
                                   const std::vector<std::string>& /* original_matching */) {
    BuildResult result;
    
    std::set<std::string> match_set;
    for (const auto& s : matching_states) {
        match_set.insert(s.full_input);
    }
    for (const auto& c : counter_states) {
        if (match_set.count(c.full_input)) {
            result.success = false;
            result.proof = "  [ERROR] Counter \"" + c.full_input + "\" equals a matching input!\n";
            return result;
        }
    }
    
    std::vector<std::shared_ptr<PatternNode>> alts;
    std::vector<std::string> full_seeds;
    std::vector<std::string> all_counters;
    
    for (const auto& c : counter_states) {
        all_counters.push_back(c.full_input);
    }
    
    for (const auto& s : matching_states) {
        alts.push_back(PatternNode::createLiteral(s.full_input, {s.full_input}, all_counters));
        full_seeds.push_back(s.full_input);
    }
    
    if (alts.empty()) {
        result.success = false;
        result.proof = "  [ERROR] No alternatives generated\n";
        return result;
    }
    
    if (alts.size() == 1) {
        result.ast = alts[0];
    } else {
        result.ast = PatternNode::createAlternation(alts, full_seeds, all_counters);
    }
    
    result.proof = "  [SUCCESS] Built alternation of " + std::to_string(alts.size()) + " literals\n";
    result.success = true;
    return result;
}

// Forward declaration for recursion
BuildResult buildRecursive(std::vector<InputState> matching_states,
                           std::vector<InputState> counter_states,
                           int depth,
                                  std::mt19937& rng);

// Build a sequence node from prefix literal + suffix result
static BuildResult buildSeqWithPrefix(
    const std::string& prefix,
    std::vector<InputState>& new_matching,
    std::vector<InputState>& new_counter_states,
    const std::vector<std::string>& counters_for_children,
    int depth,
    std::mt19937& rng,
    const std::string& strategy_name) {
    
    auto suffix_result = buildRecursive(new_matching, new_counter_states, depth + 1, rng);
    
    std::vector<std::shared_ptr<PatternNode>> seq_nodes;
    std::vector<std::string> seeds;
    for (const auto& m : new_matching) seeds.push_back(m.full_input);
    seq_nodes.push_back(PatternNode::createLiteral(prefix, seeds, counters_for_children));
    
    if (suffix_result.success && suffix_result.ast) {
        seq_nodes.push_back(suffix_result.ast);
    } else {
        // Fallback: build literals for remainders
        std::vector<std::shared_ptr<PatternNode>> remainder_alts;
        std::vector<std::string> rem_seeds;
        for (const auto& sm : new_matching) {
            remainder_alts.push_back(PatternNode::createLiteral(sm.remaining, {sm.full_input}, counters_for_children));
            rem_seeds.push_back(sm.full_input);
        }
        if (remainder_alts.size() == 1) {
            seq_nodes.push_back(remainder_alts[0]);
        } else if (!remainder_alts.empty()) {
            seq_nodes.push_back(PatternNode::createAlternation(remainder_alts, rem_seeds, counters_for_children));
        }
    }
    
    BuildResult result;
    result.ast = PatternNode::createSequence(seq_nodes, seeds, counters_for_children);
    // Propagate child fragments
    if (suffix_result.success) {
        for (const auto& [k, v] : suffix_result.fragments) result.fragments[k] = v;
    }
    result.proof = "  [Depth " + std::to_string(depth) + "] " + strategy_name + ": \"" + prefix + "\"\n";
    if (suffix_result.success) result.proof += suffix_result.proof;
    result.success = true;
    return result;
}

// Build a sequence node from prefix result + suffix literal
static BuildResult buildSeqWithSuffix(
    std::vector<InputState>& new_matching,
    std::vector<InputState>& new_counter_states,
    const std::string& suffix,
    const std::vector<std::string>& counters_for_children,
    int depth,
    std::mt19937& rng,
    const std::string& strategy_name) {
    
    auto prefix_result = buildRecursive(new_matching, new_counter_states, depth + 1, rng);
    
    std::vector<std::shared_ptr<PatternNode>> seq_nodes;
    std::vector<std::string> seeds;
    for (const auto& m : new_matching) seeds.push_back(m.full_input);
    
    if (prefix_result.success && prefix_result.ast) {
        seq_nodes.push_back(prefix_result.ast);
    } else {
        std::vector<std::shared_ptr<PatternNode>> prefix_alts;
        std::vector<std::string> pre_seeds;
        for (const auto& sm : new_matching) {
            prefix_alts.push_back(PatternNode::createLiteral(sm.remaining, {sm.full_input}, counters_for_children));
            pre_seeds.push_back(sm.full_input);
        }
        if (prefix_alts.size() == 1) {
            seq_nodes.push_back(prefix_alts[0]);
        } else if (!prefix_alts.empty()) {
            seq_nodes.push_back(PatternNode::createAlternation(prefix_alts, pre_seeds, counters_for_children));
        }
    }
    
    seq_nodes.push_back(PatternNode::createLiteral(suffix, seeds, counters_for_children));
    
    BuildResult result;
    result.ast = PatternNode::createSequence(seq_nodes, seeds, counters_for_children);
    // Propagate child fragments
    if (prefix_result.success) {
        for (const auto& [k, v] : prefix_result.fragments) result.fragments[k] = v;
    }
    result.proof = "  [Depth " + std::to_string(depth) + "] " + strategy_name + ": \"" + suffix + "\"\n";
    if (prefix_result.success) result.proof += prefix_result.proof;
    result.success = true;
    return result;
}

// Main recursive builder
BuildResult buildRecursive(std::vector<InputState> matching_states,
                                  std::vector<InputState> counter_states,
                                  int depth,
                                  std::mt19937& rng) {
    if (depth > 20) {
        return makeAlternation(matching_states, counter_states, {});
    }
    
    // Collect remainders
    std::vector<std::string> match_remainders;
    for (const auto& s : matching_states) {
        if (!s.remaining.empty()) {
            match_remainders.push_back(s.remaining);
        }
    }
    
    if (match_remainders.empty()) {
        return makeAlternation(matching_states, counter_states, {});
    }
    
    // Single matching input: literal
    if (matching_states.size() == 1) {
        BuildResult result;
        std::vector<std::string> counters;
        for (const auto& c : counter_states) counters.push_back(c.full_input);
        result.ast = PatternNode::createLiteral(
            matching_states[0].remaining, {matching_states[0].full_input}, counters);
        result.success = true;
        result.proof = "  [Depth " + std::to_string(depth) + "] Single literal\n";
        return result;
    }
    
    std::vector<std::string> counters_for_children;
    for (const auto& c : counter_states) {
        counters_for_children.push_back(c.full_input);
    }
    
    // ---- Strategy 1: Distinguishing prefix (multi-char) ----
    std::string dist_prefix = findDistinguishingPrefix(matching_states, counter_states);
    if (!dist_prefix.empty() && dist_prefix.size() > 1) {
        std::vector<InputState> new_matching;
        std::vector<InputState> new_counter_states;
        
        for (const auto& s : matching_states) {
            if (s.remaining.size() >= dist_prefix.size() && 
                s.remaining.substr(0, dist_prefix.size()) == dist_prefix) {
                new_matching.push_back(InputState(s.full_input, true));
                new_matching.back().remaining = s.remaining.substr(dist_prefix.size());
            }
        }
        for (const auto& c : counter_states) {
            if (c.remaining.size() < dist_prefix.size() || 
                c.remaining.substr(0, dist_prefix.size()) != dist_prefix) {
                new_counter_states.push_back(InputState(c.full_input, false));
            }
        }
        
        return buildSeqWithPrefix(dist_prefix, new_matching, new_counter_states,
                                  counters_for_children, depth, rng, "Distinguished by prefix");
    }
    
    // ---- Strategy 2: Distinguishing char class ----
    std::set<char> dist_class = findDistinguishingCharClass(matching_states, counter_states);
    if (!dist_class.empty()) {
        if (dist_class.size() == 1) {
            char ch = *dist_class.begin();
            std::string char_str(1, ch);
            std::vector<InputState> new_matching;
            std::vector<InputState> new_counter_states;
            
            for (const auto& s : matching_states) {
                if (!s.remaining.empty() && s.remaining[0] == ch) {
                    new_matching.push_back(InputState(s.full_input, true));
                    new_matching.back().remaining = s.remaining.substr(1);
                }
            }
            for (const auto& c : counter_states) {
                if (c.remaining.empty() || c.remaining[0] != ch) {
                    new_counter_states.push_back(InputState(c.full_input, false));
                }
            }
            
            return buildSeqWithPrefix(char_str, new_matching, new_counter_states,
                                      counters_for_children, depth, rng, "Distinguished by char");
        }
        
        // Multiple chars: build (c1|c2|...) + suffix
        std::vector<std::shared_ptr<PatternNode>> char_alts;
        std::vector<std::string> char_seeds;
        for (char c : dist_class) {
            std::string char_str(1, c);
            char_alts.push_back(PatternNode::createLiteral(char_str, {char_str}, counters_for_children));
            char_seeds.push_back(char_str);
        }
        auto char_alt_node = PatternNode::createAlternation(char_alts, char_seeds, counters_for_children);
        
        std::vector<InputState> new_matching;
        std::vector<InputState> new_counter_states;
        for (const auto& s : matching_states) {
            if (!s.remaining.empty() && dist_class.count(s.remaining[0])) {
                new_matching.push_back(InputState(s.full_input, true));
                new_matching.back().remaining = s.remaining.substr(1);
            }
        }
        for (const auto& c : counter_states) {
            if (c.remaining.empty() || !dist_class.count(c.remaining[0])) {
                new_counter_states.push_back(InputState(c.full_input, false));
            }
        }
        
        auto suffix_result = buildRecursive(new_matching, new_counter_states, depth + 1, rng);
        
        std::vector<std::shared_ptr<PatternNode>> seq_nodes;
        std::vector<std::string> seeds;
        for (const auto& m : new_matching) seeds.push_back(m.full_input);
        seq_nodes.push_back(char_alt_node);
        if (suffix_result.success && suffix_result.ast) {
            seq_nodes.push_back(suffix_result.ast);
        } else {
            std::vector<std::shared_ptr<PatternNode>> rem_alts;
            for (const auto& sm : new_matching) {
                rem_alts.push_back(PatternNode::createLiteral(sm.remaining, {sm.full_input}, counters_for_children));
            }
            if (rem_alts.size() == 1) seq_nodes.push_back(rem_alts[0]);
            else if (!rem_alts.empty()) seq_nodes.push_back(PatternNode::createAlternation(rem_alts, seeds, counters_for_children));
        }
        
        BuildResult result;
        result.ast = PatternNode::createSequence(seq_nodes, seeds, counters_for_children);
        result.proof = "  [Depth " + std::to_string(depth) + "] Distinguished by char class\n";
        if (suffix_result.success) result.proof += suffix_result.proof;
        result.success = true;
        return result;
    }
    
    // ---- Strategy 2b: Fragment-based char class ----
    // Same as Strategy 2 multi-char, but wraps (c1|c2|...) into a fragment definition.
    // Tests the pipeline's fragment expansion path with alternation fragments.
    // Only activates 40% of the time (to avoid always preferring fragments).
    if (!dist_class.empty() && dist_class.size() >= 2 &&
        std::uniform_int_distribution<int>(0, 9)(rng) < 4) {
        
        // Build fragment definition as alternation of single chars
        std::string frag_name = PatternFactorization::nextFragName();
        std::string frag_def;
        for (char c : dist_class) {
            if (!frag_def.empty()) frag_def += "|";
            frag_def += std::string(1, c);
        }
        
        auto frag_ref = PatternNode::createFragment(frag_name);
        
        std::vector<InputState> new_matching;
        std::vector<InputState> new_counter_states;
        for (const auto& s : matching_states) {
            if (!s.remaining.empty() && dist_class.count(s.remaining[0])) {
                new_matching.push_back(InputState(s.full_input, true));
                new_matching.back().remaining = s.remaining.substr(1);
            }
        }
        for (const auto& c : counter_states) {
            if (c.remaining.empty() || !dist_class.count(c.remaining[0])) {
                new_counter_states.push_back(InputState(c.full_input, false));
            }
        }
        
        auto suffix_result = buildRecursive(new_matching, new_counter_states, depth + 1, rng);
        
        std::vector<std::shared_ptr<PatternNode>> seq_nodes;
        std::vector<std::string> seeds;
        for (const auto& m : new_matching) seeds.push_back(m.full_input);
        seq_nodes.push_back(frag_ref);
        if (suffix_result.success && suffix_result.ast) {
            seq_nodes.push_back(suffix_result.ast);
        }
        
        BuildResult result;
        result.ast = PatternNode::createSequence(seq_nodes, seeds, counters_for_children);
        result.fragments[frag_name] = frag_def;
        // Merge child fragments
        if (suffix_result.success) {
            for (const auto& [k, v] : suffix_result.fragments) {
                result.fragments[k] = v;
            }
        }
        result.proof = "  [Depth " + std::to_string(depth) + "] Fragment char class: [[" + frag_name + "]] = " + frag_def + "\n";
        if (suffix_result.success) result.proof += suffix_result.proof;
        result.success = true;
        return result;
    }
    
    // ---- Strategy 2c: Fragment-based LCS splitting ----
    // Find the longest common substring of all matching inputs, define a fragment
    // with that value, and recurse on the pre/post contexts. Tests the pipeline's
    // fragment expansion path with multi-char fragment values.
    // Only activates 30% of the time and requires LCS length >= 2.
    {
        if (matching_states.size() >= 2 && matching_states.size() <= 20 &&
            std::uniform_int_distribution<int>(0, 9)(rng) < 3) {
            
            // Find longest common substring
            std::string best_substr;
            for (size_t i = 0; i < matching_states[0].remaining.size(); i++) {
                for (size_t len = 2; len <= matching_states[0].remaining.size() - i; len++) {
                    std::string substr = matching_states[0].remaining.substr(i, len);
                    bool in_all = true;
                    for (size_t j = 1; j < matching_states.size(); j++) {
                        if (matching_states[j].remaining.find(substr) == std::string::npos) {
                            in_all = false;
                            break;
                        }
                    }
                    if (in_all && substr.size() > best_substr.size()) {
                        best_substr = substr;
                    }
                }
            }
            
            if (best_substr.size() >= 2) {
                std::string frag_name = PatternFactorization::nextFragName();
                
                auto frag_ref = PatternNode::createFragment(frag_name);
                
                // Split each matching input at first occurrence of the LCS
                std::vector<InputState> pre_states, post_states;
                for (const auto& s : matching_states) {
                    size_t pos = s.remaining.find(best_substr);
                    if (pos != std::string::npos) {
                        InputState pre(s.full_input, true);
                        pre.remaining = s.remaining.substr(0, pos);
                        pre_states.push_back(pre);
                        
                        InputState post(s.full_input, true);
                        post.remaining = s.remaining.substr(pos + best_substr.size());
                        post_states.push_back(post);
                    }
                }
                
                if (!pre_states.empty() && !post_states.empty()) {
                    auto pre_result = buildRecursive(pre_states, counter_states, depth + 1, rng);
                    auto post_result = buildRecursive(post_states, counter_states, depth + 1, rng);
                    
                    if (pre_result.success && post_result.success && pre_result.ast && post_result.ast) {
                        std::vector<std::shared_ptr<PatternNode>> seq_children;
                        seq_children.push_back(pre_result.ast);
                        seq_children.push_back(frag_ref);
                        seq_children.push_back(post_result.ast);
                        
                        BuildResult result;
                        result.ast = PatternNode::createSequence(seq_children);
                        std::vector<std::string> seeds;
                        for (const auto& s : matching_states) seeds.push_back(s.full_input);
                        result.ast->matched_seeds = seeds;
                        result.fragments[frag_name] = best_substr;
                        for (const auto& [k, v] : pre_result.fragments) result.fragments[k] = v;
                        for (const auto& [k, v] : post_result.fragments) result.fragments[k] = v;
                        result.proof = "  [Depth " + std::to_string(depth) + "] Fragment LCS: [[" + frag_name + "]] = " + best_substr + "\n" +
                                      pre_result.proof + post_result.proof;
                        result.success = true;
                        return result;
                    }
                }
            }
        }
    }
    
    // ---- Strategy 3: Single distinguishing char ----
    auto [pos, ch] = findDistinguishingChar(matching_states, counter_states);
    if (ch != '\0') {
        std::string char_str(1, ch);
        std::vector<InputState> new_matching;
        std::vector<InputState> new_counter_states;
        
        for (const auto& s : matching_states) {
            if (!s.remaining.empty() && s.remaining[0] == ch) {
                new_matching.push_back(InputState(s.full_input, true));
                new_matching.back().remaining = s.remaining.substr(1);
            }
        }
        for (const auto& c : counter_states) {
            if (c.remaining.empty() || c.remaining[0] != ch) {
                new_counter_states.push_back(InputState(c.full_input, false));
            }
        }
        
        return buildSeqWithPrefix(char_str, new_matching, new_counter_states,
                                  counters_for_children, depth, rng,
                                  "Distinguished by char at pos " + std::to_string(pos));
    }
    
    // ---- Strategies 4-6: Try in randomized order for diversity ----
    // Suffix, length partition, and first-char partition are independent;
    // trying them in different orders yields different ASTs across runs.
    {
        // Define strategy functions as lambdas that return optional BuildResult
        using StratFn = std::function<BuildResult()>;
        struct StratEntry { int id; StratFn fn; };
        
        std::vector<StratEntry> strats;
        
        // Strategy 4: Distinguishing suffix
        strats.push_back({4, [&]() -> BuildResult {
            std::string dsuf = findDistinguishingSuffix(matching_states, counter_states);
            if (dsuf.empty()) return {};
            
            std::vector<InputState> nm, nc;
            for (const auto& s : matching_states) {
                if (s.remaining.size() >= dsuf.size() &&
                    s.remaining.substr(s.remaining.size() - dsuf.size()) == dsuf) {
                    nm.push_back(InputState(s.full_input, true));
                    nm.back().remaining = s.remaining.substr(0, s.remaining.size() - dsuf.size());
                }
            }
            for (const auto& c : counter_states) {
                if (c.remaining.size() < dsuf.size() ||
                    c.remaining.substr(c.remaining.size() - dsuf.size()) != dsuf) {
                    nc.push_back(InputState(c.full_input, false));
                }
            }
            
            if (!nm.empty()) {
                return buildSeqWithSuffix(nm, nc, dsuf, counters_for_children, depth, rng,
                                          "Distinguished by suffix");
            }
            return {};
        }});
        
        // Strategy 5: Length-based partition
        strats.push_back({5, [&]() -> BuildResult {
            std::map<size_t, std::vector<InputState>> by_length;
            for (const auto& s : matching_states) {
                by_length[s.remaining.size()].push_back(s);
            }
            
            if (by_length.size() <= 1 || by_length.size() > 6) return {};
            
            std::set<size_t> counter_lengths;
            for (const auto& cs : counter_states) {
                counter_lengths.insert(cs.remaining.size());
            }
            
            bool has_distinction = false;
            for (const auto& [len, group] : by_length) {
                if (!counter_lengths.count(len) && !group.empty()) {
                    has_distinction = true;
                    break;
                }
            }
            if (!has_distinction) return {};
            
            std::vector<std::shared_ptr<PatternNode>> length_alts;
            std::vector<std::string> all_seeds;
            
            for (auto& [len, group] : by_length) {
                std::vector<InputState> other_counters;
                for (const auto& cs : counter_states) {
                    if (cs.remaining.size() != len) {
                        other_counters.push_back(cs);
                    }
                }
                
                auto sub_result = buildRecursive(group, other_counters, depth + 1, rng);
                if (sub_result.success && sub_result.ast) {
                    length_alts.push_back(sub_result.ast);
                    for (const auto& g : group) all_seeds.push_back(g.full_input);
                } else {
                    return {};
                }
            }
            
            if (!length_alts.empty()) {
                BuildResult result;
                if (length_alts.size() == 1) {
                    result.ast = length_alts[0];
                } else {
                    result.ast = PatternNode::createAlternation(length_alts, all_seeds, counters_for_children);
                }
                result.proof = "  [Depth " + std::to_string(depth) + "] Distinguished by length (" +
                              std::to_string(by_length.size()) + " groups)\n";
                result.success = true;
                return result;
            }
            return {};
        }});
        
        // Strategy 6: First-char partition
        strats.push_back({6, [&]() -> BuildResult {
            std::map<char, std::vector<InputState>> by_fc;
            for (const auto& s : matching_states) {
                if (!s.remaining.empty()) {
                    by_fc[s.remaining[0]].push_back(s);
                }
            }
            
            if (by_fc.size() <= 1 || by_fc.size() > 8) return {};
            
            std::vector<std::shared_ptr<PatternNode>> group_alts;
            std::vector<std::string> all_seeds;
            
            for (auto& [fc, group] : by_fc) {
                auto sub_result = buildRecursive(group, counter_states, depth + 1, rng);
                if (sub_result.success && sub_result.ast) {
                    group_alts.push_back(sub_result.ast);
                    for (const auto& g : group) all_seeds.push_back(g.full_input);
                } else {
                    return {};
                }
            }
            
            if (!group_alts.empty()) {
                BuildResult result;
                result.ast = PatternNode::createAlternation(group_alts, all_seeds, counters_for_children);
                result.proof = "  [Depth " + std::to_string(depth) + "] Partitioned by first char (" +
                              std::to_string(by_fc.size()) + " groups)\n";
                result.success = true;
                return result;
            }
            return {};
        }});
        
        // Shuffle and try each, with depth-dependent bias:
        // even depths favor prefix-oriented, odd depths favor suffix-oriented
        std::shuffle(strats.begin(), strats.end(), rng);
        if (depth % 2 == 1) {
            // Move suffix strategy (id=4) to front if present
            auto it = std::find_if(strats.begin(), strats.end(),
                [](const auto& e) { return e.id == 4; });
            if (it != strats.end() && it != strats.begin()) {
                std::iter_swap(it, strats.begin());
            }
        } else {
            // Move first-char partition (id=6) to front if present
            auto it = std::find_if(strats.begin(), strats.end(),
                [](const auto& e) { return e.id == 6; });
            if (it != strats.end() && it != strats.begin()) {
                std::iter_swap(it, strats.begin());
            }
        }
        for (auto& entry : strats) {
            BuildResult r = entry.fn();
            if (r.success) return r;
        }
    }
    
    // ---- Strategy 7: Distinguishing substring split ----
    // Find a substring (anywhere, not just prefix/suffix) present in ALL matching
    // but absent from ALL counters. Split around it and recurse.
    {
        std::string dist_substr = findDistinguishingSubstring(matching_states, counter_states);
        if (!dist_substr.empty() && dist_substr.size() >= 2) {
            // Find where the substring appears in each matching input (use first occurrence)
            std::vector<InputState> pre_states, post_states;
            for (const auto& s : matching_states) {
                size_t pos = s.remaining.find(dist_substr);
                if (pos != std::string::npos) {
                    InputState pre(s.full_input, s.is_matching);
                    pre.remaining = s.remaining.substr(0, pos);
                    pre_states.push_back(pre);
                    
                    InputState post(s.full_input, s.is_matching);
                    post.remaining = s.remaining.substr(pos + dist_substr.size());
                    post_states.push_back(post);
                }
            }
            
            if (!pre_states.empty() && !post_states.empty()) {
                auto pre_result = buildRecursive(pre_states, counter_states, depth + 1, rng);
                auto post_result = buildRecursive(post_states, counter_states, depth + 1, rng);
                
                if (pre_result.success && post_result.success && pre_result.ast && post_result.ast) {
                    auto lit_node = PatternNode::createLiteral(dist_substr);
                    auto seq_children = std::vector<std::shared_ptr<PatternNode>>{pre_result.ast, lit_node, post_result.ast};
                    BuildResult result;
                    result.ast = PatternNode::createSequence(seq_children);
                    std::vector<std::string> seeds;
                    for (const auto& s : matching_states) seeds.push_back(s.full_input);
                    result.ast->matched_seeds = seeds;
                    // Merge child fragments
                    for (const auto& [k, v] : pre_result.fragments) result.fragments[k] = v;
                    for (const auto& [k, v] : post_result.fragments) result.fragments[k] = v;
                    result.proof = "  [Depth " + std::to_string(depth) + "] Distinguishing substring '" + dist_substr + "'\n" +
                                  pre_result.proof + post_result.proof;
                    result.success = true;
                    return result;
                }
            }
        }
    }
    
    // ---- Strategy 8: Common substring split ----
    // Find longest common substring and split around it
    {
        if (matching_states.size() >= 2 && matching_states.size() <= 20) {
            std::string best_substr;
            // Find common substring in all matching inputs
            for (size_t i = 0; i < matching_states[0].remaining.size(); i++) {
                for (size_t len = 1; len <= matching_states[0].remaining.size() - i; len++) {
                    std::string substr = matching_states[0].remaining.substr(i, len);
                    bool in_all = true;
                    for (size_t j = 1; j < matching_states.size(); j++) {
                        if (matching_states[j].remaining.find(substr) == std::string::npos) {
                            in_all = false;
                            break;
                        }
                    }
                    if (in_all && substr.size() > best_substr.size()) {
                        best_substr = substr;
                    }
                }
            }
            
            if (best_substr.size() >= 2) {
                // Split around the common substring
                std::vector<InputState> pre_states, post_states;
                for (const auto& s : matching_states) {
                    size_t pos = s.remaining.find(best_substr);
                    if (pos != std::string::npos) {
                        InputState pre(s.full_input, s.is_matching);
                        pre.remaining = s.remaining.substr(0, pos);
                        pre_states.push_back(pre);
                        
                        InputState post(s.full_input, s.is_matching);
                        post.remaining = s.remaining.substr(pos + best_substr.size());
                        post_states.push_back(post);
                    }
                }
                
                if (!pre_states.empty() && !post_states.empty()) {
                    auto pre_result = buildRecursive(pre_states, counter_states, depth + 1, rng);
                    auto post_result = buildRecursive(post_states, counter_states, depth + 1, rng);
                    
                    if (pre_result.success && post_result.success && pre_result.ast && post_result.ast) {
                        auto lit_node = PatternNode::createLiteral(best_substr);
                        auto seq_children = std::vector<std::shared_ptr<PatternNode>>{pre_result.ast, lit_node, post_result.ast};
                        BuildResult result;
                        result.ast = PatternNode::createSequence(seq_children);
                        std::vector<std::string> seeds;
                        for (const auto& s : matching_states) seeds.push_back(s.full_input);
                        result.ast->matched_seeds = seeds;
                        result.proof = "  [Depth " + std::to_string(depth) + "] Substring split on '" + best_substr + "'\n" +
                                      pre_result.proof + post_result.proof;
                        result.success = true;
                        return result;
                    }
                }
            }
        }
    }
    
    // ---- Strategy 9: Repetition detection ----
    // If all matching inputs are repetitions of a unit, create a + pattern
    {
        if (matching_states.size() >= 2) {
            std::string unit;
            bool all_repetition = false;
            
            for (const auto& s : matching_states) {
                if (s.remaining.empty()) continue;
                // Find smallest unit that repeats to form this string
                for (size_t u = 1; u <= s.remaining.size() / 2; u++) {
                    std::string candidate = s.remaining.substr(0, u);
                    size_t rep_count = s.remaining.size() / candidate.size();
                    if (rep_count >= 1 && candidate.compare(s.remaining.substr(0, candidate.size() * rep_count)) == 0 &&
                        candidate.size() * rep_count == s.remaining.size()) {
                        bool valid_unit = true;
                        // Check counter inputs don't match this unit
                        for (const auto& c : counter_states) {
                            if (!c.remaining.empty() && c.remaining.find(candidate) != std::string::npos) {
                                valid_unit = false;
                                break;
                            }
                        }
                        if (valid_unit && (unit.empty() || candidate == unit)) {
                            if (unit.empty()) unit = candidate;
                            all_repetition = true;
                        }
                    }
                }
                if (!all_repetition) break;
            }
            
            if (all_repetition && !unit.empty() && unit.size() <= 4) {
                auto unit_node = PatternNode::createLiteral(unit);
                BuildResult result;
                result.ast = PatternNode::createQuantified(unit_node, PatternType::PLUS_QUANTIFIER);
                std::vector<std::string> seeds;
                for (const auto& s : matching_states) seeds.push_back(s.full_input);
                result.ast->matched_seeds = seeds;
                result.proof = "  [Depth " + std::to_string(depth) + "] Repetition detected: '" + unit + "'+\n";
                result.success = true;
                return result;
            }
        }
    }
    
    // ---- Strategy 10: Simultaneous prefix+suffix factorization ----
    // If all matching inputs share both a common prefix P and common suffix S,
    // and P+S is shorter than every input, extract both and recurse on the middle.
    // Produces patterns like a(b|c|de)f from ["abf", "acf", "adef"].
    {
        if (matching_states.size() >= 2) {
            // Find common prefix
            std::string common_pre;
            {
                size_t min_len = matching_states[0].remaining.size();
                for (const auto& s : matching_states) min_len = std::min(min_len, s.remaining.size());
                for (size_t i = 0; i < min_len; i++) {
                    char c = matching_states[0].remaining[i];
                    bool all_same = true;
                    for (size_t j = 1; j < matching_states.size(); j++) {
                        if (matching_states[j].remaining[i] != c) {
                            all_same = false;
                            break;
                        }
                    }
                    if (all_same) common_pre += c;
                    else break;
                }
            }
            
            // Find common suffix
            std::string common_suf;
            {
                size_t min_len = matching_states[0].remaining.size();
                for (const auto& s : matching_states) min_len = std::min(min_len, s.remaining.size());
                for (size_t i = 0; i < min_len; i++) {
                    char c = matching_states[0].remaining[matching_states[0].remaining.size() - 1 - i];
                    bool all_same = true;
                    for (size_t j = 1; j < matching_states.size(); j++) {
                        if (matching_states[j].remaining[matching_states[j].remaining.size() - 1 - i] != c) {
                            all_same = false;
                            break;
                        }
                    }
                    if (all_same) common_suf = c + common_suf;
                    else break;
                }
            }
            
            // Need both prefix and suffix, and they can't overlap
            if (common_pre.size() >= 1 && common_suf.size() >= 1) {
                // Check that prefix+suffix don't overlap in any input
                bool no_overlap = true;
                for (const auto& s : matching_states) {
                    if (common_pre.size() + common_suf.size() > s.remaining.size()) {
                        no_overlap = false;
                        break;
                    }
                }
                
                if (no_overlap) {
                    // Build middle subproblem: strip prefix and suffix from each matching input
                    std::vector<InputState> middle_states;
                    for (const auto& s : matching_states) {
                        InputState mid(s.full_input, true);
                        size_t pre_len = common_pre.size();
                        size_t suf_len = common_suf.size();
                        mid.remaining = s.remaining.substr(pre_len, s.remaining.size() - pre_len - suf_len);
                        middle_states.push_back(mid);
                    }
                    
                    // Check that at least some middle parts are non-empty
                    bool any_nonempty = false;
                    for (const auto& m : middle_states) {
                        if (!m.remaining.empty()) { any_nonempty = true; break; }
                    }
                    
                    if (any_nonempty) {
                        // Filter counters: only those that start with prefix and end with suffix
                        // are relevant for the middle subproblem
                        std::vector<InputState> relevant_counters;
                        for (const auto& c : counter_states) {
                            if (c.remaining.size() >= common_pre.size() + common_suf.size() &&
                                c.remaining.substr(0, common_pre.size()) == common_pre &&
                                c.remaining.substr(c.remaining.size() - common_suf.size()) == common_suf) {
                                InputState mid_c(c.full_input, false);
                                mid_c.remaining = c.remaining.substr(common_pre.size(),
                                    c.remaining.size() - common_pre.size() - common_suf.size());
                                relevant_counters.push_back(mid_c);
                            }
                        }
                        
                        auto middle_result = buildRecursive(middle_states, relevant_counters, depth + 1, rng);
                        
                        if (middle_result.success && middle_result.ast) {
                            auto pre_node = PatternNode::createLiteral(common_pre);
                            auto suf_node = PatternNode::createLiteral(common_suf);
                            std::vector<std::shared_ptr<PatternNode>> seq_children;
                            seq_children.push_back(pre_node);
                            seq_children.push_back(middle_result.ast);
                            seq_children.push_back(suf_node);
                            
                            BuildResult result;
                            result.ast = PatternNode::createSequence(seq_children);
                            std::vector<std::string> seeds;
                            for (const auto& s : matching_states) seeds.push_back(s.full_input);
                            result.ast->matched_seeds = seeds;
                            for (const auto& [k, v] : middle_result.fragments) result.fragments[k] = v;
                            result.proof = "  [Depth " + std::to_string(depth) + "] Simultaneous prefix+suffix: '" +
                                          common_pre + "' + middle + '" + common_suf + "'\n" +
                                          middle_result.proof;
                            result.success = true;
                            return result;
                        }
                    }
                }
            }
        }
    }
    
    // Fallback: flat alternation
    return makeAlternation(matching_states, counter_states, {});
}

// Top-level entry point
BuildResult buildInductive(const std::vector<std::string>& matching,
                          const std::vector<std::string>& counters,
                          std::mt19937& rng) {
    std::vector<InputState> matching_states;
    for (const auto& m : matching) {
        matching_states.push_back(InputState(m, true));
    }
    
    std::vector<InputState> counter_states;
    for (const auto& c : counters) {
        counter_states.push_back(InputState(c, false));
    }
    
    BuildResult result = buildRecursive(matching_states, counter_states, 0, rng);
    
    // Retry with different depth budget if first attempt failed
    // (randomized starting depth effectively varies the recursion budget)
    if (!result.success && matching.size() >= 2) {
        // Try starting at depth 1-3, which reduces the effective budget from 12 to 9-11
        int start_depth = 1 + std::uniform_int_distribution<int>(0, 2)(rng);
        result = buildRecursive(matching_states, counter_states, start_depth, rng);
        if (result.success) {
            result.proof = "INDUCTIVE BUILD (reduced depth budget, start=" + std::to_string(start_depth) + "):\n" + result.proof;
        }
    }
    
    if (result.success && result.ast) {
        std::string proof = "INDUCTIVE BUILD:\n";
        proof += "  Strategy: Constraint-propagating prefix/suffix/length building\n";
        proof += "  Initial Specification:\n";
        proof += "    Let M = {";
        for (size_t i = 0; i < matching.size() && i < 3; i++) {
            if (i > 0) proof += ", ";
            proof += matching[i];
        }
        if (matching.size() > 3) proof += ", ...";
        proof += "} (matching inputs)\n";
        proof += "    Let C = {";
        for (size_t i = 0; i < counters.size() && i < 3; i++) {
            if (i > 0) proof += ", ";
            proof += counters[i];
        }
        if (counters.size() > 3) proof += ", ...";
        proof += "} (" + std::to_string(counters.size()) + " counter inputs)\n";
        proof += "  Constraint: ∀m∈M: pattern matches m; ∀c∈C: pattern does NOT match c\n";
        result.proof = proof + result.proof;
    } else {
        result.proof = "INDUCTIVE BUILD FAILED\n";
    }
    
    return result;
}

} // namespace InductiveBuilder