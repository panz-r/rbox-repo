// ============================================================================
// InductiveBuilder - Constraint-Propagating Pattern AST Construction
//
// Strategies (in order of preference):
// 1. Distinguishing prefix (multi-char)
// 2. Distinguishing char class at any position
// 3. Distinguishing char at any position
// 4. Distinguishing suffix (multi-char)
// 5. Length-based partition
// 6. First-char partition (split by groups)
// 7. Fallback: flat alternation
// ============================================================================

#include "inductive_builder.h"
#include "testgen.h"

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
                bool all_same = true;
                for (const auto& ms : matching_states) {
                    if (ms.remaining.find(trial) == 0) {
                        std::string match_rem = ms.remaining.substr(trial.size());
                        if (match_rem != counter_rem) {
                            all_same = false;
                            break;
                        }
                    }
                }
                if (all_same) {
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
                bool all_same = true;
                for (const auto& ms : matching_states) {
                    if (ms.remaining.size() >= trial.size() &&
                        ms.remaining.substr(ms.remaining.size() - trial.size()) == trial) {
                        std::string match_pre = ms.remaining.substr(0, ms.remaining.size() - trial.size());
                        if (match_pre != counter_pre) {
                            all_same = false;
                            break;
                        }
                    }
                }
                if (all_same) {
                    distinguishes = false;
                    break;
                }
            }
        }
        
        if (distinguishes) return trial;
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
    if (depth > 12) {
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
    
    // ---- Strategy 4: Distinguishing suffix ----
    std::string dist_suffix = findDistinguishingSuffix(matching_states, counter_states);
    if (!dist_suffix.empty() && dist_suffix.size() > 0) {
        std::vector<InputState> new_matching;
        std::vector<InputState> new_counter_states;
        
        for (const auto& s : matching_states) {
            if (s.remaining.size() >= dist_suffix.size() &&
                s.remaining.substr(s.remaining.size() - dist_suffix.size()) == dist_suffix) {
                new_matching.push_back(InputState(s.full_input, true));
                new_matching.back().remaining = s.remaining.substr(0, s.remaining.size() - dist_suffix.size());
            }
        }
        for (const auto& c : counter_states) {
            if (c.remaining.size() < dist_suffix.size() ||
                c.remaining.substr(c.remaining.size() - dist_suffix.size()) != dist_suffix) {
                new_counter_states.push_back(InputState(c.full_input, false));
            }
        }
        
        if (!new_matching.empty()) {
            return buildSeqWithSuffix(new_matching, new_counter_states, dist_suffix,
                                      counters_for_children, depth, rng,
                                      "Distinguished by suffix");
        }
    }
    
    // ---- Strategy 5: Length-based partition ----
    // Group matching inputs by length, build pattern for each length group
    {
        std::map<size_t, std::vector<InputState>> by_length;
        for (const auto& s : matching_states) {
            by_length[s.remaining.size()].push_back(s);
        }
        
        if (by_length.size() > 1 && by_length.size() <= 6) {
            // Check if any length group has no counters of that length
            std::set<size_t> counter_lengths;
            for (const auto& cs : counter_states) {
                counter_lengths.insert(cs.remaining.size());
            }
            
            bool has_length_distinction = false;
            for (const auto& [len, group] : by_length) {
                if (!counter_lengths.count(len) && !group.empty()) {
                    has_length_distinction = true;
                    break;
                }
            }
            
            if (has_length_distinction) {
                std::vector<std::shared_ptr<PatternNode>> length_alts;
                std::vector<std::string> all_seeds;
                bool all_ok = true;
                
                for (auto& [len, group] : by_length) {
                    // Get counters of different lengths
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
                        all_ok = false;
                        break;
                    }
                }
                
                if (all_ok && !length_alts.empty()) {
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
            }
        }
    }
    
    // ---- Strategy 6: First-char partition ----
    // Split matching inputs into groups by their first character, build each recursively
    {
        std::map<char, std::vector<InputState>> by_first_char;
        for (const auto& s : matching_states) {
            if (!s.remaining.empty()) {
                by_first_char[s.remaining[0]].push_back(s);
            }
        }
        
        if (by_first_char.size() > 1 && by_first_char.size() <= 8) {
            std::vector<std::shared_ptr<PatternNode>> group_alts;
            std::vector<std::string> all_seeds;
            bool all_ok = true;
            
            for (auto& [fc, group] : by_first_char) {
                auto sub_result = buildRecursive(group, counter_states, depth + 1, rng);
                if (sub_result.success && sub_result.ast) {
                    group_alts.push_back(sub_result.ast);
                    for (const auto& g : group) all_seeds.push_back(g.full_input);
                } else {
                    all_ok = false;
                    break;
                }
            }
            
            if (all_ok && !group_alts.empty()) {
                BuildResult result;
                result.ast = PatternNode::createAlternation(group_alts, all_seeds, counters_for_children);
                result.proof = "  [Depth " + std::to_string(depth) + "] Partitioned by first char (" +
                              std::to_string(by_first_char.size()) + " groups)\n";
                result.success = true;
                return result;
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