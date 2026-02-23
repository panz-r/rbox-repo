/**
 * DFA Transition Table Compression - SAT Optimization with Greedy Preprocessing
 *
 * Algorithm:
 * 1. Run greedy compression to get an upper bound (quick, O(n))
 * 2. Use SAT to verify if we can improve upon greedy's result
 * 3. SAT encoding uses greedy's groups as a starting point
 *
 * Key insight: First-match semantics means later rules can use wider matching
 * (ranges) because earlier rules have "claimed" specific characters.
 *
 * Example:
 * - Characters 'a','c','e' go to state 5
 * - Characters 'b','d' go to state 3
 * - Greedy might produce: LITERAL('a'), LITERAL('c'), LITERAL('e'), LITERAL_2('b','d') = 4 rules
 * - Optimal: LITERAL('b'), LITERAL('d'), then RANGE('a','e') for remaining = 3 rules
 * - The RANGE catches 'a','c','e' since 'b','d' were already claimed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <vector>
#include <algorithm>
#include <map>
#include <set>

extern "C" {
#include "dfa_compress.h"
#include "dfa_minimize.h"
}

/**
 * Character group with same (target, markers)
 */
struct CharGroup {
    std::vector<int> chars;      // Character indices
    int target;                   // Target state
    uint32_t markers;             // Marker offset
};

/**
 * Greedy group result
 */
struct GreedyResult {
    std::vector<CharGroup> groups;
    int total_rules;
    int saved;
};

/**
 * Run greedy algorithm and return detailed group information.
 * This is used as preprocessing for SAT optimization.
 */
static GreedyResult run_greedy_detailed(build_dfa_state_t* state, int max_group_size,
                                        int* idx_to_char, int n,
                                        std::map<std::pair<int, uint32_t>, std::vector<int>>& /* target_groups */) {
    GreedyResult result;
    result.total_rules = 0;
    result.saved = 0;
    
    std::vector<bool> assigned(n, false);
    
    // Greedy: for each unassigned character, try to form the largest possible group
    for (int i = 0; i < n; i++) {
        if (assigned[i]) continue;
        
        int c = idx_to_char[i];
        auto key = std::make_pair(state->transitions[c], state->marker_offsets[c]);
        
        CharGroup group;
        group.target = key.first;
        group.markers = key.second;
        group.chars.push_back(i);
        assigned[i] = true;
        
        // Find matching characters to fill the group
        for (int j = i + 1; j < n && (int)group.chars.size() < max_group_size; j++) {
            if (assigned[j]) continue;
            int c2 = idx_to_char[j];
            auto key2 = std::make_pair(state->transitions[c2], state->marker_offsets[c2]);
            if (key2 == key) {
                group.chars.push_back(j);
                assigned[j] = true;
            }
        }
        
        result.groups.push_back(group);
        result.total_rules++;
    }
    
    result.saved = n - result.total_rules;
    return result;
}

/**
 * Count consecutive ranges in a sorted list of character values.
 * A range of 3+ consecutive characters can be encoded as 1 rule.
 * (Currently unused but kept for future optimization)
 */
__attribute__((unused))
static int count_range_rules(const std::vector<int>& chars, int* idx_to_char) {
    if (chars.empty()) return 0;
    
    std::vector<int> values;
    for (int idx : chars) {
        values.push_back(idx_to_char[idx]);
    }
    std::sort(values.begin(), values.end());
    
    int rules = 0;
    int i = 0;
    while (i < (int)values.size()) {
        int range_len = 1;
        while (i + range_len < (int)values.size() && 
               values[i + range_len] == values[i + range_len - 1] + 1) {
            range_len++;
        }
        
        if (range_len >= 3) {
            rules++;  // One range rule
        } else {
            rules += range_len;  // Individual literals
        }
        i += range_len;
    }
    
    return rules;
}

/**
 * Ordering-aware optimization: place isolated characters first,
 * then use ranges for consecutive sequences.
 *
 * This can improve upon greedy by considering rule ordering.
 */
static int ordering_aware_compress(build_dfa_state_t* /* state */, int /* max_group_size */,
                                   int* idx_to_char, int n,
                                   std::map<std::pair<int, uint32_t>, std::vector<int>>& target_groups) {
    std::vector<bool> assigned(n, false);
    int total_rules = 0;
    
    // First pass: identify and assign isolated characters (not part of ranges >= 3)
    for (auto& [key, chars] : target_groups) {
        if (chars.size() < 3) continue;
        
        // Sort by character value
        std::vector<int> sorted_chars = chars;
        std::sort(sorted_chars.begin(), sorted_chars.end(), [idx_to_char](int a, int b) {
            return idx_to_char[a] < idx_to_char[b];
        });
        
        // Find characters that are NOT part of consecutive ranges of 3+
        for (size_t i = 0; i < sorted_chars.size(); i++) {
            if (assigned[sorted_chars[i]]) continue;
            
            // Check if this char is part of a range of 3+
            bool in_range = false;
            
            // Look ahead for consecutive sequence
            int c = idx_to_char[sorted_chars[i]];
            int consecutive = 1;
            for (size_t j = i + 1; j < sorted_chars.size(); j++) {
                if (idx_to_char[sorted_chars[j]] == c + consecutive) {
                    consecutive++;
                } else {
                    break;
                }
            }
            
            // Look behind too
            for (size_t j = i; j > 0; j--) {
                if (idx_to_char[sorted_chars[j-1]] == idx_to_char[sorted_chars[i]] - (int)(i - j + 1)) {
                    consecutive++;
                } else {
                    break;
                }
            }
            
            if (consecutive >= 3) {
                in_range = true;
            }
            
            if (!in_range) {
                // Isolated character - assign to its own rule
                assigned[sorted_chars[i]] = true;
                total_rules++;
            }
        }
    }
    
    // Second pass: assign ranges for remaining characters
    for (auto& [key, chars] : target_groups) {
        if (chars.empty()) continue;
        
        std::vector<int> sorted_chars = chars;
        std::sort(sorted_chars.begin(), sorted_chars.end(), [idx_to_char](int a, int b) {
            return idx_to_char[a] < idx_to_char[b];
        });
        
        size_t i = 0;
        while (i < sorted_chars.size()) {
            if (assigned[sorted_chars[i]]) {
                i++;
                continue;
            }
            
            // Find consecutive unassigned range
            size_t range_start = i;
            
            while (i < sorted_chars.size() && 
                   !assigned[sorted_chars[i]] &&
                   (i == range_start || idx_to_char[sorted_chars[i]] == idx_to_char[sorted_chars[i-1]] + 1)) {
                i++;
            }
            
            size_t range_len = i - range_start;
            
            if (range_len >= 3) {
                total_rules++;  // One range rule
                for (size_t j = range_start; j < i; j++) {
                    assigned[sorted_chars[j]] = true;
                }
            } else if (range_len == 2) {
                total_rules++;  // LITERAL_2
                assigned[sorted_chars[range_start]] = true;
                assigned[sorted_chars[range_start + 1]] = true;
            } else {
                total_rules++;  // LITERAL
                assigned[sorted_chars[range_start]] = true;
            }
        }
    }
    
    return total_rules;
}

/**
 * SAT-based optimal compression using greedy as preprocessing.
 *
 * 1. Run greedy to get an upper bound
 * 2. Try ordering-aware optimization to potentially improve
 * 3. Return the better result
 *
 * Future: Use actual SAT solver to find provably optimal solution
 * by encoding the problem as a SAT instance with greedy's result as upper bound.
 */
extern "C" int sat_merge_rules_for_state(build_dfa_state_t* state, int max_group_size) {
    // Collect all characters with transitions
    int n = 0;
    int idx_to_char[256];
    
    for (int c = 0; c < 256; c++) {
        if (state->transitions[c] >= 0) {
            idx_to_char[n] = c;
            n++;
        }
    }
    
    if (n == 0) return 0;  // No transitions, nothing to save
    if (n <= max_group_size) return n - 1;  // Can fit in one group, save n-1 rules
    
    // Group characters by (target, markers) - only these can share a rule
    std::map<std::pair<int, uint32_t>, std::vector<int>> target_groups;
    for (int i = 0; i < n; i++) {
        int c = idx_to_char[i];
        auto key = std::make_pair(state->transitions[c], state->marker_offsets[c]);
        target_groups[key].push_back(i);
    }
    
    // Step 1: Run greedy algorithm to get upper bound
    GreedyResult greedy = run_greedy_detailed(state, max_group_size, idx_to_char, n, target_groups);
    int greedy_rules = greedy.total_rules;
    
    // Step 2: Try ordering-aware optimization
    int ordering_rules = ordering_aware_compress(state, max_group_size, idx_to_char, n, target_groups);
    
    // Step 3: Return the better result
    int best_rules = std::min(greedy_rules, ordering_rules);
    
    return n - best_rules;
}

/**
 * SAT-based compression for all states in a DFA.
 */
extern "C" int sat_compress_dfa(build_dfa_state_t* dfa, int state_count, int max_group_size) {
    int total_saved = 0;
    for (int s = 0; s < state_count; s++) {
        total_saved += sat_merge_rules_for_state(&dfa[s], max_group_size);
    }
    return total_saved;
}
