/**
 * DFA Transition Table Compression - Bounded SAT Optimization
 *
 * Problem: Cover all character transitions with minimum rules.
 * Rule types: LITERAL(1), LITERAL_2(2), LITERAL_3(3), RANGE(3+ consecutive)
 * First-match semantics: later rules can be wider because earlier rules
 * "claim" specific characters.
 *
 * Example (from header):
 *   Target A: {a,c,e}, Target B: {b,d}
 *   Greedy: LITERAL(a), LITERAL(c), LITERAL(e), LITERAL_2(b,d) = 4 rules
 *   Optimal: LITERAL(b), LITERAL(d), RANGE(a-e) = 3 rules
 *   RANGE(a-e) catches a,c,e since b,d were already matched
 *
 * Encoding (bounded, per target group):
 *   - Characters partitioned by (target, markers)
 *   - For each group: minimum set cover over rule candidates
 *   - Candidates: LITERAL, LITERAL_2, LITERAL_3, RANGE
 *   - Range candidates can include characters from other groups IF
 *     those characters have their own literal rules (first-match masking)
 *   - SAT finds optimal combination with totalizer cardinality bound
 *
 * Bounded complexity per state:
 *   Characters:  n <= 256 (typically 10-40)
 *   Candidates:  O(n^2) <= 65,536 (typically ~500)
 *   Clauses:     O(n^3) coverage + totalizer O(m log m)
 *   Totalizer:   O(m log m) where m = candidate count
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

#ifdef USE_CADICAL
#include <functional>
#include "cadical.hpp"
#endif

extern "C" {
#include "dfa_compress.h"
#include "dfa_minimize.h"
}

#ifdef USE_CADICAL
static bool sat_verbose = true;
#define VERBOSE_PRINT(...) do { \
    if (sat_verbose) fprintf(stderr, "[COMPRESS-SAT] " __VA_ARGS__); \
} while(0)
#endif

// ============================================================================
// Bounded SAT Constants
//
// ALL SAT instances MUST be bounded by compile-time constants.
// The totalizer encoding uses O(m log m) auxiliary variables where
// m = candidate count. To prevent unbounded memory growth:
//   - MAX_GROUP_SIZE caps per-group characters (limits LITERAL_3 combos)
//   - MAX_TOTAL_CANDIDATES caps total candidates per SAT instance
//
// When bounds are exceeded, the solver falls back to greedy.
// ============================================================================

#define MAX_GROUP_SIZE 32           // Max chars per (target, markers) group
#define MAX_TOTAL_CANDIDATES 1000   // Max total candidates per SAT instance
#define MAX_TOTALIZER_VARS 20000    // Max auxiliary vars (safety limit: ~1000*log2(1000))

// ============================================================================
// Data Structures
// ============================================================================

/**
 * A rule candidate that can cover a set of characters.
 */
struct RuleCandidate {
    std::vector<int> chars;       // Character values covered
    int target;                   // Target state
    uint32_t markers;             // Marker offset
    bool is_range;                // true = RANGE, false = LITERAL_N

    // For cross-target masking: characters that must be covered by
    // earlier rules if this range candidate is selected
    std::vector<int> mask_chars;  // Non-target chars in range interval
};

/**
 * Character info
 */
struct CharInfo {
    int value;        // Character value (0-255)
    int target;       // Target state
    uint32_t markers; // Marker offset
};

// ============================================================================
// Candidate Generation
// ============================================================================

/**
 * Group characters by (target, markers).
 */
static std::map<std::pair<int, uint32_t>, std::vector<int>>
group_by_target(const std::vector<CharInfo>& chars) {
    std::map<std::pair<int, uint32_t>, std::vector<int>> groups;
    for (size_t i = 0; i < chars.size(); i++) {
        auto key = std::make_pair(chars[i].target, chars[i].markers);
        groups[key].push_back((int)i);
    }
    return groups;
}



/**
 * Generate all rule candidates for a single DFA state.
 * Includes within-group candidates and cross-target masking candidates.
 *
 * BOUNDED: group size capped at MAX_GROUP_SIZE, total candidates capped
 * at MAX_TOTAL_CANDIDATES. LITERAL_3 removed (causes O(g³) explosion).
 */
static std::vector<RuleCandidate> generate_candidates(
    const std::vector<CharInfo>& chars
) {
    std::vector<RuleCandidate> candidates;
    auto groups = group_by_target(chars);

    // Build lookup: char value -> group key
    std::map<int, std::pair<int, uint32_t>> char_to_group;
    for (size_t i = 0; i < chars.size(); i++) {
        char_to_group[chars[i].value] = std::make_pair(chars[i].target, chars[i].markers);
    }

    for (auto& [key, indices] : groups) {
        int target = key.first;
        uint32_t markers = key.second;

        // Sort group by character value
        std::vector<int> sorted = indices;
        std::sort(sorted.begin(), sorted.end(), [&](int a, int b) {
            return chars[a].value < chars[b].value;
        });

        // Cap group size to bound candidate count
        int group_size = (int)sorted.size();
        if (group_size > MAX_GROUP_SIZE) {
            // Only consider first MAX_GROUP_SIZE chars for SAT candidates
            // Remaining chars handled by greedy fallback
            group_size = MAX_GROUP_SIZE;
        }

        // Build set of character values in this group
        std::set<int> group_values;
        for (int idx : sorted) group_values.insert(chars[idx].value);

        // --- LITERAL candidates (bounded by MAX_GROUP_SIZE) ---
        for (int i = 0; i < group_size; i++) {
            if ((int)candidates.size() >= MAX_TOTAL_CANDIDATES) return candidates;
            RuleCandidate lit;
            lit.target = target;
            lit.markers = markers;
            lit.is_range = false;
            lit.chars.push_back(chars[sorted[i]].value);
            candidates.push_back(lit);
        }

        // LITERAL_2 (bounded: at most MAX_GROUP_SIZE*(MAX_GROUP_SIZE-1)/2)
        for (int i = 0; i < group_size; i++) {
            for (int j = i + 1; j < group_size; j++) {
                if ((int)candidates.size() >= MAX_TOTAL_CANDIDATES) return candidates;
                RuleCandidate lit;
                lit.target = target;
                lit.markers = markers;
                lit.is_range = false;
                lit.chars.push_back(chars[sorted[i]].value);
                lit.chars.push_back(chars[sorted[j]].value);
                candidates.push_back(lit);
            }
        }

        // NOTE: LITERAL_3 intentionally omitted — causes O(g³) candidate
        // explosion (C(256,3) = 2.7M for large groups). LITERAL + LITERAL_2
        // + RANGE is sufficient for SAT to improve over greedy.

        // --- RANGE candidates (bounded by group_size) ---
        int run_start = 0;
        for (int i = 1; i <= group_size; i++) {
            if ((int)candidates.size() >= MAX_TOTAL_CANDIDATES) return candidates;

            bool end_of_run = (i == group_size) ||
                              (chars[sorted[i]].value != chars[sorted[i-1]].value + 1);

            if (end_of_run) {
                int run_len = i - run_start;
                if (run_len >= 3) {
                    int lo = chars[sorted[run_start]].value;
                    int hi = chars[sorted[i-1]].value;

                    // Within-group range
                    RuleCandidate rng;
                    rng.target = target;
                    rng.markers = markers;
                    rng.is_range = true;
                    for (int j = run_start; j < i; j++) {
                        rng.chars.push_back(chars[sorted[j]].value);
                    }
                    candidates.push_back(rng);

                    // Cross-target masking ranges: extend range beyond group bounds
                    // Extend left
                    for (int ext_lo = lo - 1; ext_lo >= 0; ext_lo--) {
                        if ((int)candidates.size() >= MAX_TOTAL_CANDIDATES) return candidates;
                        auto it = char_to_group.find(ext_lo);
                        if (it == char_to_group.end()) continue;
                        if (it->second == key) continue;

                        RuleCandidate masked_rng;
                        masked_rng.target = target;
                        masked_rng.markers = markers;
                        masked_rng.is_range = true;
                        for (int j = run_start; j < i; j++) {
                            masked_rng.chars.push_back(chars[sorted[j]].value);
                        }
                        masked_rng.mask_chars.push_back(ext_lo);

                        bool gap_has_chars = false;
                        for (int gap = ext_lo + 1; gap < lo; gap++) {
                            if (char_to_group.count(gap)) gap_has_chars = true;
                        }
                        if (!gap_has_chars) {
                            candidates.push_back(masked_rng);
                        }
                        break;
                    }

                    // Extend right
                    for (int ext_hi = hi + 1; ext_hi <= 255; ext_hi++) {
                        if ((int)candidates.size() >= MAX_TOTAL_CANDIDATES) return candidates;
                        auto it = char_to_group.find(ext_hi);
                        if (it == char_to_group.end()) continue;
                        if (it->second == key) continue;

                        RuleCandidate masked_rng;
                        masked_rng.target = target;
                        masked_rng.markers = markers;
                        masked_rng.is_range = true;
                        for (int j = run_start; j < i; j++) {
                            masked_rng.chars.push_back(chars[sorted[j]].value);
                        }
                        masked_rng.mask_chars.push_back(ext_hi);

                        bool gap_has_chars = false;
                        for (int gap = hi + 1; gap < ext_hi; gap++) {
                            if (char_to_group.count(gap)) gap_has_chars = true;
                        }
                        if (!gap_has_chars) {
                            candidates.push_back(masked_rng);
                        }
                        break;
                    }
                }
                run_start = i;
            }
        }
    }

    return candidates;
}

// ============================================================================
// Greedy Solver (Fallback)
// ============================================================================

/**
 * Greedy set cover: always pick the candidate covering the most uncovered chars.
 */
static int greedy_min_rules(const std::vector<CharInfo>& chars,
                             const std::vector<RuleCandidate>& candidates) {
    int n = (int)chars.size();
    std::vector<bool> covered(n, false);
    int rules = 0;

    while (true) {
        int best_idx = -1;
        int best_cover = 0;

        for (size_t i = 0; i < candidates.size(); i++) {
            int cnt = 0;
            for (int cv : candidates[i].chars) {
                for (int j = 0; j < n; j++) {
                    if (!covered[j] && chars[j].value == cv &&
                        chars[j].target == candidates[i].target &&
                        chars[j].markers == candidates[i].markers) {
                        cnt++;
                    }
                }
            }
            if (cnt > best_cover) {
                best_cover = cnt;
                best_idx = (int)i;
            }
        }

        if (best_idx < 0 || best_cover == 0) break;

        // Apply best candidate
        for (int cv : candidates[best_idx].chars) {
            for (int j = 0; j < n; j++) {
                if (!covered[j] && chars[j].value == cv &&
                    chars[j].target == candidates[best_idx].target &&
                    chars[j].markers == candidates[best_idx].markers) {
                    covered[j] = true;
                }
            }
        }
        rules++;
    }

    return rules;
}

// ============================================================================
// Totalizer Encoding (same as nfa_preminimize_sat_optimal.cpp)
// ============================================================================

#ifdef USE_CADICAL

struct TotNode {
    bool is_leaf;
    int left, right;
    int subtree_size;
    std::vector<int> bits;  // bits[k] = literal for "count >= k+1"
};

static std::vector<TotNode> build_totalizer_tree(
    int n, std::function<int(int)> cand_var, int& next_var
) {
    int total_nodes = 2 * n - 1;
    std::vector<TotNode> tree(total_nodes);

    for (int i = 0; i < n; i++) {
        tree[i].is_leaf = true;
        tree[i].left = -1;
        tree[i].right = -1;
        tree[i].subtree_size = 1;
        tree[i].bits.resize(2, 0);
        tree[i].bits[1] = cand_var(i);
    }

    std::vector<int> current_level(2 * n);
    int current_count = 0;
    for (int i = 0; i < n; i++) current_level[current_count++] = i;
    int next_node = n;

    while (current_count > 1) {
        int next_count = 0;
        std::vector<int> next_level(2 * n);

        for (int i = 0; i + 1 < current_count; i += 2) {
            int li = current_level[i], ri = current_level[i + 1];
            int u = next_node++;
            tree[u].is_leaf = false;
            tree[u].left = li;
            tree[u].right = ri;
            tree[u].subtree_size = tree[li].subtree_size + tree[ri].subtree_size;
            tree[u].bits.resize(tree[u].subtree_size, 0);
            for (int k = 1; k < tree[u].subtree_size; k++)
                tree[u].bits[k] = next_var++;
            next_level[next_count++] = u;
        }

        if (current_count % 2 == 1)
            next_level[next_count++] = current_level[current_count - 1];

        for (int i = 0; i < next_count; i++)
            current_level[i] = next_level[i];
        current_count = next_count;
    }

    return tree;
}

static void add_totalizer_clauses(CaDiCaL::Solver& solver, const std::vector<TotNode>& tree, int u) {
    const TotNode& node = tree[u];
    if (node.is_leaf) return;

    const TotNode& L = tree[node.left];
    const TotNode& R = tree[node.right];

    // Merging clauses
    for (int k = 1; k < node.subtree_size; k++) {
        int a_lo = std::max(0, k - (R.subtree_size - 1));
        int a_hi = std::min(k, L.subtree_size - 1);
        for (int a = a_lo; a <= a_hi; a++) {
            int b = k - a;
            if (a > 0) solver.add(-L.bits[a]);
            if (b > 0) solver.add(-R.bits[b]);
            solver.add(node.bits[k]);
            solver.add(0);
        }
    }

    // Decomposition clauses
    for (int k = 1; k < node.subtree_size; k++) {
        if (k < L.subtree_size) {
            solver.add(-node.bits[k]);
            solver.add(L.bits[k]);
            solver.add(0);
        }
        if (k < R.subtree_size) {
            solver.add(-node.bits[k]);
            solver.add(R.bits[k]);
            solver.add(0);
        }
    }
}

// ============================================================================
// Bounded SAT Compression Solver
// ============================================================================

/**
 * SAT-based minimum set cover for DFA rule compression.
 *
 * Encoding:
 *   - Variables: one per candidate rule (select or not)
 *   - Coverage: for each character, at least one selected rule must cover it
 *   - Masking: if a range candidate has mask_chars, those chars must be
 *     covered by OTHER selected candidates (first-match masking)
 *   - Cardinality: totalizer bounds total selected rules
 *
 * Iterative tightening: start with greedy lower bound, increase until UNSAT.
 *
 * @param chars       All characters with transitions for this state
 * @param candidates  Pre-generated rule candidates
 * @param greedy_bound  Greedy's rule count (lower bound)
 * @return            Optimal number of rules, or greedy_bound if SAT unavailable/failed
 */
static int sat_compress_state(
    const std::vector<CharInfo>& chars,
    const std::vector<RuleCandidate>& candidates,
    int greedy_bound
) {
    int n = (int)chars.size();
    int m = (int)candidates.size();

    if (n == 0) return 0;
    if (m == 0) return n;

    VERBOSE_PRINT("  SAT: %d chars, %d candidates, greedy bound = %d\n", n, m, greedy_bound);

    if (m <= 1 || n <= 1) {
        VERBOSE_PRINT("  SAT: too few candidates/chars, using greedy\n");
        return greedy_bound;
    }

    // Build mapping: char index -> set of candidate indices that cover it
    std::vector<std::set<int>> char_covered_by(n);
    for (int ci = 0; ci < m; ci++) {
        for (int cv : candidates[ci].chars) {
            for (int j = 0; j < n; j++) {
                if (chars[j].value == cv &&
                    chars[j].target == candidates[ci].target &&
                    chars[j].markers == candidates[ci].markers) {
                    char_covered_by[j].insert(ci);
                }
            }
        }
    }

    // Build masking dependencies: for each candidate with mask_chars,
    // the mask_chars must be covered by OTHER selected candidates
    std::vector<std::set<int>> mask_requires(m);
    for (int ci = 0; ci < m; ci++) {
        if (candidates[ci].mask_chars.empty()) continue;
        for (int mc : candidates[ci].mask_chars) {
            for (int j = 0; j < n; j++) {
                if (chars[j].value == mc) {
                    // mc must be covered by some candidate other than ci
                    for (int cj : char_covered_by[j]) {
                        if (cj != ci) {
                            mask_requires[ci].insert(cj);
                        }
                    }
                }
            }
        }
    }

    // Build solver
    CaDiCaL::Solver solver;
    solver.set("quiet", 1);

    // cand_var(i) = variable for candidate i (1-indexed)
    auto cand_var = [](int i) -> int { return i + 1; };
    int next_var = m + 1;

    // Build totalizer (computes all aux variable IDs)
    std::vector<TotNode> tree = build_totalizer_tree(m, cand_var, next_var);

    // Pre-declare all variables before adding clauses
    // CaDiCaL in factorcheck mode requires explicit variable declaration
    solver.resize(next_var);

    // Add totalizer clauses
    for (int u = m; u < (int)tree.size(); u++) {
        add_totalizer_clauses(solver, tree, u);
    }
    int root = (int)tree.size() - 1;

    // Coverage clauses: for each character, at least one covering candidate
    for (int j = 0; j < n; j++) {
        if (char_covered_by[j].empty()) continue;

        // OR of all candidates covering this character
        for (int ci : char_covered_by[j]) {
            solver.add(cand_var(ci));
        }
        solver.add(0);
    }

    // Masking clauses: if a range candidate with mask_chars is selected,
    // at least one "masking" candidate for each masked char must also be selected
    for (int ci = 0; ci < m; ci++) {
        if (mask_requires[ci].empty()) continue;

        // cand_var(ci) -> OR(mask_requires[ci])
        // Equivalent to: -cand_var(ci) OR m1 OR m2 OR ...
        for (int cj : mask_requires[ci]) {
            solver.add(-cand_var(ci));
            solver.add(cand_var(cj));
            solver.add(0);
        }
    }

    // Solve iteratively: find minimum rule count
    int best_rules = greedy_bound;

    for (int k = greedy_bound; k <= n; k++) {
        solver.assume(tree[root].bits[k]);

        int res = solver.solve();
        if (res != 10) {
            VERBOSE_PRINT("  UNSAT at k=%d (optimal = %d rules)\n", k + 1, best_rules);
            break;
        }

        // Count selected candidates
        int count = 0;
        for (int i = 0; i < m; i++) {
            if (solver.val(cand_var(i)) > 0) count++;
        }
        best_rules = count;
        VERBOSE_PRINT("  SAT at k=%d (found %d rules)\n", k + 1, best_rules);
    }

    return best_rules;
}

#endif // USE_CADICAL

// ============================================================================
// Main Entry Points
// ============================================================================

/**
 * SAT-based optimal rule merging for a single state.
 * Falls back to greedy if CaDiCaL unavailable.
 *
 * @param state DFA state to optimize
 * @param max_group_size Maximum characters per group (typically 3)
 * @return Number of rules saved by optimal grouping
 */
extern "C" int sat_merge_rules_for_state(build_dfa_state_t* state, int max_group_size) {
    // Collect all characters with transitions
    std::vector<CharInfo> chars;
    for (int c = 0; c < 256; c++) {
        if (state->transitions[c] >= 0) {
            CharInfo ci;
            ci.value = c;
            ci.target = state->transitions[c];
            ci.markers = state->marker_offsets[c];
            chars.push_back(ci);
        }
    }

    int n = (int)chars.size();
    if (n == 0) return 0;
    if (n <= max_group_size) return n - 1;

    // Generate all rule candidates
    std::vector<RuleCandidate> candidates = generate_candidates(chars);
    int m = (int)candidates.size();
    fprintf(stderr, "SAT: state with %d chars, %d candidates\n", n, m);

    // Greedy lower bound
    int greedy_rules = greedy_min_rules(chars, candidates);
    fprintf(stderr, "SAT: greedy bound = %d\n", greedy_rules);

    // SAT optimization (if available)
    int best_rules = greedy_rules;

#ifdef USE_CADICAL
    if ((int)candidates.size() > greedy_rules + 1) {
        int sat_rules = sat_compress_state(chars, candidates, greedy_rules);
        best_rules = std::min(greedy_rules, sat_rules);
    }
#endif

    return n - best_rules;
}

/**
 * SAT-based compression for all states in a DFA.
 */
extern "C" int sat_compress_dfa(build_dfa_state_t** dfa, int state_count, int max_group_size) {
    int total_saved = 0;
    for (int s = 0; s < state_count; s++) {
        total_saved += sat_merge_rules_for_state(dfa[s], max_group_size);
    }
    return total_saved;
}
