/**
 * DFA Minimization Implementation - Scalable SAT Encoding with CEGAR
 *
 * This implementation addresses the O(n³) transitivity explosion by using
 * Counter-Example Guided Abstraction Refinement (CEGAR). It also implements
 * pattern-aware "don't-care" marker optimization for Mealy Machines.
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
#include <iostream>
#include <chrono>
#include <numeric>
#include "cadical.hpp"

extern "C" {
#include "../include/dfa_types.h"
#include "dfa_minimize.h"
}

/**
 * Sparse Pattern Set using sorted vectors
 */
class PatternSet {
public:
    std::vector<uint16_t> ids;

    void add(uint16_t id) {
        if (id == 0) return; 
        auto it = std::lower_bound(ids.begin(), ids.end(), id);
        if (it == ids.end() || *it != id) {
            ids.insert(it, id);
        }
    }

    bool contains(uint16_t id) const {
        return std::binary_search(ids.begin(), ids.end(), id);
    }

    bool operator==(const PatternSet& other) const {
        return ids == other.ids;
    }

    bool operator!=(const PatternSet& other) const {
        return !(*this == other);
    }

    PatternSet intersect(const PatternSet& other) const {
        PatternSet result;
        std::set_intersection(ids.begin(), ids.end(),
                              other.ids.begin(), other.ids.end(),
                              std::back_inserter(result.ids));
        return result;
    }

    PatternSet unite(const PatternSet& other) const {
        PatternSet result;
        std::set_union(ids.begin(), ids.end(),
                        other.ids.begin(), other.ids.end(),
                        std::back_inserter(result.ids));
        return result;
    }
};

/**
 * Alphabet Compressor: Groups symbols into classes
 */
struct SymbolClassMap {
    int char_to_class[MAX_SYMBOLS];
    int class_to_char[MAX_SYMBOLS];
    int num_classes;

    void compute(const build_dfa_state_t* dfa, int state_count) {
        num_classes = 0;
        std::map<std::vector<std::pair<int, uint32_t>>, int> signature_to_class;

        for (int c = 0; c < MAX_SYMBOLS; c++) {
            std::vector<std::pair<int, uint32_t>> signature;
            for (int s = 0; s < state_count; s++) {
                signature.push_back({dfa[s].transitions[c], dfa[s].marker_offsets[c]});
            }

            if (signature_to_class.find(signature) == signature_to_class.end()) {
                signature_to_class[signature] = num_classes;
                class_to_char[num_classes] = c;
                num_classes++;
            }
            char_to_class[c] = signature_to_class[signature];
        }
        fprintf(stderr, "[SAT] Alphabet compressed: %d -> %d symbol classes\n", MAX_SYMBOLS, num_classes);
    }
};

class ScalableSATMinimizer {
private:
    CaDiCaL::Solver* solver;
    int n_states;
    const build_dfa_state_t* original_dfa;
    SymbolClassMap smap;
    std::vector<PatternSet> reachability;
    MarkerList* marker_lists;
    int marker_list_count;
    int total_iterations;

    int eq_var(int i, int j) {
        if (i == j) return 0;
        if (i > j) std::swap(i, j);
        long long idx = (long long)i * (2 * n_states - i - 1) / 2 + (j - i - 1);
        return (int)idx + 1;
    }

    void compute_reachability() {
        reachability.assign(n_states, PatternSet());
        for (int s = 0; s < n_states; s++) {
            if (original_dfa[s].flags & DFA_STATE_ACCEPTING) {
                reachability[s].add(original_dfa[s].accepting_pattern_id + 1);
            }
        }

        bool changed = true;
        while (changed) {
            changed = false;
            for (int s = 0; s < n_states; s++) {
                size_t old_size = reachability[s].ids.size();
                for (int c = 0; c < MAX_SYMBOLS; c++) {
                    int t = original_dfa[s].transitions[c];
                    if (t >= 0 && t < n_states) {
                        for (uint16_t id : reachability[t].ids) reachability[s].add(id);
                    }
                }
                if (original_dfa[s].eos_target != 0 && (int)original_dfa[s].eos_target < n_states) {
                    for (uint16_t id : reachability[original_dfa[s].eos_target].ids) reachability[s].add(id);
                }
                if (reachability[s].ids.size() > old_size) changed = true;
            }
        }
    }

    bool are_markers_equivalent(int s1, int s2, int c) {
        uint32_t m1_idx = original_dfa[s1].marker_offsets[c];
        uint32_t m2_idx = original_dfa[s2].marker_offsets[c];
        if (m1_idx == m2_idx) return true;

        int t1 = original_dfa[s1].transitions[c];
        int t2 = original_dfa[s2].transitions[c];
        
        PatternSet live;
        if (t1 >= 0 && t1 < n_states) live = reachability[t1];
        if (t2 >= 0 && t2 < n_states) live = live.unite(reachability[t2]);

        if (live.ids.empty()) return true;

        auto get_filtered = [&](uint32_t idx) {
            std::vector<uint32_t> filtered;
            if (idx > 0 && idx <= (uint32_t)marker_list_count) {
                MarkerList* ml = &marker_lists[idx - 1];
                for (int i = 0; i < ml->count; i++) {
                    uint32_t m = ml->markers[i];
                    uint16_t pid = MARKER_GET_PATTERN_ID(m);
                    if (live.contains(pid + 1)) filtered.push_back(m);
                }
            }
            return filtered;
        };

        return get_filtered(m1_idx) == get_filtered(m2_idx);
    }

    bool are_eos_markers_equivalent(int s1, int s2) {
        uint32_t m1_idx = original_dfa[s1].eos_marker_offset;
        uint32_t m2_idx = original_dfa[s2].eos_marker_offset;
        if (m1_idx == m2_idx) return true;

        int t1 = original_dfa[s1].eos_target;
        int t2 = original_dfa[s2].eos_target;

        PatternSet live;
        if (t1 > 0 && t1 < n_states) live = reachability[t1];
        if (t2 > 0 && t2 < n_states) live = live.unite(reachability[t2]);

        if (live.ids.empty()) return true;

        auto get_filtered = [&](uint32_t idx) {
            std::vector<uint32_t> filtered;
            if (idx > 0 && idx <= (uint32_t)marker_list_count) {
                MarkerList* ml = &marker_lists[idx - 1];
                for (int i = 0; i < ml->count; i++) {
                    uint32_t m = ml->markers[i];
                    uint16_t pid = MARKER_GET_PATTERN_ID(m);
                    if (live.contains(pid + 1)) filtered.push_back(m);
                }
            }
            return filtered;
        };

        return get_filtered(m1_idx) == get_filtered(m2_idx);
    }

public:
    ScalableSATMinimizer(const build_dfa_state_t* dfa, int states) 
        : n_states(states), original_dfa(dfa), total_iterations(0) {
        solver = new CaDiCaL::Solver();
        
        long long num_vars = (long long)n_states * (n_states - 1) / 2;
        if (num_vars > 0) {
            solver->resize((int)num_vars);
        }

        marker_lists = dfa_get_marker_lists(&marker_list_count);
        smap.compute(dfa, states);
        compute_reachability();
    }

    ~ScalableSATMinimizer() { delete solver; }

    int getTotalIterations() const { return total_iterations; }

    int run() {
        fprintf(stderr, "[SAT] Initializing base constraints...\n");
        int unit_clauses = 0;
        for (int i = 0; i < n_states; i++) {
            for (int j = i + 1; j < n_states; j++) {
                bool incompatible = false;
                if ((original_dfa[i].flags & DFA_STATE_ACCEPTING) != (original_dfa[j].flags & DFA_STATE_ACCEPTING)) incompatible = true;
                if (!incompatible && (original_dfa[i].flags & 0xFF00) != (original_dfa[j].flags & 0xFF00)) incompatible = true;
                if (!incompatible && (original_dfa[i].flags & DFA_STATE_ACCEPTING) && 
                    original_dfa[i].accepting_pattern_id != original_dfa[j].accepting_pattern_id) incompatible = true;
                if (!incompatible && reachability[i] != reachability[j]) incompatible = true;

                if (!incompatible) {
                    for (int sc = 0; sc < smap.num_classes; sc++) {
                        if (!are_markers_equivalent(i, j, smap.class_to_char[sc])) { incompatible = true; break; }
                    }
                }
                if (!incompatible && !are_eos_markers_equivalent(i, j)) incompatible = true;

                if (incompatible) { solver->add(-eq_var(i, j)); solver->add(0); unit_clauses++; }
            }
        }
        fprintf(stderr, "[SAT] Added %d unit separation clauses\n", unit_clauses);

        int iteration = 0;
        while (true) {
            iteration++;
            auto iter_start = std::chrono::steady_clock::now();
            fprintf(stderr, "[SAT] Iteration %d: Solving... ", iteration);
            int res = solver->solve();
            if (res == 20) { fprintf(stderr, "UNSAT\n"); break; }
            
            std::vector<int> parent(n_states); std::iota(parent.begin(), parent.end(), 0);
            auto find = [&](auto self, int x) -> int { return (parent[x] == x) ? x : (parent[x] = self(self, parent[x])); };
            int current_merges = 0;
            for (int i = 0; i < n_states; i++) {
                for (int j = i + 1; j < n_states; j++) {
                    if (solver->val(eq_var(i, j)) > 0) {
                        int ri = find(find, i), rj = find(find, j);
                        if (ri != rj) { parent[rj] = ri; current_merges++; }
                    }
                }
            }
            fprintf(stderr, "SAT (%d states)\n", n_states - current_merges);

            std::vector<std::vector<int>> violations;
            for (int i = 0; i < n_states; i++) {
                for (int j = i + 1; j < n_states; j++) {
                    if (solver->val(eq_var(i, j)) > 0) {
                        for (int sc = 0; sc < smap.num_classes; sc++) {
                            int c = smap.class_to_char[sc];
                            int ti = original_dfa[i].transitions[c], tj = original_dfa[j].transitions[c];
                            if (ti != tj) {
                                if (ti < 0 || tj < 0) violations.push_back({-eq_var(i, j)});
                                else {
                                    int v = eq_var(ti, tj);
                                    if (solver->val(v) < 0) violations.push_back({-eq_var(i, j), v});
                                }
                            }
                        }
                        int ei = original_dfa[i].eos_target, ej = original_dfa[j].eos_target;
                        if (ei != ej) {
                            if (ei == 0 || ej == 0) violations.push_back({-eq_var(i, j)});
                            else {
                                int v = eq_var(ei, ej);
                                if (solver->val(v) < 0) violations.push_back({-eq_var(i, j), v});
                            }
                        }
                    }
                }
                if (violations.size() > 50000) break;
            }

            if (violations.empty()) {
                for (int i = 0; i < n_states; i++) {
                    for (int j = i + 1; j < n_states; j++) {
                        if (solver->val(eq_var(i, j)) > 0) {
                            for (int k = j + 1; k < n_states; k++) {
                                if (solver->val(eq_var(j, k)) > 0) {
                                    int v = eq_var(i, k);
                                    if (solver->val(v) < 0) violations.push_back({-eq_var(i, j), -eq_var(j, k), v});
                                }
                            }
                        }
                    }
                    if (violations.size() > 50000) break;
                }
            }

            if (violations.empty()) { fprintf(stderr, "[SAT] No violations found. Success!\n"); break; }
            for (const auto& v : violations) { for (int lit : v) solver->add(lit); solver->add(0); }
            auto iter_end = std::chrono::steady_clock::now();
            auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(iter_end - iter_start).count();
            fprintf(stderr, "[SAT] Added %zu clauses in %ldms\n", violations.size(), dur);
            if (iteration > 500) break;
        }
        total_iterations = iteration;
        return extract_result();
    }

    int extract_result() {
        std::vector<int> partition(n_states);
        std::vector<int> parent(n_states); std::iota(parent.begin(), parent.end(), 0);
        auto find = [&](auto self, int x) -> int { return (parent[x] == x) ? x : (parent[x] = self(self, parent[x])); };
        for (int i = 0; i < n_states; i++) {
            for (int j = i + 1; j < n_states; j++) {
                if (solver->val(eq_var(i, j)) > 0) {
                    int ri = find(find, i), rj = find(find, j);
                    if (ri != rj) parent[rj] = ri;
                }
            }
        }
        std::vector<int> rep_to_new(n_states, -1);
        int next_id = 0;
        for (int i = 0; i < n_states; i++) {
            int root = find(find, i);
            if (rep_to_new[root] == -1) rep_to_new[root] = next_id++;
            partition[i] = rep_to_new[root];
        }

        std::vector<build_dfa_state_t> new_dfa(next_id);
        std::vector<bool> initialized(next_id, false);
        for (int i = 0; i < n_states; i++) {
            int p = partition[i];
            if (!initialized[p]) {
                new_dfa[p] = original_dfa[i];
                for (int c = 0; c < MAX_SYMBOLS; c++) {
                    int t = original_dfa[i].transitions[c];
                    new_dfa[p].transitions[c] = (t >= 0 && t < n_states) ? partition[t] : -1;
                }
                if (original_dfa[i].eos_target != 0 && (int)original_dfa[i].eos_target < n_states) {
                    new_dfa[p].eos_target = partition[original_dfa[i].eos_target];
                }
                initialized[p] = true;
            }
        }
        memcpy((void*)original_dfa, new_dfa.data(), next_id * sizeof(build_dfa_state_t));
        return next_id;
    }
};

extern "C" {
int dfa_minimize_sat(build_dfa_state_t** dfa, int state_count) {
    if (state_count <= 1) return state_count;

    // Trap State Synthesis
    std::vector<bool> reaches_accept(state_count, false);
    for (int s = 0; s < state_count; s++) {
        if (dfa[s]->flags & DFA_STATE_ACCEPTING) reaches_accept[s] = true;
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (int s = 0; s < state_count; s++) {
            if (reaches_accept[s]) continue;
            for (int c = 0; c < MAX_SYMBOLS; c++) {
                int t = dfa[s]->transitions[c];
                if (t >= 0 && t < state_count && reaches_accept[t]) {
                    reaches_accept[s] = true; changed = true; break;
                }
            }
            if (!reaches_accept[s] && dfa[s]->eos_target != 0 && (int)dfa[s]->eos_target < state_count && reaches_accept[dfa[s]->eos_target]) {
                reaches_accept[s] = true; changed = true;
            }
        }
    }

    int trap_state = -1;
    for (int s = 0; s < state_count; s++) {
        if (!reaches_accept[s]) {
            if (trap_state == -1) {
                trap_state = s;
                for (int c = 0; c < MAX_SYMBOLS; c++) dfa[s]->transitions[c] = s;
                dfa[s]->eos_target = 0;
                dfa[s]->flags &= ~DFA_STATE_ACCEPTING;
            } else {
                for (int c = 0; c < MAX_SYMBOLS; c++) dfa[s]->transitions[c] = trap_state;
                dfa[s]->eos_target = 0;
            }
        }
    }

    int hop_count = dfa_minimize_hopcroft(dfa, state_count);
    fprintf(stderr, "[SAT] Hopcroft reduced to %d states\n", hop_count);

    if (hop_count <= 1) return hop_count;

    ScalableSATMinimizer minimizer(*dfa, hop_count);
    int result = minimizer.run();
    dfa_minimize_set_iterations(minimizer.getTotalIterations());
    return result;
}
}
