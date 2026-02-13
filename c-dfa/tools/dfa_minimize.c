/**
 * DFA Minimization Implementation
 * 
 * Implements DFA state minimization using:
 * 1. Dead State Pruning (Reverse Reachability)
 * 2. Hopcroft's Algorithm (Worklist-based Partition Refinement)
 * 3. Moore's Algorithm (Fallback/Verification option)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include "../include/dfa_types.h"
#include "dfa_minimize.h"

// Constants matching nfa.h
#include "../include/nfa.h"
#define TOTAL_SYMBOLS (MAX_SYMBOLS * 2 + 1)

// FNV-1a Constants for hashing
#define FNV_PRIME 16777619
#define FNV_OFFSET_BASIS 2166136261u

// Debug and Configuration
static bool minimize_verbose = true;  // Enable for debugging
static dfa_min_algo_t current_algo = DFA_MIN_HOPCROFT;
static dfa_minimize_stats_t last_stats = {0};

#define VERBOSE_PRINT(fmt, ...) do { \
    if (minimize_verbose) fprintf(stderr, "[MINIMIZE] " fmt, ##__VA_ARGS__); \
} while(0)

/**
 * Check allocation result and abort on failure
 */
static void* alloc_or_abort(void* ptr, const char* msg) {
    if (ptr == NULL) {
        fprintf(stderr, "FATAL: %s - %s\n", msg, strerror(errno));
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// ============================================================================
// Data Structures for Minimization
// ============================================================================

// Predecessor Graph Structure (Inverse Transitions)
typedef struct {
    int* sources;       // Source state of transition
    int* char_codes;    // Virtual symbol ID (0-512)
    int* offsets;       // Start index in arrays for each target state
    int* counts;        // Number of incoming edges for each target state
    int total_edges;
} inverse_graph_t;

// Partition structure
typedef struct {
    int states[MAX_STATES];
    int count;
} partition_t;

// Minimizer State (Main workspace)
typedef struct {
    int partition_map[MAX_STATES];  // state -> partition_id
    partition_t partitions[MAX_STATES];
    int partition_count;
} minimizer_state_t;

// Helper for predecessor sorting
typedef struct {
    int p_id;
    int state_id;
} sort_entry_t;

static int compare_sort_entries(const void* a, const void* b) {
    const sort_entry_t* sa = (const sort_entry_t*)a;
    const sort_entry_t* sb = (const sort_entry_t*)b;
    if (sa->p_id != sb->p_id) return sa->p_id - sb->p_id;
    return sa->state_id - sb->state_id;
}

// ============================================================================
// Utility: Inverse Graph
// ============================================================================

static void free_inverse_graph(inverse_graph_t* g) {
    if (g) {
        free(g->sources);
        free(g->char_codes);
        free(g->offsets);
        free(g->counts);
    }
}

static bool build_inverse_graph(const build_dfa_state_t* dfa, int state_count, inverse_graph_t* g) {
    memset(g, 0, sizeof(inverse_graph_t));
    g->counts = calloc(state_count, sizeof(int));
    g->offsets = calloc(state_count, sizeof(int));
    if (!g->counts || !g->offsets) return false;

    // Count incoming edges
    for (int s = 0; s < state_count; s++) {
        for (int c = 0; c < 256; c++) {
            int target = dfa[s].transitions[c];
            if (target >= 0 && target < state_count) {
                g->counts[target]++;
                g->total_edges++;
            }
        }
        if (dfa[s].eos_target != 0 && dfa[s].eos_target < (uint32_t)state_count) {
            g->counts[dfa[s].eos_target]++;
            g->total_edges++;
        }
    }

    g->sources = malloc((g->total_edges + 1) * sizeof(int));
    g->char_codes = malloc((g->total_edges + 1) * sizeof(int));
    if (!g->sources || !g->char_codes) { free_inverse_graph(g); return false; }

    int current_offset = 0;
    for (int s = 0; s < state_count; s++) {
        g->offsets[s] = current_offset;
        current_offset += g->counts[s];
        g->counts[s] = 0; // Reset to use as counter
    }

    for (int s = 0; s < state_count; s++) {
        for (int c = 0; c < 256; c++) {
            int target = dfa[s].transitions[c];
            if (target >= 0 && target < state_count) {
                int idx = g->offsets[target] + g->counts[target]++;
                g->sources[idx] = s;
                // Encode symbol: 1-256 for Literal, 257-512 for ANY
                g->char_codes[idx] = dfa[s].transitions_from_any[c] ? (c + 257) : (c + 1);
            }
        }
        if (dfa[s].eos_target != 0 && dfa[s].eos_target < (uint32_t)state_count) {
            int target = dfa[s].eos_target;
            int idx = g->offsets[target] + g->counts[target]++;
            g->sources[idx] = s;
            g->char_codes[idx] = 0; // EOS symbol
        }
    }
    return true;
}

// ============================================================================
// Phase 1: Dead State Pruning (Two-Pass: Forward + Backward)
// ============================================================================

static int prune_dead_states(build_dfa_state_t* dfa, int state_count) {
    // Phase 1: Forward reachability from start state (state 0)
    bool* forward_reachable = calloc(state_count, sizeof(bool));
    int* queue = malloc(state_count * sizeof(int));
    if (!forward_reachable || !queue) {
        free(forward_reachable); free(queue); return state_count;
    }

    int head = 0, tail = 0;
    forward_reachable[0] = true;
    queue[tail++] = 0;

    while (head < tail) {
        int s = queue[head++];
        for (int c = 0; c < 256; c++) {
            int t = dfa[s].transitions[c];
            if (t != -1 && !forward_reachable[t]) {
                forward_reachable[t] = true;
                queue[tail++] = t;
            }
        }
    }

    // Phase 2: Backward reachability from accepting states
    bool* backward_reachable = calloc(state_count, sizeof(bool));
    inverse_graph_t inv;

    if (!backward_reachable || !build_inverse_graph(dfa, state_count, &inv)) {
        free(forward_reachable); free(backward_reachable); free(queue); return state_count;
    }

    head = 0; tail = 0;
    for (int s = 0; s < state_count; s++) {
        if ((dfa[s].flags & 0xFF00) != 0) {  // Accepting states
            backward_reachable[s] = true;
            queue[tail++] = s;
        }
    }

    while (head < tail) {
        int target = queue[head++];
        int start = inv.offsets[target], count = inv.counts[target];
        for (int i = 0; i < count; i++) {
            int src = inv.sources[start + i];
            if (!backward_reachable[src]) {
                backward_reachable[src] = true;
                queue[tail++] = src;
            }
        }
    }
    free_inverse_graph(&inv);
    free(queue);

    // Phase 3: Keep states that are BOTH forward and backward reachable
    bool* useful = malloc(state_count * sizeof(bool));
    int useful_count = 0;
    for (int s = 0; s < state_count; s++) {
        if (forward_reachable[s] && backward_reachable[s]) {
            useful[s] = true;
            useful_count++;
        }
    }
    useful[0] = true;  // Always keep start state

    // Phase 4: Compact the DFA
    int* map = malloc(state_count * sizeof(int));
    int new_count = 0;
    for (int s = 0; s < state_count; s++) {
        if (useful[s]) {
            map[s] = new_count;
            if (s != new_count) dfa[new_count] = dfa[s];
            new_count++;
        } else map[s] = -1;
    }

    // Phase 5: Update transitions using the compact map
    for (int s = 0; s < new_count; s++) {
        for (int c = 0; c < 256; c++) {
            int t = dfa[s].transitions[c];
            if (t != -1) dfa[s].transitions[c] = (t < state_count) ? map[t] : -1;
        }
        if (dfa[s].eos_target != 0 && dfa[s].eos_target < (uint32_t)state_count) {
            dfa[s].eos_target = (uint32_t)map[dfa[s].eos_target];
        }
    }

    VERBOSE_PRINT("Pruned %d dead states (forward=%d, backward=%d, useful=%d)\n",
                  state_count - new_count, useful_count, useful_count, new_count);
    free(forward_reachable); free(backward_reachable); free(useful); free(map);
    return new_count;
}

// ============================================================================
// Shared: Partition Equivalence logic - NOTE: are_properties_equivalent was
// removed as it was dead code (never called from anywhere)
// ============================================================================

static bool are_transitions_equivalent(const build_dfa_state_t* s1, const build_dfa_state_t* s2, const int* partition_map) {
    for (int c = 0; c < 256; c++) {
        int t1 = s1->transitions[c], t2 = s2->transitions[c];
        if (t1 == -1 && t2 == -1) continue;
        if (t1 == -1 || t2 == -1) return false;
        if (t1 >= 0 && t1 < MAX_STATES && t2 >= 0 && t2 < MAX_STATES) {
            if (partition_map[t1] != partition_map[t2]) return false;
        } else {
            if (t1 != t2) return false;
        }
        if (s1->transitions_from_any[c] != s2->transitions_from_any[c]) return false;
        if (s1->marker_offsets[c] != s2->marker_offsets[c]) return false;
    }
    if (s1->eos_target != 0 && s2->eos_target != 0) {
        if (s1->eos_target < MAX_STATES && s2->eos_target < MAX_STATES) {
            if (partition_map[s1->eos_target] != partition_map[s2->eos_target]) return false;
        } else {
            if (s1->eos_target != s2->eos_target) return false;
        }
    }
    return true;
}

static uint16_t compute_hash(const build_dfa_state_t* state, const int* partition_map) {
    uint32_t hash = FNV_OFFSET_BASIS;
    hash ^= (state->flags & 0xFFFF); hash *= FNV_PRIME;
    hash ^= state->eos_marker_offset; hash *= FNV_PRIME;
    for (int c = 0; c < 256; c += 8) {
        int t = state->transitions[c];
        int target_p = -1;
        if (t != -1 && t < MAX_STATES) {
            target_p = partition_map[t];
        }
        hash ^= c; hash *= FNV_PRIME;
        hash ^= (uint8_t)target_p; hash *= FNV_PRIME;
        hash ^= (state->marker_offsets[c] & 0xFF); hash *= FNV_PRIME;
    }
    for (int c = 0; c < 256; c += 32) {
        hash ^= (state->marker_offsets[c] >> 8); hash *= FNV_PRIME;
    }
    if (state->eos_target != 0 && state->eos_target < MAX_STATES) {
        int eos_p = partition_map[state->eos_target];
        hash ^= (uint8_t)eos_p; hash *= FNV_PRIME;
    }
    return (uint16_t)((hash >> 16) ^ (hash & 0xFFFF));
}

static void initialize_partitions(minimizer_state_t* ms, const build_dfa_state_t* dfa, int state_count) {
    for (int i = 0; i < MAX_STATES; i++) ms->partition_map[i] = -1;
    int group_count = 0;
    for (int s = 0; s < state_count; s++) {
        bool found = false;
        for (int g = 0; g < group_count; g++) {
            int rep = ms->partitions[g].states[0];
            // Check if state s has identical transitions to partition representative
            // During initialization, just compare actual transition targets directly
            bool equivalent = true;
            for (int c = 0; c < 256; c++) {
                int t1 = dfa[s].transitions[c];
                int t2 = dfa[rep].transitions[c];
                if (t1 != t2) { equivalent = false; break; }
            }
            // Also check eos_target
            if (equivalent && dfa[s].eos_target != dfa[rep].eos_target) equivalent = false;
            if (equivalent && dfa[s].flags == dfa[rep].flags &&
                dfa[s].eos_marker_offset == dfa[rep].eos_marker_offset) {
                ms->partitions[g].states[ms->partitions[g].count++] = s;
                ms->partition_map[s] = g;
                found = true; break;
            }
        }
        if (!found) {
            ms->partitions[group_count].states[0] = s;
            ms->partitions[group_count].count = 1;
            ms->partition_map[s] = group_count;
            group_count++;
        }
    }
    ms->partition_count = group_count;
    fprintf(stderr, "[MINIMIZE DEBUG] initialize_partitions: created %d initial partitions\n", group_count);
}

static int build_minimized_dfa(build_dfa_state_t* dfa, const minimizer_state_t* ms, int old_state_count) {
    build_dfa_state_t* new_dfa = malloc(ms->partition_count * sizeof(build_dfa_state_t));
    alloc_or_abort(new_dfa, "Alloc New DFA Buffer");
    int state_remap[MAX_STATES];
    for (int i = 0; i < MAX_STATES; i++) state_remap[i] = -1;  // Initialize to -1
    int new_count = 0;

    fprintf(stderr, "[MINIMIZE DEBUG] Old state count: %d, Partitions: %d\n", old_state_count, ms->partition_count);

    for (int p = 0; p < ms->partition_count; p++) {
        if (ms->partitions[p].count == 0) continue;
        int rep = ms->partitions[p].states[0];
        fprintf(stderr, "[MINIMIZE DEBUG] Partition %d: rep=%d (orig transitions['a']=%d), states=[",
              p, rep, dfa[rep].transitions['a']);
        for (int i = 0; i < ms->partitions[p].count; i++) {
            fprintf(stderr, "%d ", ms->partitions[p].states[i]);
        }
        fprintf(stderr, "]\n");
        memcpy(&new_dfa[new_count], &dfa[rep], sizeof(build_dfa_state_t));
        for (int i = 0; i < ms->partitions[p].count; i++) state_remap[ms->partitions[p].states[i]] = new_count;
        new_count++;
    }

    fprintf(stderr, "[MINIMIZE DEBUG] After partition loop: new_count=%d\n", new_count);
    for (int s = 0; s < new_count; s++) {
        fprintf(stderr, "[MINIMIZE DEBUG] New state %d: trans['a']=%d (from rep=%d)\n",
              s, new_dfa[s].transitions['a'], ms->partitions[s].states[0]);
    }

    for (int s = 0; s < new_count; s++) {
        for (int c = 0; c < 256; c++) {
            int t = new_dfa[s].transitions[c];
            if (t != -1 && t < old_state_count && state_remap[t] != -1) {
                fprintf(stderr, "[MINIMIZE DEBUG] Remap: state %d, char '%c'(%d): %d -> %d\n",
                      s, c >= 32 ? c : '?', c, t, state_remap[t]);
                new_dfa[s].transitions[c] = state_remap[t];
            } else if (t != -1) {
                new_dfa[s].transitions[c] = -1;  // Transition to removed state
            }
        }
        if (new_dfa[s].eos_target != 0 && new_dfa[s].eos_target < (uint32_t)old_state_count && state_remap[new_dfa[s].eos_target] != -1) {
            new_dfa[s].eos_target = (uint32_t)state_remap[new_dfa[s].eos_target];
        } else if (new_dfa[s].eos_target != 0) {
            new_dfa[s].eos_target = 0;  // EOS transition to removed state
        }
        new_dfa[s].nfa_state_count = 0;
    }

    memcpy(dfa, new_dfa, new_count * sizeof(build_dfa_state_t));
    free(new_dfa); return new_count;
}

// ============================================================================
// Phase 2 (A): Hopcroft's Algorithm
// ============================================================================

int dfa_minimize_hopcroft(build_dfa_state_t* dfa, int state_count) {
    minimizer_state_t* ms = calloc(1, sizeof(minimizer_state_t));
    initialize_partitions(ms, dfa, state_count);
    inverse_graph_t inv;
    if (!build_inverse_graph(dfa, state_count, &inv)) { free(ms); return state_count; }
    if (!build_inverse_graph(dfa, state_count, &inv)) { free(ms); return state_count; }
    int head = 0, tail = 0;
    int worklist[MAX_STATES * 4];
    bool in_worklist[MAX_STATES] = {false};
    for (int p = 0; p < ms->partition_count; p++) { worklist[tail++] = p; in_worklist[p] = true; }
    int* char_preds = malloc((inv.total_edges + 1) * sizeof(int));
    int* char_pred_counts = calloc(TOTAL_SYMBOLS, sizeof(int));
    int* char_pred_offsets = calloc(TOTAL_SYMBOLS, sizeof(int));
    sort_entry_t* sort_buf = malloc(state_count * sizeof(sort_entry_t));
    while (head < tail) {
        int S = worklist[head++]; in_worklist[S] = false;
        memset(char_pred_counts, 0, TOTAL_SYMBOLS * sizeof(int));
        for (int i = 0; i < ms->partitions[S].count; i++) {
            int s = ms->partitions[S].states[i];
            int start = inv.offsets[s], count = inv.counts[s];
            for (int k = 0; k < count; k++) char_pred_counts[inv.char_codes[start + k]]++;
        }
        int off = 0;
        for (int c = 0; c < TOTAL_SYMBOLS; c++) { char_pred_offsets[c] = off; off += char_pred_counts[c]; char_pred_counts[c] = 0; }
        for (int i = 0; i < ms->partitions[S].count; i++) {
            int s = ms->partitions[S].states[i];
            int start = inv.offsets[s], count = inv.counts[s];
            for (int k = 0; k < count; k++) { int cid = inv.char_codes[start + k]; char_preds[char_pred_offsets[cid] + char_pred_counts[cid]++] = inv.sources[start + k]; }
        }
        for (int c_idx = 0; c_idx < TOTAL_SYMBOLS; c_idx++) {
            int count = char_pred_counts[c_idx]; if (count == 0) continue;
            for (int i = 0; i < count; i++) { sort_buf[i].state_id = char_preds[char_pred_offsets[c_idx] + i]; sort_buf[i].p_id = ms->partition_map[sort_buf[i].state_id]; }
            qsort(sort_buf, count, sizeof(sort_entry_t), compare_sort_entries);
            int gs = 0;
            while (gs < count) {
                int P = sort_buf[gs].p_id; int ge = gs;
                while (ge < count && sort_buf[ge].p_id == P) ge++;
                int group_size = ge - gs;
                if (group_size < ms->partitions[P].count) {
                    int NewP = ms->partition_count++; ms->partitions[NewP].count = 0;
                    for (int i = 0; i < group_size; i++) { int s = sort_buf[gs + i].state_id; ms->partition_map[s] = NewP; ms->partitions[NewP].states[ms->partitions[NewP].count++] = s; }
                    int kept = 0;
                    for (int i = 0; i < ms->partitions[P].count; i++) { int s = ms->partitions[P].states[i]; if (ms->partition_map[s] == P) ms->partitions[P].states[kept++] = s; }
                    ms->partitions[P].count = kept;
                    if (in_worklist[P]) { if (tail < MAX_STATES*4) { worklist[tail++] = NewP; in_worklist[NewP] = true; } }
                    else {
                        int smaller = (ms->partitions[NewP].count <= ms->partitions[P].count) ? NewP : P;
                        if (tail < MAX_STATES*4) { worklist[tail++] = smaller; in_worklist[smaller] = true; }
                    }
                }
                gs = ge;
            }
        }
    }

    int new_count = build_minimized_dfa(dfa, ms, state_count);
    free(ms); free(char_preds); free(char_pred_counts); free(char_pred_offsets); free(sort_buf); free_inverse_graph(&inv);
    return new_count;
}

// ============================================================================
// Phase 2 (B): Moore's Algorithm (Fallback)
// ============================================================================

int dfa_minimize_moore(build_dfa_state_t* dfa, int state_count) {
    minimizer_state_t* ms = calloc(1, sizeof(minimizer_state_t));
    initialize_partitions(ms, dfa, state_count);
    int iterations = 0;
    while (iterations < 100) {
        iterations++; bool changed = false;
        int old_count = ms->partition_count;
        for (int p = 0; p < old_count; p++) {
            if (ms->partitions[p].count <= 1) continue;
            int subgroup_count = 0; int state_to_sg[MAX_STATES]; int sg_reps[MAX_STATES];
            for (int i = 0; i < ms->partitions[p].count; i++) {
                int s = ms->partitions[p].states[i]; int sg = -1;
                uint16_t sig = compute_hash(&dfa[s], ms->partition_map);
                for (int u = 0; u < subgroup_count; u++) {
                    if (sig == compute_hash(&dfa[sg_reps[u]], ms->partition_map)) {
                        if (are_transitions_equivalent(&dfa[s], &dfa[sg_reps[u]], ms->partition_map)) { sg = u; break; }
                    }
                }
                if (sg == -1) { sg = subgroup_count++; sg_reps[sg] = s; }
                state_to_sg[i] = sg;
            }
            if (subgroup_count > 1) {
                changed = true; int new_p_ids[MAX_STATES]; new_p_ids[0] = p;
                for (int sg = 1; sg < subgroup_count; sg++) { new_p_ids[sg] = ms->partition_count++; ms->partitions[new_p_ids[sg]].count = 0; }
                int kept[MAX_STATES], kept_count = 0;
                for (int i = 0; i < ms->partitions[p].count; i++) {
                    int s = ms->partitions[p].states[i]; int dest = new_p_ids[state_to_sg[i]];
                    if (dest == p) kept[kept_count++] = s;
                    else { ms->partitions[dest].states[ms->partitions[dest].count++] = s; ms->partition_map[s] = dest; }
                }
                ms->partitions[p].count = kept_count; memcpy(ms->partitions[p].states, kept, kept_count * sizeof(int));
            }
        }
        if (!changed) break;
    }
    int new_count = build_minimized_dfa(dfa, ms, state_count);
    free(ms); return new_count;
}

// ============================================================================
// Public Entry Point
// ============================================================================

void dfa_minimize_set_algorithm(dfa_min_algo_t algo) { current_algo = algo; }
void dfa_minimize_set_moore(bool use_moore) { current_algo = use_moore ? DFA_MIN_MOORE : DFA_MIN_HOPCROFT; }
void dfa_minimize_set_verbose(bool verbose) { minimize_verbose = verbose; }
void dfa_minimize_get_stats(dfa_minimize_stats_t* stats) { if(stats) *stats = last_stats; }

static bool verify_minimized_dfa(const build_dfa_state_t* dfa, int state_count) {
    if (state_count <= 0) return false;
    for (int s = 0; s < state_count; s++) {
        for (int c = 0; c < 256; c++) {
            int t = dfa[s].transitions[c];
            if (t != -1 && (t < 0 || t >= state_count)) return false;
        }
        if (dfa[s].eos_target != 0 && dfa[s].eos_target >= (uint32_t)state_count) return false;
    }
    return true;
}

int dfa_minimize(build_dfa_state_t* dfa, int state_count) {
    if (state_count <= 0) return 0;
    int original = state_count;
    
    // Phase 1: Structural optimization
    state_count = prune_dead_states(dfa, state_count);

    // Phase 2: Behavioral optimization
    int new_count;
    if (current_algo == DFA_MIN_MOORE) {
        new_count = dfa_minimize_moore(dfa, state_count);
    } else if (current_algo == DFA_MIN_BRZOZOWSKI) {
        new_count = dfa_minimize_brzozowski(dfa, state_count);
    } else {
        new_count = dfa_minimize_hopcroft(dfa, state_count);
    }
    
    last_stats.initial_states = original;
    last_stats.final_states = new_count;
    last_stats.states_removed = original - new_count;
    
    if (!verify_minimized_dfa(dfa, new_count)) {
        fprintf(stderr, "FATAL: Minimized DFA failed verification.\n");
        exit(1);
    }
    
    return new_count;
}
