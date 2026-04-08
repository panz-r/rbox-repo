/**
 * DFA Layout Optimizer Implementation
 * 
 * Optimizes the binary layout of DFA states for cache performance.
 * Uses 3-region layout:
 * 1. Forward-BFS region: States close to start (early evaluation)
 * 2. Affinity groups: States that transition to each other (middle evaluation)
 * 3. Backward-BFS region: States close to accepting states (late evaluation)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "dfa_layout.h"

// MAX_STATES is defined in nfa.h which is included via dfa_minimize.h -> dfa_layout.h
#define MAX_LAYER 10000

// Thread-local sort key for qsort comparison (safe for single-threaded use)
static const int* g_layout_sort_key = NULL;

/**
 * Comparison function for qsort - compares states by their sort key.
 */
static int compare_layout_states(const void* a, const void* b) {
    int key_a = g_layout_sort_key[*(const int*)a];
    int key_b = g_layout_sort_key[*(const int*)b];
    return (key_a > key_b) - (key_a < key_b);
}

/**
 * Get default layout options (all optimizations enabled)
 */
layout_options_t get_default_layout_options(void) {
    layout_options_t opts = {
        .reorder_states = true,
        .place_rules_near_state = true,
        .align_cache_lines = true,
        .cache_line_size = 64
    };
    return opts;
}

/**
 * Build forward BFS depths from start state.
 * Returns array of depths (caller must free).
 */
static int* build_forward_depths(build_dfa_state_t** dfa, int state_count) {
    int* depths = malloc(state_count * sizeof(int));
    int* queue = malloc(state_count * sizeof(int));
    bool* visited = calloc(state_count, sizeof(bool));
    if (!depths || !queue || !visited) {
        free(depths); free(queue); free(visited);
        return NULL;
    }
    
    for (int i = 0; i < state_count; i++) {
        depths[i] = -1;
    }
    
    int head = 0, tail = 0;
    queue[tail++] = 0;
    visited[0] = true;
    depths[0] = 0;
    
    while (head < tail) {
        int state = queue[head++];
        for (int c = 0; c < BYTE_VALUE_MAX; c++) {
            int next = dfa[state]->transitions[c];
            if (next >= 0 && next < state_count && !visited[next]) {
                visited[next] = true;
                int d = depths[state] + 1;
                depths[next] = (d > MAX_LAYER) ? MAX_LAYER : d;
                queue[tail++] = next;
            }
        }
        if (dfa[state]->eos_target > 0 && dfa[state]->eos_target < (uint32_t)state_count) {
            int next = (int)dfa[state]->eos_target;
            if (!visited[next]) {
                visited[next] = true;
                int d = depths[state] + 1;
                depths[next] = (d > MAX_LAYER) ? MAX_LAYER : d;
                queue[tail++] = next;
            }
        }
    }
    
    // Cap any remaining -1 (unreachable) states to MAX_LAYER
    for (int i = 0; i < state_count; i++) {
        if (depths[i] < 0 || depths[i] > MAX_LAYER) {
            depths[i] = MAX_LAYER;
        }
    }
    
    free(queue);
    free(visited);
    return depths;
}

/**
 * Build backward BFS depths from accepting states.
 * Returns array of depths (caller must free).
 */
static int* build_backward_depths(build_dfa_state_t** dfa, int state_count) {
    int* depths = malloc(state_count * sizeof(int));
    int* queue = malloc(state_count * sizeof(int));
    bool* visited = calloc(state_count, sizeof(bool));
    bool* is_accepting = calloc(state_count, sizeof(bool));
    
    // Build predecessor lists
    int* pred_count = calloc(state_count, sizeof(int));
    int** preds = malloc(state_count * sizeof(int*));
    
    if (!depths || !queue || !visited || !is_accepting || !pred_count || !preds) {
        free(depths); free(queue); free(visited); free(is_accepting);
        free(pred_count); free(preds);
        return NULL;
    }
    for (int i = 0; i < state_count; i++) {
        preds[i] = NULL;
    }
    
    // Count predecessors
    for (int s = 0; s < state_count; s++) {
        for (int c = 0; c < BYTE_VALUE_MAX; c++) {
            int t = dfa[s]->transitions[c];
            if (t >= 0 && t < state_count) {
                pred_count[t]++;
            }
        }
        if (dfa[s]->eos_target > 0 && dfa[s]->eos_target < (uint32_t)state_count) {
            pred_count[dfa[s]->eos_target]++;
        }
    }
    
    // Allocate predecessor arrays
    for (int i = 0; i < state_count; i++) {
        if (pred_count[i] > 0) {
            preds[i] = malloc(pred_count[i] * sizeof(int));
            if (!preds[i]) {
                // Allocation failed - clean up and return NULL
                for (int j = 0; j < i; j++) {
                    free(preds[j]);
                }
                free(preds);
                free(pred_count);
                free(depths);
                free(queue);
                free(visited);
                free(is_accepting);
                return NULL;
            }
        }
        pred_count[i] = 0;  // Reset for filling
    }
    
    // Fill predecessor arrays
    for (int s = 0; s < state_count; s++) {
        for (int c = 0; c < BYTE_VALUE_MAX; c++) {
            int t = dfa[s]->transitions[c];
            if (t >= 0 && t < state_count) {
                preds[t][pred_count[t]++] = s;
            }
        }
        if (dfa[s]->eos_target > 0 && dfa[s]->eos_target < (uint32_t)state_count) {
            preds[dfa[s]->eos_target][pred_count[dfa[s]->eos_target]++] = s;
        }
    }
    
    for (int i = 0; i < state_count; i++) {
        depths[i] = -1;
        if (dfa[i]->flags & DFA_STATE_ACCEPTING) {
            is_accepting[i] = true;
        }
    }
    
    // BFS from all accepting states
    int head = 0, tail = 0;
    for (int i = 0; i < state_count; i++) {
        if (is_accepting[i]) {
            queue[tail++] = i;
            visited[i] = true;
            depths[i] = 0;
        }
    }
    
    while (head < tail) {
        int state = queue[head++];
        for (int i = 0; i < pred_count[state]; i++) {
            int pred = preds[state][i];
            if (!visited[pred]) {
                visited[pred] = true;
                int d = depths[state] + 1;
                depths[pred] = (d > MAX_LAYER) ? MAX_LAYER : d;
                queue[tail++] = pred;
            }
        }
    }
    
    // Cap any remaining -1 (unreachable) states to MAX_LAYER
    for (int i = 0; i < state_count; i++) {
        if (depths[i] < 0 || depths[i] > MAX_LAYER) {
            depths[i] = MAX_LAYER;
        }
    }
    
    // Cleanup
    for (int i = 0; i < state_count; i++) {
        free(preds[i]);
    }
    free(preds);
    free(pred_count);
    free(queue);
    free(visited);
    free(is_accepting);
    
    return depths;
}

// ============================================================================
// SCC-Based Layout Optimization
// ============================================================================

#define MAX_SCCS 4096

typedef struct {
    int* states;        // States in this SCC
    int count;          // Number of states
    int capacity;       // Allocated capacity
    int entry_layer;    // Min BFS layer from entry points
    int sort_key;       // For ordering SCCs in final layout
} scc_info_t;

/**
 * Tarjan's SCC algorithm for finding strongly connected components.
 * Returns scc_id[state] = SCC index for each state.
 * scc_info array is populated with states in each SCC.
 */
static int* find_sccs_tarjan(
    build_dfa_state_t** dfa,
    int state_count,
    scc_info_t* scc_info,
    int* scc_count_out
) {
    int* index = malloc(state_count * sizeof(int));
    int* lowlink = malloc(state_count * sizeof(int));
    bool* on_stack = calloc(state_count, sizeof(bool));
    int* stack = malloc(state_count * sizeof(int));
    int* scc_id = calloc(state_count, sizeof(int));  // Use calloc, init to 0
    
    if (!index || !lowlink || !on_stack || !stack || !scc_id) {
        free(index); free(lowlink); free(on_stack); free(stack); free(scc_id);
        return NULL;
    }
    
    for (int i = 0; i < state_count; i++) {
        index[i] = -1;
        scc_id[i] = -1;  // Mark as unvisited
    }
    
    for (int i = 0; i < MAX_SCCS; i++) {
        scc_info[i].states = NULL;
        scc_info[i].count = 0;
        scc_info[i].capacity = 0;
        scc_info[i].entry_layer = 0;
        scc_info[i].sort_key = 0;
    }
    
    int current_index = 0;
    int stack_top = 0;
    int scc_count = 0;
    
    // Tarjan's DFS (iterative to handle large graphs)
    int* dfs_stack = malloc(state_count * 2 * sizeof(int)); // (state, next_child_index)
    if (!dfs_stack) {
        free(index); free(lowlink); free(on_stack); free(stack); free(scc_id);
        *scc_count_out = 0;
        return NULL;
    }
    int dfs_top = 0;
    const int end_sentinel = BYTE_VALUE_MAX + 1;  // 257: marks all children processed
    
    for (int start = 0; start < state_count; start++) {
        if (index[start] >= 0) continue;
        
        // Start DFS from this state
        dfs_stack[dfs_top * 2] = start;
        dfs_stack[dfs_top * 2 + 1] = 0;
        dfs_top++;
        
        while (dfs_top > 0) {
            int state = dfs_stack[(dfs_top - 1) * 2];
            int* next_child = &dfs_stack[(dfs_top - 1) * 2 + 1];
            
            if (index[state] < 0) {
                // First visit
                index[state] = current_index;
                lowlink[state] = current_index;
                current_index++;
                stack[stack_top++] = state;
                on_stack[state] = true;
            }
            
            bool done = true;
            // Process children starting from next_child
            for (int c = *next_child; c < BYTE_VALUE_MAX; c++) {
                int next = dfa[state]->transitions[c];
                if (next >= 0 && next < state_count) {
                    if (index[next] < 0) {
                        // Unvisited child - recurse
                        *next_child = c + 1;
                        if (dfs_top < state_count) {  // Bounds check
                            dfs_stack[dfs_top * 2] = next;
                            dfs_stack[dfs_top * 2 + 1] = 0;
                            dfs_top++;
                        }
                        done = false;
                        break;
                    } else if (on_stack[next]) {
                        // Back edge
                        if (index[next] < lowlink[state]) {
                            lowlink[state] = index[next];
                        }
                    }
                }
            }
            
            // Also check EOS transitions
            if (done) {
                if (*next_child <= BYTE_VALUE_MAX) {
                    if (dfa[state]->eos_target > 0 && dfa[state]->eos_target < (uint32_t)state_count) {
                        int next = (int)dfa[state]->eos_target;
                        if (index[next] < 0) {
                            *next_child = end_sentinel; // Mark all children processed
                            if (dfs_top < state_count) {  // Bounds check
                                dfs_stack[dfs_top * 2] = next;
                                dfs_stack[dfs_top * 2 + 1] = 0;
                                dfs_top++;
                            }
                            done = false;
                        } else if (on_stack[next]) {
                            if (index[next] < lowlink[state]) {
                                lowlink[state] = index[next];
                            }
                        }
                    }
                }
            }
            
            if (done) {
                // All children processed - check if root of SCC
                if (lowlink[state] == index[state]) {
                    // Found an SCC
                    if (scc_count >= MAX_SCCS) break;
                    
                    int initial_cap = 64;
                    scc_info[scc_count].states = malloc(initial_cap * sizeof(int));
                    if (!scc_info[scc_count].states) {
                        // Allocation failed - stop SCC detection
                        break;
                    }
                    scc_info[scc_count].count = 0;
                    scc_info[scc_count].capacity = initial_cap;
                    
                    int s;
                    do {
                        s = stack[--stack_top];
                        on_stack[s] = false;
                        
                        // Grow if needed
                        if (scc_info[scc_count].count >= scc_info[scc_count].capacity) {
                            int new_cap = scc_info[scc_count].capacity * 2;
                            int* new_states = realloc(
                                scc_info[scc_count].states,
                                new_cap * sizeof(int)
                            );
                            if (!new_states) {
                                // realloc failed - keep original pointer, stop adding states
                                break;
                            }
                            scc_info[scc_count].states = new_states;
                            scc_info[scc_count].capacity = new_cap;
                        }
                        
                        scc_info[scc_count].states[scc_info[scc_count].count++] = s;
                        scc_id[s] = scc_count;
                    } while (s != state);
                    
                    scc_count++;
                }
                dfs_top--;
            }
        }
    }
    
    free(dfs_stack);
    free(index);
    free(lowlink);
    free(on_stack);
    free(stack);
    
    *scc_count_out = scc_count;
    return scc_id;
}

/**
 * Build condensation graph (DAG of SCCs).
 * condensation[i][j] = number of transitions from SCC i to SCC j
 */
static int** build_condensation_graph(
    build_dfa_state_t** dfa,
    int state_count,
    const int* scc_id,
    int scc_count
) {
    int** cond = calloc(scc_count, sizeof(int*));
    if (!cond) return NULL;
    
    for (int i = 0; i < scc_count; i++) {
        cond[i] = calloc(scc_count, sizeof(int));
        if (!cond[i]) {
            for (int j = 0; j < i; j++) free(cond[j]);
            free(cond);
            return NULL;
        }
    }
    
    // Count edges between SCCs
    for (int s = 0; s < state_count; s++) {
        int src_scc = scc_id[s];
        for (int c = 0; c < BYTE_VALUE_MAX; c++) {
            int t = dfa[s]->transitions[c];
            if (t >= 0 && t < state_count) {
                int dst_scc = scc_id[t];
                if (src_scc != dst_scc) {
                    cond[src_scc][dst_scc]++;
                }
            }
        }
        if (dfa[s]->eos_target > 0 && dfa[s]->eos_target < (uint32_t)state_count) {
            int t = (int)dfa[s]->eos_target;
            int dst_scc = scc_id[t];
            if (src_scc != dst_scc) {
                cond[src_scc][dst_scc]++;
            }
        }
    }
    
    return cond;
}

/**
 * Free condensation graph.
 */
static void free_condensation_graph(int** cond, int scc_count) {
    if (!cond) return;
    for (int i = 0; i < scc_count; i++) {
        free(cond[i]);
    }
    free(cond);
}

/**
 * Topological sort of condensation DAG using Kahn's algorithm.
 * Returns array: topo_order[position] = SCC index
 */
static int* topo_sort_condensation(int** cond, int scc_count) {
    int* in_degree = calloc(scc_count, sizeof(int));
    int* queue = malloc(scc_count * sizeof(int));
    int* order = malloc(scc_count * sizeof(int));
    
    if (!in_degree || !queue || !order) {
        free(in_degree); free(queue); free(order);
        return NULL;
    }
    
    for (int i = 0; i < scc_count; i++) {
        for (int j = 0; j < scc_count; j++) {
            if (cond[j][i] > 0) {
                in_degree[i]++;
            }
        }
    }
    
    // Kahn's algorithm
    int head = 0, tail = 0;
    for (int i = 0; i < scc_count; i++) {
        if (in_degree[i] == 0) {
            queue[tail++] = i;
        }
    }
    
    int pos = 0;
    while (head < tail) {
        int scc = queue[head++];
        order[pos++] = scc;
        
        for (int j = 0; j < scc_count; j++) {
            if (cond[scc][j] > 0) {
                in_degree[j]--;
                if (in_degree[j] == 0) {
                    queue[tail++] = j;
                }
            }
        }
    }
    
    free(in_degree);
    free(queue);
    return order;
}

/**
 * Compute BFS layers within an SCC from entry states.
 * Uses scc_id for O(1) membership check.
 */
static void compute_scc_layers(
    build_dfa_state_t** dfa,
    int state_count,
    const int* scc_states,
    int scc_size,
    const bool* is_entry,
    int* scc_layer,
    const int* scc_id,
    int current_scc
) {
    int* queue = malloc(scc_size * sizeof(int));
    if (!queue) return;
    
    int head = 0, tail = 0;
    
    // BFS from entry states
    for (int i = 0; i < scc_size; i++) {
        int s = scc_states[i];
        scc_layer[s] = -1;
        if (is_entry[s]) {
            scc_layer[s] = 0;
            queue[tail++] = s;
        }
    }
    
    // If no explicit entry states, start from first state
    if (tail == 0 && scc_size > 0) {
        int s = scc_states[0];
        scc_layer[s] = 0;
        queue[tail++] = s;
    }
    
    while (head < tail) {
        int state = queue[head++];
        int next_layer = scc_layer[state] + 1;
        if (next_layer > MAX_LAYER) next_layer = MAX_LAYER;
        
        for (int c = 0; c < BYTE_VALUE_MAX; c++) {
            int next = dfa[state]->transitions[c];
            if (next >= 0 && next < state_count && scc_layer[next] < 0) {
                // O(1) membership check using scc_id array
                if (scc_id[next] == current_scc) {
                    scc_layer[next] = next_layer;
                    queue[tail++] = next;
                }
            }
        }
    }
    
    // Mark any remaining unvisited states with sentinel (MAX_LAYER + 1)
    // These are states within the SCC that are unreachable from entry points
    for (int i = 0; i < scc_size; i++) {
        int s = scc_states[i];
        if (scc_layer[s] < 0) {
            scc_layer[s] = MAX_LAYER + 1;
        }
    }
    
    free(queue);
}

/**
 * Check if swapping positions p and p+1 preserves topological order.
 */
static bool can_swap_positions(int** cond, const int* order, int p, int scc_count) {
    if (p < 0 || p >= scc_count - 1) return false;
    int scc_a = order[p];
    int scc_b = order[p + 1];
    // Can swap only if there's no edge from scc_b to scc_a (would violate topo order)
    return cond[scc_b][scc_a] == 0;
}

/**
 * Compute cost delta for swapping adjacent SCCs at positions p and p+1.
 */
static long long swap_cost_delta(int** cond, const int* order, const int* pos, int p, int scc_count) {
    int scc_a = order[p];
    int scc_b = order[p + 1];
    long long delta = 0;
    
    for (int k = 0; k < scc_count; k++) {
        if (k == scc_a || k == scc_b) continue;
        delta += (long long)cond[k][scc_a] * (abs(pos[k] - (p + 1)) - abs(pos[k] - p));
        delta += (long long)cond[scc_a][k] * (abs((p + 1) - pos[k]) - abs(p - pos[k]));
        delta += (long long)cond[k][scc_b] * (abs(pos[k] - p) - abs(pos[k] - (p + 1)));
        delta += (long long)cond[scc_b][k] * (abs(p - pos[k]) - abs((p + 1) - pos[k]));
    }
    
    return delta;
}

#include "dfa_layout_sat.h"

/**
 * Greedy refinement of topological ordering for condensation DAG.
 * Minimizes Σ cond[i][j] * |pos[i] - pos[j]| (total weighted transition distance).
 * Uses iterative adjacent swap improvement.
 */
static int* refine_condensation_order(
    int** cond,
    int scc_count,
    int* topo_order
) {
    if (scc_count <= 2) {
        int* order = malloc(scc_count * sizeof(int));
        memcpy(order, topo_order, scc_count * sizeof(int));
        return order;
    }
    
    // Copy topological order
    int* order = malloc(scc_count * sizeof(int));
    memcpy(order, topo_order, scc_count * sizeof(int));
    
    // Map SCC -> position
    int* pos = malloc(scc_count * sizeof(int));
    for (int i = 0; i < scc_count; i++) {
        pos[order[i]] = i;
    }
    
    // Greedy improvement: try swapping adjacent SCCs
    bool improved = true;
    while (improved) {
        improved = false;
        for (int p = 0; p < scc_count - 1; p++) {
            if (!can_swap_positions(cond, order, p, scc_count)) continue;
            
            long long delta = swap_cost_delta(cond, order, pos, p, scc_count);
            
            if (delta < 0) {
                // Swap improves cost
                int scc_a = order[p];
                int scc_b = order[p + 1];
                order[p] = scc_b;
                order[p + 1] = scc_a;
                pos[scc_a] = p + 1;
                pos[scc_b] = p;
                improved = true;
            }
        }
    }
    
    free(pos);
    return order;
}

/**
 * Build affinity groups based on SCC decomposition.
 * States in the same SCC share the same affinity group.
 * SCCs are ordered by topological sort of the condensation DAG.
 */
static int* build_scc_affinity_groups(
    build_dfa_state_t** dfa,
    int state_count,
    int* group_count,
    int* scc_layer_out
) {
    if (state_count <= 0) return NULL;
    
    // For small DFAs, SCC analysis is unnecessary - use identity groups
    if (state_count < 8) {
        int* group_id = malloc(state_count * sizeof(int));
        if (!group_id) return NULL;
        for (int i = 0; i < state_count; i++) group_id[i] = i;
        if (scc_layer_out) memset(scc_layer_out, 0, state_count * sizeof(int));
        *group_count = state_count;
        return group_id;
    }
    
    // Step 1: Find SCCs
    scc_info_t scc_info[MAX_SCCS];
    int scc_count = 0;
    int* scc_id = find_sccs_tarjan(dfa, state_count, scc_info, &scc_count);
    if (!scc_id || scc_count == 0) {
        free(scc_id);
        return NULL;
    }
    
    // Step 2: Build condensation graph
    int** cond = build_condensation_graph(dfa, state_count, scc_id, scc_count);
    if (!cond) {
        for (int i = 0; i < scc_count; i++) free(scc_info[i].states);
        free(scc_id);
        return NULL;
    }
    
    // Step 3: Topological sort
    int* topo_order = topo_sort_condensation(cond, scc_count);
    if (!topo_order) {
        free_condensation_graph(cond, scc_count);
        for (int i = 0; i < scc_count; i++) free(scc_info[i].states);
        free(scc_id);
        return NULL;
    }
    
    // Step 3b: Refine ordering for better cache locality (greedy)
    int* refined_order = refine_condensation_order(cond, scc_count, topo_order);
    if (!refined_order) {
        refined_order = topo_order; // Fallback to topological order
    } else {
        free(topo_order);
        topo_order = refined_order;
    }
    
    // Step 3c: SAT-based refinement (if available and graph is small enough)
    if (sat_layout_available() && scc_count >= 4 && scc_count <= 20) {
        // Compute cost of greedy ordering
        int* greedy_pos = malloc(scc_count * sizeof(int));
        for (int p = 0; p < scc_count; p++) {
            greedy_pos[topo_order[p]] = p;
        }
        long long greedy_cost = 0;
        for (int i = 0; i < scc_count; i++) {
            for (int j = 0; j < scc_count; j++) {
                if (cond[i][j] > 0) {
                    greedy_cost += (long long)cond[i][j] * abs(greedy_pos[i] - greedy_pos[j]);
                }
            }
        }
        free(greedy_pos);
        
        // Try SAT optimization
        int* sat_order = sat_optimize_condensation_order(cond, scc_count, topo_order, greedy_cost);
        if (sat_order) {
            free(topo_order);
            topo_order = sat_order;
        }
    }
    
    // Step 4: Compute entry states and BFS layers within each SCC
    int* scc_layer = calloc(state_count, sizeof(int));
    bool* is_entry = calloc(state_count, sizeof(bool));
    
    // Mark entry states (state 0, and states with predecessors from other SCCs)
    is_entry[0] = true;
    for (int s = 0; s < state_count; s++) {
        int sid = scc_id[s];
        for (int c = 0; c < BYTE_VALUE_MAX; c++) {
            int t = dfa[s]->transitions[c];
            if (t >= 0 && t < state_count && scc_id[t] != sid) {
                is_entry[t] = true; // t is entry to its SCC
            }
        }
    }
    
    for (int i = 0; i < scc_count; i++) {
        compute_scc_layers(dfa, state_count, scc_info[i].states,
                          scc_info[i].count, is_entry, scc_layer, scc_id, i);
    }
    
    // Step 5: Build group ID based on topological order
    int* group_id = calloc(state_count, sizeof(int));
    if (!group_id) {
        free(scc_layer); free(is_entry);
        free_condensation_graph(cond, scc_count);
        for (int i = 0; i < scc_count; i++) free(scc_info[i].states);
        free(scc_id); free(topo_order);
        return NULL;
    }
    
    // Map SCC to topological position
    int* scc_topo_pos = malloc(scc_count * sizeof(int));
    for (int i = 0; i < scc_count; i++) {
        scc_topo_pos[topo_order[i]] = i;
    }
    
    // Initialize group_id to 0 for safety, then assign based on SCC
    for (int s = 0; s < state_count; s++) {
        group_id[s] = 0;  // Default for states not visited by Tarjan
    }
    for (int s = 0; s < state_count; s++) {
        if (scc_id[s] >= 0 && scc_id[s] < scc_count) {
            group_id[s] = scc_topo_pos[scc_id[s]];
        }
    }
    
    // Copy SCC layers to output
    if (scc_layer_out) {
        memcpy(scc_layer_out, scc_layer, state_count * sizeof(int));
    }
    
    *group_count = scc_count;
    
    // Cleanup
    free(scc_layer);
    free(is_entry);
    free(scc_topo_pos);
    free_condensation_graph(cond, scc_count);
    for (int i = 0; i < scc_count; i++) free(scc_info[i].states);
    free(scc_id);
    free(topo_order);
    
    return group_id;
}

/**
 * Build state access order using 3-region layout.
 * 1. Forward-BFS region: States close to start
 * 2. Affinity groups: States that transition to each other
 * 3. Backward-BFS region: States close to accepting states
 */
int* build_state_order_bfs(build_dfa_state_t** dfa, int state_count) {
    if (state_count <= 0) return NULL;
    
    int* forward_depths = build_forward_depths(dfa, state_count);
    int* backward_depths = build_backward_depths(dfa, state_count);
    
    if (!forward_depths || !backward_depths) {
        free(forward_depths);
        free(backward_depths);
        return NULL;
    }
    
    // Count truly unreachable states (not reachable from start AND can't reach accepting)
    int unreachable_count = 0;
    for (int i = 0; i < state_count; i++) {
        if (forward_depths[i] >= MAX_LAYER && backward_depths[i] >= MAX_LAYER) {
            unreachable_count++;
        }
    }
    
    // Find max depths
    int max_forward = 0, max_backward = 0;
    for (int i = 0; i < state_count; i++) {
        if (forward_depths[i] > max_forward) max_forward = forward_depths[i];
        if (backward_depths[i] > max_backward) max_backward = backward_depths[i];
    }
    
    // Define region boundaries (tunable)
    int forward_threshold = max_forward / 3;      // Top 1/3 by forward depth
    int backward_threshold = max_backward / 3;    // Top 1/3 by backward depth
    
    // Build SCC-based affinity groups for middle region
    int affinity_group_count;
    int* scc_layers = calloc(state_count, sizeof(int));
    int* affinity_groups = build_scc_affinity_groups(dfa, state_count, &affinity_group_count, scc_layers);
    if (!affinity_groups) {
        // Fallback: each state in its own group
        affinity_groups = malloc(state_count * sizeof(int));
        for (int i = 0; i < state_count; i++) affinity_groups[i] = i;
        affinity_group_count = state_count;
    }
    
    // Classify states into regions
    int* region = malloc(state_count * sizeof(int));
    #define REGION_FORWARD  0
    #define REGION_MIDDLE    1
    #define REGION_BACKWARD  2
    
    for (int i = 0; i < state_count; i++) {
        if (forward_depths[i] >= 0 && forward_depths[i] <= forward_threshold) {
            region[i] = REGION_FORWARD;
        } else if (backward_depths[i] >= 0 && backward_depths[i] <= backward_threshold) {
            region[i] = REGION_BACKWARD;
        } else {
            region[i] = REGION_MIDDLE;
        }
    }
    
    // Sort states: first by region, then by SCC group (for middle), then by depth
    int* order = malloc(state_count * sizeof(int));
    for (int i = 0; i < state_count; i++) {
        order[i] = i;
    }
    
    // Compute sort keys for O(n log n) sorting
    int* sort_key = malloc(state_count * sizeof(int));
    for (int i = 0; i < state_count; i++) {
        int subkey;
        if (region[i] == REGION_FORWARD) {
            subkey = forward_depths[i];
            if (subkey > MAX_LAYER) subkey = MAX_LAYER;
        } else if (region[i] == REGION_BACKWARD) {
            subkey = backward_depths[i];
            if (subkey > MAX_LAYER) subkey = MAX_LAYER;
        } else {
            // Middle region: SCC group in high bits, SCC-internal BFS layer in low bits
            // This groups states by SCC, then orders within SCC by unrolled BFS layer
            int scc_l = scc_layers[i];
            // Handle sentinel (MAX_LAYER + 1) by using max depth as fallback
            if (scc_l < 0 || scc_l > MAX_LAYER) {
                scc_l = forward_depths[i];
                if (scc_l < 0) scc_l = backward_depths[i];
                if (scc_l < 0) scc_l = MAX_LAYER;
            }
            if (scc_l > MAX_LAYER) scc_l = MAX_LAYER;
            subkey = (affinity_groups[i] << 16) | (scc_l & 0xFFFF);
        }
        // Region in bits 30-31, subkey in bits 0-29
        sort_key[i] = (region[i] << 30) | (subkey & 0x3FFFFFFF);
    }
    
    // Sort states
    g_layout_sort_key = sort_key;
    qsort(order, state_count, sizeof(int), compare_layout_states);
    free(sort_key);
    
    // CRITICAL: Ensure start state (state 0) remains at position 0
    // The DFA loader assumes state 0 is the initial state
    // After qsort, order[i] = state that should be at position i
    // We need to find where state 0 ended up and swap it with whatever is at position 0
    if (state_count > 0) {
        int pos_of_state_0 = -1;
        for (int i = 0; i < state_count; i++) {
            if (order[i] == 0) {
                pos_of_state_0 = i;
                break;
            }
        }
        
        if (pos_of_state_0 > 0) {
            // State 0 is not at position 0, swap with whatever is there
            int state_at_0 = order[0];
            order[0] = 0;
            order[pos_of_state_0] = state_at_0;
        }
    }
    
    // Convert to final order (old_state -> new_position)
    int* final_order = malloc(state_count * sizeof(int));
    for (int i = 0; i < state_count; i++) {
        final_order[order[i]] = i;
    }
    
    free(order);
    free(forward_depths);
    free(backward_depths);
    free(region);
    free(affinity_groups);
    free(scc_layers);
    
    return final_order;
}

/**
 * Create inverse mapping: new_position -> old_state
 */
static int* create_inverse_order(const int* order, int state_count) {
    int* inverse = malloc(state_count * sizeof(int));
    if (!inverse) return NULL;
    
    for (int i = 0; i < state_count; i++) {
        inverse[order[i]] = i;
    }
    
    return inverse;
}

/**
 * Reorder states according to the given order.
 * order[i] = new position of state i
 */
static void reorder_states(build_dfa_state_t** dfa, int state_count, const int* order) {
    build_dfa_state_t** temp = malloc(state_count * sizeof(build_dfa_state_t*));
    if (!temp) return;
    
    // Create inverse mapping
    int* inverse = create_inverse_order(order, state_count);
    if (!inverse) {
        free(temp);
        return;
    }
    
    // Copy states to new positions
    for (int i = 0; i < state_count; i++) {
        temp[order[i]] = dfa[i];
    }
    
    // Update transition targets to use new positions
    for (int i = 0; i < state_count; i++) {
        for (int c = 0; c < BYTE_VALUE_MAX; c++) {
            int old_target = temp[i]->transitions[c];
            if (old_target >= 0 && old_target < state_count) {
                temp[i]->transitions[c] = order[old_target];
            }
        }
        if (temp[i]->eos_target > 0 && temp[i]->eos_target < (uint32_t)state_count) {
            temp[i]->eos_target = order[temp[i]->eos_target];
        }
    }
    
    memcpy(dfa, temp, state_count * sizeof(build_dfa_state_t*));
    
    free(temp);
    free(inverse);
}

/**
 * Apply layout optimization to the DFA.
 */
int* optimize_dfa_layout(
    build_dfa_state_t** dfa,
    int state_count,
    const layout_options_t* options
) {
    if (!options || !options->reorder_states) {
        // No reordering, return identity mapping
        int* order = malloc(state_count * sizeof(int));
        if (order) {
            for (int i = 0; i < state_count; i++) {
                order[i] = i;
            }
        }
        return order;
    }
    
    // Build BFS-based order
    int* order = build_state_order_bfs(dfa, state_count);
    if (!order) return NULL;
    
    reorder_states(dfa, state_count, order);
    
    return order;
}

/**
 * Calculate the size of the optimized DFA layout.
 */
size_t calculate_optimized_layout_size(
    const build_dfa_state_t** dfa,
    int state_count,
    int encoding
) {
    int ss = DFA_STATE_SIZE(encoding);
    int rs = DFA_RULE_SIZE(encoding);
    uint8_t id_len = 0;  // Unknown at layout time; use 0 for estimate
    size_t hs = DFA_HEADER_SIZE(encoding, id_len);

    size_t size = hs;

    // States array
    size += (size_t)state_count * ss;

    // Count rules
    int total_rules = 0;
    for (int i = 0; i < state_count; i++) {
        for (int c = 0; c < BYTE_VALUE_MAX; c++) {
            if (dfa[i]->transitions[c] >= 0) {
                total_rules++;
            }
        }
    }

    // Rules array
    size += (size_t)total_rules * rs;

    // Marker data (approximate)
    for (int i = 0; i < state_count; i++) {
        for (int c = 0; c < BYTE_VALUE_MAX; c++) {
            if (dfa[i]->marker_offsets[c] != 0) {
                size += 16;  // Approximate marker list size
            }
        }
    }

    return size;
}
