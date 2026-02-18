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

// Global sort key for qsort comparison (not thread-safe, but OK for single-threaded use)
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
static int* build_forward_depths(const build_dfa_state_t* dfa, int state_count) {
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
        for (int c = 0; c < 256; c++) {
            int next = dfa[state].transitions[c];
            if (next >= 0 && next < state_count && !visited[next]) {
                visited[next] = true;
                depths[next] = depths[state] + 1;
                queue[tail++] = next;
            }
        }
        if (dfa[state].eos_target > 0 && dfa[state].eos_target < (uint32_t)state_count) {
            int next = (int)dfa[state].eos_target;
            if (!visited[next]) {
                visited[next] = true;
                depths[next] = depths[state] + 1;
                queue[tail++] = next;
            }
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
static int* build_backward_depths(const build_dfa_state_t* dfa, int state_count) {
    int* depths = malloc(state_count * sizeof(int));
    int* queue = malloc(state_count * sizeof(int));
    bool* visited = calloc(state_count, sizeof(bool));
    bool* is_accepting = calloc(state_count, sizeof(bool));
    
    // Build predecessor lists
    int* pred_count = calloc(state_count, sizeof(int));
    int** preds = malloc(state_count * sizeof(int*));
    for (int i = 0; i < state_count; i++) {
        preds[i] = NULL;
    }
    
    // Count predecessors
    for (int s = 0; s < state_count; s++) {
        for (int c = 0; c < 256; c++) {
            int t = dfa[s].transitions[c];
            if (t >= 0 && t < state_count) {
                pred_count[t]++;
            }
        }
        if (dfa[s].eos_target > 0 && dfa[s].eos_target < (uint32_t)state_count) {
            pred_count[dfa[s].eos_target]++;
        }
    }
    
    // Allocate predecessor arrays
    for (int i = 0; i < state_count; i++) {
        if (pred_count[i] > 0) {
            preds[i] = malloc(pred_count[i] * sizeof(int));
        }
        pred_count[i] = 0;  // Reset for filling
    }
    
    // Fill predecessor arrays
    for (int s = 0; s < state_count; s++) {
        for (int c = 0; c < 256; c++) {
            int t = dfa[s].transitions[c];
            if (t >= 0 && t < state_count) {
                preds[t][pred_count[t]++] = s;
            }
        }
        if (dfa[s].eos_target > 0 && dfa[s].eos_target < (uint32_t)state_count) {
            preds[dfa[s].eos_target][pred_count[dfa[s].eos_target]++] = s;
        }
    }
    
    // Initialize
    for (int i = 0; i < state_count; i++) {
        depths[i] = -1;
        if (dfa[i].flags & DFA_STATE_ACCEPTING) {
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
                depths[pred] = depths[state] + 1;
                queue[tail++] = pred;
            }
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

/**
 * Build affinity groups - states that transition to each other.
 * Simplified version: just use state ID as group (identity).
 * The middle region has no clear optimal layout, so we keep original order.
 */
static int* build_affinity_groups(const build_dfa_state_t* dfa, int state_count, int* group_count) {
    // For middle region: just use state ID as group
    // This preserves original order when sorted by (group, depth)
    // Since group=i for all states, sorting becomes just by depth
    int* group_id = malloc(state_count * sizeof(int));
    for (int i = 0; i < state_count; i++) {
        group_id[i] = i;  // Each state in its own group = identity order
    }
    *group_count = state_count;
    (void)dfa;  // Unused
    return group_id;
}

/**
 * Build state access order using 3-region layout.
 * 1. Forward-BFS region: States close to start
 * 2. Affinity groups: States that transition to each other
 * 3. Backward-BFS region: States close to accepting states
 */
int* build_state_order_bfs(const build_dfa_state_t* dfa, int state_count) {
    if (state_count <= 0) return NULL;
    
    int* forward_depths = build_forward_depths(dfa, state_count);
    int* backward_depths = build_backward_depths(dfa, state_count);
    
    if (!forward_depths || !backward_depths) {
        free(forward_depths);
        free(backward_depths);
        return NULL;
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
    
    // Build affinity groups for middle region
    int affinity_group_count;
    int* affinity_groups = build_affinity_groups(dfa, state_count, &affinity_group_count);
    
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
    
    // Sort states: first by region, then by affinity group (for middle), then by depth
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
        } else if (region[i] == REGION_BACKWARD) {
            subkey = backward_depths[i];
        } else {
            // Middle region: affinity group in high bits, combined depth in low bits
            subkey = (affinity_groups[i] << 16) | (forward_depths[i] + backward_depths[i]);
        }
        // Region in bits 30-31, subkey in bits 0-29
        sort_key[i] = (region[i] << 30) | (subkey & 0x3FFFFFFF);
    }
    
    // Use file-scope comparison function
    g_layout_sort_key = sort_key;
    qsort(order, state_count, sizeof(int), compare_layout_states);
    free(sort_key);
    
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
static void reorder_states(build_dfa_state_t* dfa, int state_count, const int* order) {
    build_dfa_state_t* temp = malloc(state_count * sizeof(build_dfa_state_t));
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
        for (int c = 0; c < 256; c++) {
            int old_target = temp[i].transitions[c];
            if (old_target >= 0 && old_target < state_count) {
                temp[i].transitions[c] = order[old_target];
            }
        }
        if (temp[i].eos_target > 0 && temp[i].eos_target < (uint32_t)state_count) {
            temp[i].eos_target = order[temp[i].eos_target];
        }
    }
    
    // Copy back
    memcpy(dfa, temp, state_count * sizeof(build_dfa_state_t));
    
    free(temp);
    free(inverse);
}

/**
 * Apply layout optimization to the DFA.
 */
int* optimize_dfa_layout(
    build_dfa_state_t* dfa,
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
    
    // Apply reordering
    reorder_states(dfa, state_count, order);
    
    return order;
}

/**
 * Calculate the size of the optimized DFA layout.
 */
size_t calculate_optimized_layout_size(
    const build_dfa_state_t* dfa,
    int state_count,
    const layout_options_t* options
) {
    (void)options;  // Currently not used
    
    // Header size
    size_t size = 23;  // magic(4) + version(2) + state_count(2) + initial_state(4) + 
                       // accepting_mask(4) + flags(2) + id_len(1) + metadata(4)
    
    // States array
    size += state_count * sizeof(dfa_state_t);
    
    // Count rules
    int total_rules = 0;
    for (int i = 0; i < state_count; i++) {
        for (int c = 0; c < 256; c++) {
            if (dfa[i].transitions[c] >= 0) {
                total_rules++;
            }
        }
    }
    
    // Rules array
    size += total_rules * sizeof(dfa_rule_t);
    
    // Marker data (approximate)
    for (int i = 0; i < state_count; i++) {
        for (int c = 0; c < 256; c++) {
            if (dfa[i].marker_offsets[c] != 0) {
                size += 16;  // Approximate marker list size
            }
        }
    }
    
    return size;
}
