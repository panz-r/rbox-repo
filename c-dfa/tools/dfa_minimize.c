/**
 * DFA Minimization Implementation
 * 
 * Implements DFA state minimization using a variant of Hopcroft's algorithm.
 * Optimized for the ReadOnlyBox DFA structure with 256 character transitions.
 * 
 * Algorithm Overview:
 * 1. Start with two partitions: accepting states and non-accepting states
 * 2. Split partitions based on transition targets
 * 3. Repeat until no more splits occur
 * 4. Build minimized DFA with one state per partition
 * 
 * Time Complexity: O(n * k * log n) where n=states, k=alphabet size (256)
 * Space Complexity: O(n * k)
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
#define MAX_STATES 8192
#define MAX_SYMBOLS 256

// Debug flag
static bool minimize_verbose = false;

// Statistics
static dfa_minimize_stats_t last_stats = {0};

// Worklist for partition refinement
// Each partition is a set of states that are currently equivalent
typedef struct {
    int* states;         // Dynamic array of states in this partition
    int count;
    int capacity;
    uint16_t signature;  // Hash signature for quick comparison
} partition_t;

// State mapping: original state -> partition index
typedef struct {
    int* partition_map;      // State -> partition index
    partition_t* partitions; // Array of partitions
    int partition_count;
    int max_partitions;
} minimizer_state_t;

#define VERBOSE_PRINT(fmt, ...) do { \
    if (minimize_verbose) fprintf(stderr, "[MINIMIZE] " fmt, ##__VA_ARGS__); \
} while(0)

/**
 * Check allocation result and abort on failure with error message
 */
static void* alloc_or_abort(void* ptr, const char* msg) {
    if (ptr == NULL) {
        fprintf(stderr, "FATAL: %s - %s\n", msg, strerror(errno));
        exit(EXIT_FAILURE);
    }
    return ptr;
}

/**
 * Check if two states have equivalent "acceptance properties"
 * States can only be equivalent if they have:
 * - Same category mask (accepting/non-accepting and which categories)
 * - Same capture markers (start, end, defer)
 * - Same EOS target status
 */
static bool states_have_same_properties(const build_dfa_state_t* s1, const build_dfa_state_t* s2) {
    // Check category mask (bits 8-15 of flags)
    uint8_t cat1 = (s1->flags >> 8) & 0xFF;
    uint8_t cat2 = (s2->flags >> 8) & 0xFF;
    if (cat1 != cat2) return false;
    
    // Check capture markers
    if (s1->capture_start_id != s2->capture_start_id) return false;
    if (s1->capture_end_id != s2->capture_end_id) return false;
    if (s1->capture_defer_id != s2->capture_defer_id) return false;
    
    // Check EOS target (simplified: just check if both have or don't have EOS)
    bool has_eos1 = (s1->eos_target != 0);
    bool has_eos2 = (s2->eos_target != 0);
    if (has_eos1 != has_eos2) return false;
    
    // Check other flags that affect behavior (but not category)
    uint16_t flags1 = s1->flags & 0xFF;  // Lower 8 bits only
    uint16_t flags2 = s2->flags & 0xFF;
    if (flags1 != flags2) return false;
    
    return true;
}

/**
 * Check if two states have equivalent transitions given current partition mapping
 * 
 * Two states are transition-equivalent if for every character c:
 * - Both have no transition on c, OR
 * - Both transition to states in the same partition
 */
static bool states_have_equivalent_transitions(
    const build_dfa_state_t* s1,
    const build_dfa_state_t* s2,
    const int* partition_map
) {
    for (int c = 0; c < 256; c++) {
        int t1 = s1->transitions[c];
        int t2 = s2->transitions[c];
        
        // Both have no transition - equivalent for this character
        if (t1 == -1 && t2 == -1) continue;
        
        // One has transition, other doesn't - not equivalent
        if (t1 == -1 || t2 == -1) return false;
        
        // Both have transitions - check if they go to same partition
        if (partition_map[t1] != partition_map[t2]) return false;

        // Transitions must also match their "from_any" attribute
        if (s1->transitions_from_any[c] != s2->transitions_from_any[c]) return false;
    }
    
    // Check EOS target transition equivalence
    uint32_t eos1 = s1->eos_target;
    uint32_t eos2 = s2->eos_target;
    
    // If one has EOS and other doesn't, they are not equivalent
    // (This was already checked in properties but good to be explicit here)
    if ((eos1 != 0) != (eos2 != 0)) return false;
    
    // If both have EOS, they must point to equivalent states (same partition)
    if (eos1 != 0 && eos2 != 0) {
        if (partition_map[eos1] != partition_map[eos2]) return false;
    }
    
    return true;
}

// FNV-1a Constants
#define FNV_PRIME 16777619
#define FNV_OFFSET_BASIS 2166136261u

/**
 * Compute a signature (hash) for a state based on its transitions
 * Uses FNV-1a algorithm for better distribution/collision resistance
 */
static uint16_t compute_state_signature(
    const build_dfa_state_t* state,
    const int* partition_map
) {
    uint32_t hash = FNV_OFFSET_BASIS;
    
    // Include properties in signature
    // Mix flags (category mask + state flags)
    hash ^= (state->flags & 0xFFFF);
    hash *= FNV_PRIME;
    
    // Mix capture IDs
    hash ^= (uint8_t)state->capture_start_id; hash *= FNV_PRIME;
    hash ^= (uint8_t)state->capture_end_id; hash *= FNV_PRIME;
    hash ^= (uint8_t)state->capture_defer_id; hash *= FNV_PRIME;
    
    // Mix EOS target existence (we'll mix the partition later)
    if (state->eos_target != 0) {
        hash ^= 0xFF; 
        hash *= FNV_PRIME;
    }
    
    // Include transition target partitions
    for (int c = 0; c < 256; c++) {
        int t = state->transitions[c];
        int target_p = (t != -1) ? partition_map[t] : -1;
        bool from_any = state->transitions_from_any[c];
        
        // Construct a 32-bit value representing this transition edge
        // [from_any:1] [char:8] [target_partition:23]
        // Actually, for FNV we just mix bytes.
        
        // Mix Character
        hash ^= c;
        hash *= FNV_PRIME;
        
        // Mix Target Partition (low byte)
        hash ^= (target_p & 0xFF);
        hash *= FNV_PRIME;
        
        // Mix Target Partition (high byte)
        hash ^= ((target_p >> 8) & 0xFF);
        hash *= FNV_PRIME;
        
        // Mix 'from_any' flag
        if (from_any) {
            hash ^= 0xAA;
            hash *= FNV_PRIME;
        }
    }
    
    // Include EOS target partition in signature
    if (state->eos_target != 0) {
        // We use state index as EOS target initially, but for signature 
        // we must use the PARTITION of that target
        int eos_p = partition_map[state->eos_target];
        hash ^= (eos_p & 0xFF); hash *= FNV_PRIME;
        hash ^= ((eos_p >> 8) & 0xFF); hash *= FNV_PRIME;
    }
    
    // Fold 32-bit hash to 16-bit signature
    return (uint16_t)((hash >> 16) ^ (hash & 0xFFFF));
}

/**
 * Initialize partitions based on acceptance properties
 * Split states into accepting vs non-accepting groups first
 */
static void initialize_partitions(
    minimizer_state_t* ms,
    const build_dfa_state_t* dfa,
    int state_count
) {
    // Allocate dynamic arrays for partitions
    ms->max_partitions = state_count;
    ms->partitions = alloc_or_abort(calloc(state_count, sizeof(partition_t)),
                                     "Failed to allocate partitions array");
    ms->partition_map = alloc_or_abort(malloc(state_count * sizeof(int)),
                                        "Failed to allocate partition map");
    
    // Initialize partition map
    for (int i = 0; i < state_count; i++) {
        ms->partition_map[i] = -1;
    }
    
    // First pass: group by properties
    int group_count = 0;
    
    for (int s = 0; s < state_count; s++) {
        bool found_group = false;
        
        // Find a matching group
        for (int g = 0; g < group_count; g++) {
            int representative = ms->partitions[g].states[0];
            if (states_have_same_properties(&dfa[s], &dfa[representative])) {
                // Add to existing group
                if (ms->partitions[g].count >= ms->partitions[g].capacity) {
                    ms->partitions[g].capacity = ms->partitions[g].capacity * 2 + 4;
                    ms->partitions[g].states = alloc_or_abort(realloc(ms->partitions[g].states,
                                                        ms->partitions[g].capacity * sizeof(int)),
                                                        "Failed to grow partition states array");
                }
                ms->partitions[g].states[ms->partitions[g].count++] = s;
                ms->partition_map[s] = g;
                found_group = true;
                break;
            }
        }
        
        // Create new group
        if (!found_group) {
            ms->partitions[group_count].capacity = 4;
            ms->partitions[group_count].states = alloc_or_abort(malloc(ms->partitions[group_count].capacity * sizeof(int)),
                                                                 "Failed to allocate partition states array");
            ms->partitions[group_count].states[0] = s;
            ms->partitions[group_count].count = 1;
            ms->partitions[group_count].signature = 0;
            ms->partition_map[s] = group_count;
            group_count++;
        }
    }
    
    ms->partition_count = group_count;
    
    VERBOSE_PRINT("Initial partitions: %d (from %d states)\n", group_count, state_count);
}

/**
 * Refine partitions by splitting based on transition differences
 * Returns true if any splits occurred
 */
static bool refine_partitions(minimizer_state_t* ms, const build_dfa_state_t* dfa) {
    bool changed = false;
    int old_partition_count = ms->partition_count;
    
    // Process each existing partition
    for (int p = 0; p < old_partition_count; p++) {
        if (ms->partitions[p].count <= 1) continue;  // Can't split singleton
        
        // Try to split this partition
        // Group states by their transition signatures
        uint16_t* state_sigs = alloc_or_abort(malloc(ms->partitions[p].count * sizeof(uint16_t)),
                                               "Failed to allocate state signatures array");

        for (int i = 0; i < ms->partitions[p].count; i++) {
            int state = ms->partitions[p].states[i];
            state_sigs[i] = compute_state_signature(&dfa[state], ms->partition_map);
        }

        // Find unique signatures and assign states to subgroups
        int p_count = ms->partitions[p].count;
        uint16_t* unique_sigs = alloc_or_abort(malloc(p_count * sizeof(uint16_t)), "Failed to allocate unique signatures array");
        int* unique_reps = alloc_or_abort(malloc(p_count * sizeof(int)), "Failed to allocate unique representatives array");
        int unique_count = 0;
        int* state_to_subgroup = alloc_or_abort(malloc(p_count * sizeof(int)), "Failed to allocate subgroup mapping array");
        
        for (int i = 0; i < p_count; i++) {
            uint16_t sig = state_sigs[i];
            int state = ms->partitions[p].states[i];
            int subgroup = -1;
            
            // Find matching signature
            for (int u = 0; u < unique_count; u++) {
                if (unique_sigs[u] == sig) {
                    // Verify actual equivalence (signature collision check)
                    int rep = unique_reps[u];
                    if (states_have_equivalent_transitions(&dfa[state], &dfa[rep], ms->partition_map)) {
                        subgroup = u;
                        break;
                    }
                }
            }
            
            // Create new subgroup if no match
            if (subgroup < 0) {
                unique_sigs[unique_count] = sig;
                unique_reps[unique_count] = state;
                subgroup = unique_count;
                unique_count++;
            }
            
            state_to_subgroup[i] = subgroup;
        }
        
        // If multiple subgroups, we need to split
        if (unique_count > 1) {
            VERBOSE_PRINT("Splitting partition %d (%d states) into %d subgroups\n", 
                         p, p_count, unique_count);
            
            // Count states in each subgroup
            int* subgroup_counts = alloc_or_abort(calloc(unique_count, sizeof(int)), "Failed to allocate subgroup counts");
            for (int i = 0; i < p_count; i++) {
                subgroup_counts[state_to_subgroup[i]]++;
            }
            
            // Keep first subgroup (subgroup 0) in original partition
            // Move others to new partitions
            
            // Create new partitions for other subgroups first
            int* subgroup_partitions = alloc_or_abort(malloc(unique_count * sizeof(int)), "Failed to allocate subgroup partitions array");
            subgroup_partitions[0] = p;  // Original partition
            
            for (int sg = 1; sg < unique_count; sg++) {
                if (ms->partition_count >= ms->max_partitions) {
                    ms->max_partitions *= 2;
                    ms->partitions = alloc_or_abort(realloc(ms->partitions, ms->max_partitions * sizeof(partition_t)),
                                                     "Failed to grow partitions array");
                }
                
                int new_p = ms->partition_count++;
                subgroup_partitions[sg] = new_p;
                ms->partitions[new_p].capacity = subgroup_counts[sg];
                ms->partitions[new_p].states = alloc_or_abort(malloc(subgroup_counts[sg] * sizeof(int)),
                                                                "Failed to allocate new partition states");
                ms->partitions[new_p].count = 0;
                ms->partitions[new_p].signature = unique_sigs[sg];
            }
            
            // Create new array for original partition's kept states
            int* new_states = alloc_or_abort(malloc(subgroup_counts[0] * sizeof(int)), "Failed to allocate kept states array");
            int new_count = 0;
            
            // Move states to their new partitions
            for (int i = 0; i < p_count; i++) {
                int sg = state_to_subgroup[i];
                int state = ms->partitions[p].states[i];
                int dest_p = subgroup_partitions[sg];
                
                if (sg == 0) {
                    // Keep in original partition
                    new_states[new_count++] = state;
                } else {
                    // Move to new partition
                    ms->partitions[dest_p].states[ms->partitions[dest_p].count++] = state;
                }
                ms->partition_map[state] = dest_p;
            }
            
            // Update original partition
            free(ms->partitions[p].states);
            ms->partitions[p].states = new_states;
            ms->partitions[p].count = new_count;
            ms->partitions[p].capacity = new_count;
            
            free(subgroup_partitions);
            free(subgroup_counts);
            changed = true;
        }
        
        free(unique_sigs);
        free(unique_reps);
        free(state_sigs);
        free(state_to_subgroup);
    }
    
    return changed;
}

/**
 * Build the minimized DFA from partitions
 * Returns the new state count
 */
static int build_minimized_dfa(
    build_dfa_state_t* dfa,
    const minimizer_state_t* ms,
    int old_state_count
) {
    build_dfa_state_t* new_dfa = malloc(ms->partition_count * sizeof(build_dfa_state_t));
    int* state_remap = malloc(old_state_count * sizeof(int));
    
    if (!new_dfa || !state_remap) {
        fprintf(stderr, "Error: Failed to allocate memory for minimized DFA\n");
        free(new_dfa);
        free(state_remap);
        return old_state_count;  // Return original count on failure
    }
    
    // Build new DFA with one state per partition
    int new_count = 0;
    for (int p = 0; p < ms->partition_count; p++) {
        if (ms->partitions[p].count == 0) continue;
        
        // Use the first state of partition as representative
        int rep = ms->partitions[p].states[0];
        memcpy(&new_dfa[new_count], &dfa[rep], sizeof(build_dfa_state_t));
        
        // Record remapping for all states in this partition
        for (int i = 0; i < ms->partitions[p].count; i++) {
            state_remap[ms->partitions[p].states[i]] = new_count;
        }
        
        new_count++;
    }
    
    VERBOSE_PRINT("Remapping %d states to %d minimized states\n", old_state_count, new_count);
    
    // Update transitions in new DFA to point to remapped states
    for (int s = 0; s < new_count; s++) {
        for (int c = 0; c < 256; c++) {
            int old_target = new_dfa[s].transitions[c];
            if (old_target != -1 && old_target < old_state_count) {
                new_dfa[s].transitions[c] = state_remap[old_target];
            }
        }
        
        // Remap EOS target (0 means no EOS target)
        if (new_dfa[s].eos_target != 0 && new_dfa[s].eos_target < (uint32_t)old_state_count) {
            new_dfa[s].eos_target = (uint32_t)state_remap[new_dfa[s].eos_target];
        }
        
        // Clear nfa_states count - not needed in minimized DFA
        // Note: we don't zero the large nfa_states array for performance
        new_dfa[s].nfa_state_count = 0;
    }
    
    // Copy back to original array
    memcpy(dfa, new_dfa, new_count * sizeof(build_dfa_state_t));
    
    free(new_dfa);
    free(state_remap);
    
    return new_count;
}

/**
 * Verify that a minimized DFA is valid
 * Returns true if valid, false otherwise
 */
static bool verify_minimized_dfa(const build_dfa_state_t* dfa, int state_count, int original_count) {
    bool valid = true;
    int errors = 0;

    // Check 1: All transitions point to valid states
    for (int s = 0; s < state_count && errors < 10; s++) {
        for (int c = 0; c < 256; c++) {
            int target = dfa[s].transitions[c];
            if (target != -1) {
                if (target < 0 || target >= state_count) {
                    fprintf(stderr, "VERIFY ERROR: State %d has invalid transition on char %d to state %d (valid range: 0-%d)\n",
                            s, c, target, state_count - 1);
                    errors++;
                    valid = false;
                }
            }
        }
    }

    // Check 2: All EOS targets are valid
    for (int s = 0; s < state_count && errors < 10; s++) {
        if (dfa[s].eos_target != 0) {
            // eos_target is a state index in the minimized DFA
            if (dfa[s].eos_target >= (uint32_t)state_count) {
                fprintf(stderr, "VERIFY ERROR: State %d has invalid EOS target %u (valid range: 0-%d)\n",
                        s, dfa[s].eos_target, state_count - 1);
                errors++;
                valid = false;
            }
        }
    }

    // Check 3: At least one state exists
    if (state_count <= 0) {
        fprintf(stderr, "VERIFY ERROR: Minimized DFA has no states\n");
        valid = false;
    }

    // Check 4: State count should be <= original (can't grow)
    if (state_count > original_count) {
        fprintf(stderr, "VERIFY ERROR: State count grew from %d to %d\n", original_count, state_count);
        valid = false;
    }

    // Check 5: Verify at least one accepting state exists if original had one
    bool has_accepting = false;
    for (int s = 0; s < state_count; s++) {
        if (dfa[s].flags & 0xFF00) {  // Check category mask
            has_accepting = true;
            break;
        }
    }
    
    // Check 6: Verify State 0 integrity
    // Partition 0 must contain original State 0 and be mapped to new State 0
    // This is guaranteed by initialize_partitions and build_minimized_dfa
    // but we check the resulting DFA structure here.
    if (state_count > 0) {
        // Start state (0) should generally not have flags like DEAD or ERROR
        // unless the whole DFA is just that state.
        if (dfa[0].flags & DFA_STATE_ERROR) {
            fprintf(stderr, "VERIFY WARNING: Start state 0 is marked as ERROR\n");
        }
    }

    // We can't easily check if original had accepting states without passing more info,
    // but we can at least report the status
    VERBOSE_PRINT("Verification: %d states, %saccepting state%s found\n",
                  state_count, has_accepting ? "" : "no ", has_accepting ? "" : "s");

    return valid;
}

/**
 * Main minimization entry point
 */
int dfa_minimize(build_dfa_state_t* dfa, int state_count) {
    if (state_count <= 0) return 0;
    if (state_count > MAX_STATES) {
        fprintf(stderr, "Error: Too many states for minimization (%d > %d)\n", 
                state_count, MAX_STATES);
        return state_count;
    }
    
    VERBOSE_PRINT("Starting DFA minimization: %d states\n", state_count);
    
    minimizer_state_t ms;
    memset(&ms, 0, sizeof(ms));
    ms.partition_map = NULL;
    ms.partitions = NULL;
    ms.partition_count = 0;
    ms.max_partitions = 0;
    
    // Step 1: Create initial partitions based on acceptance
    initialize_partitions(&ms, dfa, state_count);
    
    // Step 2: Refine partitions until stable
    int iterations = 0;
    const int MAX_ITERATIONS = 100;  // Safety limit
    
    while (iterations < MAX_ITERATIONS) {
        iterations++;
        VERBOSE_PRINT("Refinement iteration %d: %d partitions\n", iterations, ms.partition_count);
        
        if (!refine_partitions(&ms, dfa)) {
            VERBOSE_PRINT("No more splits possible after %d iterations\n", iterations);
            break;
        }
    }
    
    if (iterations >= MAX_ITERATIONS) {
        fprintf(stderr, "Warning: Minimization did not converge after %d iterations\n", 
                MAX_ITERATIONS);
    }
    
    // Step 3: Build minimized DFA
    int new_count = build_minimized_dfa(dfa, &ms, state_count);
    
    // Cleanup: free all allocated memory
    for (int p = 0; p < ms.partition_count; p++) {
        free(ms.partitions[p].states);
    }
    free(ms.partitions);
    free(ms.partition_map);
    
    // Update statistics
    last_stats.initial_states = state_count;
    last_stats.final_states = new_count;
    last_stats.states_removed = state_count - new_count;
    last_stats.iterations = iterations;
    
    VERBOSE_PRINT("Minimization complete: %d -> %d states (removed %d, %.1f%% reduction)\n",
                 state_count, new_count, state_count - new_count,
                 state_count > 0 ? (100.0 * (state_count - new_count) / state_count) : 0.0);
    
    // Verify the minimized DFA structure
    if (!verify_minimized_dfa(dfa, new_count, state_count)) {
        fprintf(stderr, "FATAL: Minimized DFA failed verification. Aborting to prevent invalid binary output.\n");
        exit(EXIT_FAILURE);
    }
    
    return new_count;
}

/**
 * Set verbose output mode
 */
void dfa_minimize_set_verbose(bool verbose) {
    minimize_verbose = verbose;
}

/**
 * Get statistics from last minimization
 */
void dfa_minimize_get_stats(dfa_minimize_stats_t* stats) {
    if (stats) {
        memcpy(stats, &last_stats, sizeof(dfa_minimize_stats_t));
    }
}
