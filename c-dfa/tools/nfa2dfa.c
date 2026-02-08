#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include "../include/dfa_types.h"
#include "../include/nfa.h"
#include "dfa_minimize.h"

// Bitmask type for visited tracking (8192 bits = 128 uint64_t for MAX_STATES=8192)
#define VISITED_WORDS 128
typedef struct {
    uint64_t bits[VISITED_WORDS];
} visited_bitmask_t;

// Forward declaration
int find_symbol_id(char c);

// Pattern identifier (read from NFA file)
static char pattern_identifier[256] = "";

// Debug output control - set to 0 to disable all debug prints
#ifndef NFA2DFA_DEBUG
#define NFA2DFA_DEBUG 0
#endif

// Verbose output control - set to 0 to disable progress messages
#ifndef NFA2DFA_VERBOSE
#define NFA2DFA_VERBOSE 0
#endif

// Runtime verbose flag (overrides compile-time setting)
static bool flag_verbose = false;

// Conditional debug print macro - only prints if verbose is enabled
#define DEBUG_PRINT(fmt, ...) do { if (flag_verbose) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

// Character class definition
typedef struct {
    int start_char;
    int end_char;
    int symbol_id;
    bool is_special;
} char_class_t;

// Negated transition structure for NFA
typedef struct {
    int target_state;
    char excluded_chars[MAX_SYMBOLS];
    int excluded_count;
} negated_transition_t;

// NFA State for reading NFA files
typedef struct {
    uint8_t category_mask;  // Bitmask of accepting categories
    char* tags[MAX_STATES];
    int tag_count;
    int transitions[MAX_SYMBOLS];
    int transition_count;
    char multi_targets[MAX_SYMBOLS][256];  // For storing additional targets as CSV
    negated_transition_t negated_transitions[MAX_SYMBOLS];
    int negated_transition_count;
    int8_t capture_start_id;   // Capture ID to emit at this state (-1 = none)
    int8_t capture_end_id;     // Capture ID to emit at this state (-1 = none)
    int8_t capture_defer_id;   // Capture ID to defer until leaving this state (-1 = none)
    bool is_eos_target;        // This state can accept via EOS transition
    int16_t pattern_id;        // Pattern ID this state belongs to (-1 = none/shared)
} nfa_state_t;

// Note: build_dfa_state_t is now defined in dfa_minimize.h

// Global variables
static nfa_state_t nfa[MAX_STATES];
static build_dfa_state_t dfa[MAX_STATES];
static char_class_t alphabet[MAX_SYMBOLS];
static int nfa_state_count = 0;
static int dfa_state_count = 0;
static int alphabet_size = 0;

// Initialize NFA
void nfa_init(void) {
    for (int i = 0; i < MAX_STATES; i++) {
        nfa[i].category_mask = 0;
        nfa[i].tag_count = 0;
        for (int j = 0; j < MAX_STATES; j++) {
            nfa[i].tags[j] = NULL;
        }
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            nfa[i].transitions[j] = -1;
            nfa[i].multi_targets[j][0] = '\0';
        }
        nfa[i].transition_count = 0;
        nfa[i].negated_transition_count = 0;
        nfa[i].capture_start_id = -1;
        nfa[i].capture_end_id = -1;
        nfa[i].capture_defer_id = -1;
        nfa[i].is_eos_target = false;
        nfa[i].pattern_id = -1;
    }
    nfa_state_count = 0;
}

// Initialize DFA
void dfa_init(void) {
    for (int i = 0; i < MAX_STATES; i++) {
        dfa[i].flags = 0;
        dfa[i].transition_count = 0;
        dfa[i].nfa_state_count = 0;
        dfa[i].capture_start_id = -1;
        dfa[i].capture_end_id = -1;
        dfa[i].capture_defer_id = -1;
        dfa[i].eos_target = 0;
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            dfa[i].transitions[j] = -1;
            dfa[i].transitions_from_any[j] = false;
        }
        for (int j = 0; j < MAX_STATES; j++) {
            dfa[i].nfa_states[j] = -1;
        }
    }
    dfa_state_count = 0;
}

// Helper function to iteratively follow EOS transitions and collect category masks
// Returns the combined category mask from all terminal states reachable via EOS chain
// Uses iterative DFS with bitmask visited tracking to avoid stack overflow
static uint8_t collect_eos_categories(int start_state, int eos_symbol) {
    uint8_t combined_mask = 0;

    // Use a bitmask for visited tracking
    visited_bitmask_t visited;
    memset(&visited, 0, sizeof(visited));

    // Stack for iterative DFS (use malloc for large stacks if needed)
    int* stack = NULL;
    int stack_capacity = 64;
    int stack_top = 0;

    stack = malloc(stack_capacity * sizeof(int));
    if (!stack) {
        fprintf(stderr, "Error: Failed to allocate stack for EOS traversal\n");
        return 0;
    }

    // Push start state
    stack[stack_top++] = start_state;

    while (stack_top > 0) {
        // Pop from stack
        int state = stack[--stack_top];

        // Bounds check for safety
        if (state < 0 || state >= nfa_state_count) {
            continue;
        }

        // Check if already visited using bitmask
        int word = state / 64;
        int bit = state % 64;
        if (word < VISITED_WORDS && (visited.bits[word] & (1ULL << bit))) {
            continue;
        }
        // Mark as visited
        if (word < VISITED_WORDS) {
            visited.bits[word] |= (1ULL << bit);
        }

        // Check if this state is terminal (EOS target with category)
        if (nfa[state].is_eos_target && nfa[state].category_mask != 0) {
            // Check if this state has NO character transitions (truly terminal)
            bool has_char_trans = false;
            for (int s = 0; s < alphabet_size; s++) {
                if (alphabet[s].is_special) continue;
                if (nfa[state].transitions[s] != -1 || nfa[state].multi_targets[s][0] != '\0') {
                    has_char_trans = true;
                    break;
                }
            }
            if (!has_char_trans) {
                combined_mask |= nfa[state].category_mask;
            }
        }

        // Follow EOS transition if present
        if (eos_symbol >= 0 && nfa[state].transitions[eos_symbol] != -1) {
            int eos_target = nfa[state].transitions[eos_symbol];

            // Grow stack if needed
            if (stack_top >= stack_capacity) {
                stack_capacity *= 2;
                if (stack_capacity > MAX_STATES) {
                    stack_capacity = MAX_STATES;
                }
                int* new_stack = realloc(stack, stack_capacity * sizeof(int));
                if (!new_stack) {
                    fprintf(stderr, "Error: Failed to reallocate stack\n");
                    free(stack);
                    return combined_mask;
                }
                stack = new_stack;
            }

            // Push EOS target if within bounds
            if (eos_target >= 0 && eos_target < nfa_state_count && stack_top < stack_capacity) {
                stack[stack_top++] = eos_target;
            }
        }
    }

    free(stack);
    return combined_mask;
}

// Add DFA state
int dfa_add_state(uint8_t category_mask, int* nfa_states, int nfa_count) {
    if (dfa_state_count >= MAX_STATES) {
        fprintf(stderr, "Error: Maximum DFA states reached\n");
        exit(1);
    }
    int state = dfa_state_count;

    // Check for capture markers in NFA states (stored directly on states)
    uint16_t capture_flags = 0;
    int8_t capture_start_id = -1;
    int8_t capture_end_id = -1;
    int8_t capture_defer_id = -1;
    uint32_t eos_target = 0;

    for (int i = 0; i < nfa_count; i++) {
        int nfa_state = nfa_states[i];
        if (nfa_state < 0 || nfa_state >= nfa_state_count) continue;

        // Check for capture start marker on this NFA state
        if (nfa[nfa_state].capture_start_id >= 0) {
            capture_flags |= DFA_STATE_CAPTURE_START;
            capture_start_id = nfa[nfa_state].capture_start_id;
            DEBUG_PRINT("DFA state %d gets capture_start_id=%d from NFA state %d\n",
                    state, capture_start_id, nfa_state);
        }

        // Check for capture end marker on this NFA state
        if (nfa[nfa_state].capture_end_id >= 0) {
            capture_flags |= DFA_STATE_CAPTURE_END;
            capture_end_id = nfa[nfa_state].capture_end_id;
            DEBUG_PRINT("DFA state %d gets capture_end_id=%d from NFA state %d\n",
                    state, capture_end_id, nfa_state);
        }

        // Check for capture defer marker on this NFA state
        if (nfa[nfa_state].capture_defer_id >= 0) {
            capture_flags |= DFA_STATE_CAPTURE_DEFER;
            capture_defer_id = nfa[nfa_state].capture_defer_id;
            DEBUG_PRINT("DFA state %d gets capture_defer_id=%d from NFA state %d\n",
                    state, capture_defer_id, nfa_state);
        }

        // Check for EOS target marker on this NFA state
        if (nfa[nfa_state].is_eos_target) {
            eos_target = 0;  // Will be resolved during DFA construction
        }
    }
    
    // Store category_mask in bits 8-15, set DFA_STATE_ACCEPTING if category_mask != 0
    dfa[state].flags = (category_mask << 8) | capture_flags;
    if (category_mask != 0) {
        dfa[state].flags |= DFA_STATE_ACCEPTING;
    }
    if (capture_flags != 0) {
        DEBUG_PRINT("State %d has capture flags 0x%x (start_id=%d, end_id=%d, defer_id=%d)\n",
                state, capture_flags, capture_start_id, capture_end_id, capture_defer_id);
    }
    dfa[state].transition_count = 0;
    dfa[state].nfa_state_count = 0;
    dfa[state].capture_start_id = capture_start_id;
    dfa[state].capture_end_id = capture_end_id;
    dfa[state].capture_defer_id = capture_defer_id;
    dfa[state].eos_target = eos_target;
    for (int i = 0; i < nfa_count && i < MAX_STATES; i++) {
        dfa[state].nfa_states[i] = nfa_states[i];
        dfa[state].nfa_state_count++;
    }
    if (state <= 20) {
        DEBUG_PRINT("dfa_add_state(%d): category_mask=0x%02x, nfa_count=%d, nfa_states={", state, category_mask, nfa_count);
        for (int i = 0; i < nfa_count; i++) {
            DEBUG_PRINT("%d(cat=0x%02x,pid=%d)%s", nfa_states[i], nfa[nfa_states[i]].category_mask, nfa[nfa_states[i]].pattern_id, i < nfa_count-1 ? ", " : "");
        }
        DEBUG_PRINT("}\n");
    }
    dfa_state_count++;
    return state;
}

// Compute epsilon closure (follows ANY and EOS transitions)
// CRITICAL FIX: Track how each state was added to the closure
// - States added via character transitions (nfa_move) can have ANY followed
// - States added via EOS transitions can have ANY followed
// - States added via ANY transitions should NOT have ANY followed
// This prevents loop state ANY transitions (like in a((b))+ from state 9)
// from contaminating the closure with states that lead to dead paths.
void epsilon_closure(int* states, int* count, int max_states) {
    // Find symbol IDs once
    int any_symbol = -1;
    int eos_symbol = -1;
    int epsilon_symbol = -1;
    for (int s = 0; s < alphabet_size; s++) {
        if (alphabet[s].start_char == DFA_CHAR_ANY) {
            any_symbol = s;
        }
        if (alphabet[s].start_char == DFA_CHAR_EOS) {
            eos_symbol = s;
        }
        if (alphabet[s].start_char == DFA_CHAR_EPSILON) {
            epsilon_symbol = s;
        }
    }

    // Track how each state was added
    // 0 = original (from character move or initial set)
    // 1 = added via EOS
    // 2 = added via EPSILON
    // 3 = added via ANY (should not have ANY followed)
    int8_t added_via[MAX_STATES];
    for (int i = 0; i < MAX_STATES; i++) {
        added_via[i] = -1;  // Unknown
    }
    for (int i = 0; i < *count; i++) {
        added_via[states[i]] = 0;  // Original states
    }

    int added = 1;
    while (added && *count < max_states) {
        added = 0;
        for (int i = 0; i < *count; i++) {
            int state = states[i];
            if (state < 0 || state >= nfa_state_count) continue;

            // EPSILON transitions can always be followed (for alternation)
            if (epsilon_symbol >= 0 && nfa[state].transitions[epsilon_symbol] != -1) {
                int target = nfa[state].transitions[epsilon_symbol];
                bool found = false;
                for (int j = 0; j < *count; j++) {
                    if (states[j] == target) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    states[*count] = target;
                    added_via[target] = 2;  // Added via EPSILON
                    (*count)++;
                    added = 1;
                }
            }

            // EOS transitions can always be followed
            if (eos_symbol >= 0 && nfa[state].transitions[eos_symbol] != -1) {
                int target = nfa[state].transitions[eos_symbol];
                bool found = false;
                for (int j = 0; j < *count; j++) {
                    if (states[j] == target) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    states[*count] = target;
                    added_via[target] = 1;  // Added via EOS
                    (*count)++;
                    added = 1;
                }
            }

            // ANY transitions: only follow if state was NOT added via ANY or EPSILON
            // This prevents loop states from contaminating the closure
            // States added via EPSILON should not follow ANY to avoid cross-branch contamination
            if (any_symbol >= 0 && added_via[state] != 3 && added_via[state] != 2 &&
                nfa[state].transitions[any_symbol] != -1) {
                int target = nfa[state].transitions[any_symbol];
                bool found = false;
                for (int j = 0; j < *count; j++) {
                    if (states[j] == target) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    states[*count] = target;
                    added_via[target] = 3;  // Added via ANY
                    (*count)++;
                    added = 1;
                }
            }
        }
    }
}

// Move NFA states on symbol
void nfa_move(int* states, int* count, int symbol_id, int max_states) {
    int new_states[MAX_STATES];
    int new_count = 0;

    for (int i = 0; i < *count; i++) {
        int state = states[i];
        if (state < 0 || state >= nfa_state_count) continue;

        // Check first transition
        if (nfa[state].transitions[symbol_id] != -1) {
            int target = nfa[state].transitions[symbol_id];
            bool found = false;
            for (int j = 0; j < new_count; j++) {
                if (new_states[j] == target) {
                    found = true;
                    break;
                }
            }
            if (!found && new_count < max_states) {
                new_states[new_count] = target;
                new_count++;
            }
        }

        // Check additional targets in multi_targets
        if (nfa[state].multi_targets[symbol_id][0] != '\0') {
            char* p = nfa[state].multi_targets[symbol_id];
            while (p != NULL && *p != '\0') {
                if (*p == ',') p++;  // Skip leading comma
                // Use strtol for safer parsing with bounds validation
                char* end;
                long target_long = strtol(p, &end, 10);
                if (end > p && target_long >= 0 && target_long < MAX_STATES) {
                    int target = (int)target_long;
                    bool found = false;
                    for (int j = 0; j < new_count; j++) {
                        if (new_states[j] == target) {
                            found = true;
                            break;
                        }
                    }
                    if (!found && new_count < max_states) {
                        new_states[new_count] = target;
                        new_count++;
                    }
                }
                p = strchr(p, ',');
                if (p) p++;
            }
        }
    }

    for (int i = 0; i < new_count && i < max_states; i++) {
        states[i] = new_states[i];
    }
    *count = new_count;
}

// Convert NFA to DFA
void nfa_to_dfa(void) {
    dfa_init();
    int initial_nfa_states[MAX_STATES];
    initial_nfa_states[0] = 0;
    int initial_count = 1;
    epsilon_closure(initial_nfa_states, &initial_count, MAX_STATES);

    // Compute initial accepting mask - only from states with same pattern_id
    // CRITICAL FIX: The initial state's category_mask should only be set if ALL NFA states
    // in the initial closure belong to the SAME pattern. If states from different patterns
    // are present, we must NOT set the accepting mask (set to 0) to prevent incorrect matches.
    int initial_dominant_pattern = -1;
    bool initial_all_same_pattern = true;
    uint8_t initial_accepting_mask = 0;
    for (int i = 0; i < initial_count; i++) {
        int state = initial_nfa_states[i];
        int pattern_id = nfa[state].pattern_id;

        if (pattern_id < 0) {
            // State has no pattern_id (e.g., fragment or intermediate state)
            continue;
        }
        if (initial_dominant_pattern < 0) {
            initial_dominant_pattern = pattern_id;
        } else if (pattern_id != initial_dominant_pattern) {
            // States from different patterns - don't set accepting mask
            initial_all_same_pattern = false;
            break;
        }
    }
    if (initial_all_same_pattern && initial_dominant_pattern >= 0) {
        for (int i = 0; i < initial_count; i++) {
            initial_accepting_mask |= nfa[initial_nfa_states[i]].category_mask;
        }
    }

    int initial_dfa = dfa_add_state(initial_accepting_mask, initial_nfa_states, initial_count);
    int queue[MAX_STATES];
    int queue_start = 0;
    int queue_end = 1;
    queue[0] = initial_dfa;
    while (queue_start < queue_end) {
        int current_dfa = queue[queue_start];
        queue_start++;
        for (int array_idx = 0; array_idx < alphabet_size; array_idx++) {
            int move_states[MAX_STATES];
            int move_count = 0;
            for (int i = 0; i < dfa[current_dfa].nfa_state_count; i++) {
                move_states[i] = dfa[current_dfa].nfa_states[i];
            }
            move_count = dfa[current_dfa].nfa_state_count;

            // Use the actual symbol_id from the alphabet entry, not the array index
            int symbol_id = alphabet[array_idx].symbol_id;
            nfa_move(move_states, &move_count, symbol_id, MAX_STATES);
            if (move_count == 0) continue;

            // CRITICAL FIX: Save the direct move targets BEFORE epsilon closure
            // This is the key fix for the category isolation bug
            int direct_move_count = move_count;
            int direct_moves[MAX_STATES];
            for (int i = 0; i < move_count; i++) {
                direct_moves[i] = move_states[i];
            }

            // Now do epsilon closure (modifies move_states in place)
            epsilon_closure(move_states, &move_count, MAX_STATES);

            uint8_t move_accepting_mask = 0;

            // Also check EPSILON-CLOSED states for accepting status
            // After epsilon closure, move_states contains states reachable via EPSILON
            // Some of these states might be accepting (have is_eos_target=true)
            // We need to include their categories
            for (int i = 0; i < move_count; i++) {
                int state = move_states[i];
                if (nfa[state].is_eos_target && nfa[state].category_mask != 0) {
                    if (move_accepting_mask == 0) {
                        move_accepting_mask = nfa[state].category_mask;
                    } else if (move_accepting_mask != nfa[state].category_mask) {
                        move_accepting_mask |= nfa[state].category_mask;
                    }
                }
            }

            // Check which of the DIRECT MOVE TARGETS are terminal
            // (States with no character transitions)
            for (int i = 0; i < direct_move_count; i++) {
                int state = direct_moves[i];
                
                // Check if this state has any character transitions (excluding special symbols)
                bool has_char_transition = false;
                for (int s = 0; s < alphabet_size; s++) {
                    if (alphabet[s].is_special) continue;  // Skip EOS, space, etc.
                    if (nfa[state].transitions[s] != -1 || nfa[state].multi_targets[s][0] != '\0') {
                        has_char_transition = true;
                        break;
                    }
                }
                
                // If this move target is terminal, include its category
                // (Terminal means: no char transitions, is EOS target, has category)
                // IMPORTANT: Detect category conflicts - if different categories reach
                // the same state, mark as conflicting (0) to prevent misclassification
                if (!has_char_transition && nfa[state].is_eos_target && nfa[state].category_mask != 0) {
                    if (move_accepting_mask == 0) {
                        move_accepting_mask = nfa[state].category_mask;
                    } else if (move_accepting_mask != nfa[state].category_mask) {
                        move_accepting_mask |= nfa[state].category_mask;
                    }
                }
                
                // Also check EOS transitions from this move target
                // IMPORTANT: For + quantifier, we need to recursively follow EOS chains
                // to find all terminal states reachable via EOS
                
                // Find EOS symbol
                int eos_symbol = -1;
                for (int s = 0; s < alphabet_size; s++) {
                    if (alphabet[s].is_special && alphabet[s].start_char == DFA_CHAR_EOS) {  // EOS symbol
                        eos_symbol = s;
                        break;
                    }
                }
                
                if (eos_symbol >= 0 && nfa[state].transitions[eos_symbol] != -1) {
                    // Use iterative helper to collect all categories from EOS chain
                    uint8_t eos_categories = collect_eos_categories(state, eos_symbol);
                    if (eos_categories != 0) {
                        DEBUG_PRINT("state=%d EOS chain categories=0x%02x\n", state, eos_categories);
                        move_accepting_mask |= eos_categories;
                        DEBUG_PRINT("Added category 0x%02x from EOS chain\n", eos_categories);
                    }
                }
            }
            
            DEBUG_PRINT("direct_move_count=%d, move_accepting_mask=0x%02x\n", direct_move_count, move_accepting_mask);

            // Debug for transitions on 'b' from states 10 and 20
            if (alphabet[array_idx].start_char == 'b' && (current_dfa == 10 || current_dfa == 20)) {
                    DEBUG_PRINT("From DFA state %d on 'b': move_count=%d\n", current_dfa, move_count);
                int final_count = 0;
                for (int i = 0; i < move_count; i++) {
                    int state = move_states[i];
                    bool is_final = nfa[state].is_eos_target && nfa[state].category_mask != 0;
                    if (is_final) {
                        bool has_trans = false;
                        for (int s = 0; s < MAX_SYMBOLS; s++) {
                            if (nfa[state].transitions[s] != -1 || nfa[state].multi_targets[s][0] != '\0') {
                                has_trans = true;
                                break;
                            }
                        }
                        if (!has_trans) {
                            final_count++;
                            DEBUG_PRINT("  State %d: FINAL (cat=0x%02x)\n", state, nfa[state].category_mask);
                        }
                    }
                }
                DEBUG_PRINT("  Final states count: %d\n", final_count);
                DEBUG_PRINT("  move_accepting_mask=0x%02x\n", move_accepting_mask);
            }

            // Find existing DFA state with same set of NFA states
            int existing_state = -1;
            for (int i = 0; i < dfa_state_count; i++) {
                if (dfa[i].nfa_state_count != move_count) continue;

                // CRITICAL FIX: States with different acceptance categories must NOT be merged
                uint8_t existing_cat_mask = (dfa[i].flags >> 8) & 0xFF;
                if (existing_cat_mask != move_accepting_mask) continue;

                bool match = true;
                for (int j = 0; j < move_count; j++) {
                    bool found = false;
                    for (int k = 0; k < dfa[i].nfa_state_count; k++) {
                        if (dfa[i].nfa_states[k] == move_states[j]) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    existing_state = i;
                    break;
                }
            }
            if (existing_state != -1) {
                dfa[current_dfa].transitions[array_idx] = existing_state;
                dfa[current_dfa].transition_count++;
            } else {
                int new_dfa = dfa_add_state(move_accepting_mask, move_states, move_count);
                dfa[current_dfa].transitions[array_idx] = new_dfa;
                dfa[current_dfa].transition_count++;
                if (queue_end < MAX_STATES) {
                    queue[queue_end] = new_dfa;
                    queue_end++;
                }
#if 1
                // Debug for transitions on 'b' from states 10 and 20
                if (alphabet[array_idx].start_char == 'b' && (current_dfa == 10 || current_dfa == 20)) {
                DEBUG_PRINT("From DFA state %d on 'b': move_count=%d\n", current_dfa, move_count);
                    // Check for different categories
                    uint8_t seen_cats[256] = {0};
                    int cat_count = 0;
                    for (int i = 0; i < move_count; i++) {
                        uint8_t state_cat = nfa[move_states[i]].category_mask;
                        if (state_cat != 0) {
                            bool found = false;
                            for (int j = 0; j < cat_count; j++) {
                                if (seen_cats[j] == state_cat) {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found && cat_count < 256) {
                                seen_cats[cat_count++] = state_cat;
                            }
                        }
                    }
                    fprintf(stderr, "  Categories found: %d\n", cat_count);
                    fprintf(stderr, "  move_accepting_mask=0x%02x\n", move_accepting_mask);
                }
#endif
            }
        }
    }
}

// Flatten DFA: convert symbol-based transitions to character-based
void flatten_dfa(void) {
    int start_symbol = 0;
    if (alphabet_size > 0 && alphabet[0].start_char == 0 && alphabet[0].is_special) {
        start_symbol = 1;
    }
    // Find ANY symbol (special with start_char == 0)
    int any_symbol = -1;
    for (int s = 0; s < alphabet_size; s++) {
        if (alphabet[s].is_special && alphabet[s].start_char == 0) {
            any_symbol = s;
            break;
        }
    }
    for (int state = 0; state < dfa_state_count; state++) {
        int new_transitions[256];  // Character-based (0-255)
        bool new_from_any[256];
        int new_count = 0;
        for (int i = 0; i < 256; i++) {
            new_transitions[i] = -1;
            new_from_any[i] = false;
        }
        // FIRST PASS: specific character transitions (higher priority)
        // Skip symbol 0 (ANY) - it's handled in second pass
        for (int s = alphabet_size - 1; s >= start_symbol; s--) {
            if (s == any_symbol) continue;  // Skip ANY in first pass
            if (dfa[state].transitions[s] != -1) {
                int target = dfa[state].transitions[s];
                // Find the alphabet entry for this symbol position
                int start_char = alphabet[s].start_char;
                int end_char = alphabet[s].end_char;
                for (int c = start_char; c <= end_char; c++) {
                    if (c >= 0 && c < 256 && new_transitions[c] == -1) {
                        new_transitions[c] = target;
                        new_from_any[c] = false;
                        new_count++;
                    }
                }
            }
        }
        // SECOND PASS: ANY symbol to fill missing characters
        if (any_symbol >= 0 && dfa[state].transitions[any_symbol] != -1) {
            int any_target = dfa[state].transitions[any_symbol];
            for (int c = 0; c < 256; c++) {
                if (new_transitions[c] == -1) {
                    new_transitions[c] = any_target;
                    new_from_any[c] = true;
                    new_count++;
                }
            }
        }
        for (int i = 0; i < 256; i++) {
            dfa[state].transitions[i] = new_transitions[i];
            dfa[state].transitions_from_any[i] = new_from_any[i];
        }
        dfa[state].transition_count = new_count;
#if 0
        // Debug state 212 transitions
        if (state == 212) {
            DEBUG_PRINT("State 212 transitions: count=%d, transitions={", new_count);
            for (int c = 0; c < 256; c++) {
                if (new_transitions[c] != -1) {
                    fprintf(stderr, "%d->%d ", c, new_transitions[c]);
                }
            }
            fprintf(stderr, "}\n");
        }
#endif
    }
}

// Load NFA file
// Find symbol ID for a character
int find_symbol_id(char c) {
    for (int i = 0; i < alphabet_size; i++) {
        if (c >= alphabet[i].start_char && c <= alphabet[i].end_char) {
            return alphabet[i].symbol_id;
        }
    }
    return -1; // Not found
}

void load_nfa_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        exit(1);
    }
    char first_line[MAX_LINE_LENGTH];
    if (fgets(first_line, sizeof(first_line), file) == NULL) {
        fprintf(stderr, "Error: Empty NFA file\n");
        fclose(file);
        exit(1);
    }
    if (strstr(first_line, "NFA_ALPHABET") == NULL) {
        fprintf(stderr, "Error: Unsupported NFA format. Expected NFA_ALPHABET format.\n");
        fclose(file);
        exit(1);
    }
    rewind(file);
    char line[MAX_LINE_LENGTH];
    char header[64];
    int current_state = -1;
    nfa_init();
    while (fgets(line, sizeof(line), file)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        if (line[0] == '\0') continue;
        if (sscanf(line, "%63s", header) == 1) {
            if (strcmp(header, "NFA_ALPHABET") == 0) {
                continue;
            } else if (strncmp(line, "Identifier:", 11) == 0) {
                char* id_start = line + 11;
                while (*id_start == ' ') id_start++;
                strncpy(pattern_identifier, id_start, 255);
                pattern_identifier[255] = '\0';
            } else if (strstr(header, "AlphabetSize:") == header) {
                sscanf(line, "AlphabetSize: %d", &alphabet_size);
            } else if (strstr(header, "States:") == header) {
                sscanf(line, "States: %d", &nfa_state_count);
            } else if (strstr(header, "Initial:") == header) {
                continue;
            } else if (strstr(header, "Alphabet:") == header) {
                current_state = -2;
            } else if (strstr(header, "State") == header) {
                sscanf(line, "State %d:", &current_state);
            } else if (current_state == -2 && strstr(header, "Symbol") == header) {
                int symbol_id, start_char, end_char;
                char special[16] = "";
                if (sscanf(line, "  Symbol %d: %d-%d (%15[^)]",
                          &symbol_id, &start_char, &end_char, special) >= 3) {
                    if (symbol_id < MAX_SYMBOLS) {
                        alphabet[symbol_id].symbol_id = symbol_id;
                        alphabet[symbol_id].start_char = start_char;
                        alphabet[symbol_id].end_char = end_char;
                        alphabet[symbol_id].is_special = (strcmp(special, "special") == 0);
                    }
                }
            }
        }
        if (current_state >= 0) {
            if (strstr(line, "CategoryMask:") != NULL) {
                unsigned int category_mask;
                sscanf(line, "  CategoryMask: %x", &category_mask);
                nfa[current_state].category_mask = (uint8_t)category_mask;
            } else if (strstr(line, "CaptureStart:") != NULL) {
                int cap_id;
                sscanf(line, "  CaptureStart: %d", &cap_id);
                nfa[current_state].capture_start_id = (int8_t)cap_id;
            } else if (strstr(line, "CaptureEnd:") != NULL) {
                int cap_id;
                sscanf(line, "  CaptureEnd: %d", &cap_id);
                nfa[current_state].capture_end_id = (int8_t)cap_id;
            } else if (strstr(line, "CaptureDefer:") != NULL) {
                int cap_id;
                sscanf(line, "  CaptureDefer: %d", &cap_id);
                nfa[current_state].capture_defer_id = (int8_t)cap_id;
            } else if (strstr(line, "EosTarget:") != NULL) {
                char eos_str[16];
                sscanf(line, "  EosTarget: %15s", eos_str);
                nfa[current_state].is_eos_target = (strcmp(eos_str, "yes") == 0);
            } else if (strstr(line, "PatternId:") != NULL) {
                int pattern_id;
                sscanf(line, "  PatternId: %d", &pattern_id);
                nfa[current_state].pattern_id = (int16_t)pattern_id;
            } else if (strstr(line, "Accepting:") != NULL) {
                // Backward compatibility: old NFA format uses "Accepting: yes/no"
                // Map to CAT_MASK_SAFE (0x01) for accepting states
                char accepting_str[16];
                sscanf(line, "  Accepting: %15s", accepting_str);
                nfa[current_state].category_mask = (strcmp(accepting_str, "yes") == 0) ? 0x01 : 0x00;
            } else if (strstr(line, "Symbol") != NULL) {
                int symbol_id;
                // Parse format: "Symbol %d -> %d[,%d[,%d...]]" or "Symbol %d -> ,%d[,%d...]"
                char* arrow = strstr(line, "->");
                if (arrow != NULL) {
                    if (sscanf(line, "    Symbol %d", &symbol_id) == 1) {
                        char* targets_str = arrow + 2;
                        // Skip leading whitespace
                        while (*targets_str == ' ') targets_str++;

                        // Parse targets separated by commas
                        char* p = targets_str;
                        int target_count = 0;

                        while (p != NULL && *p != '\0' && *p != '\n') {
                            // Find next comma or end
                            char* comma = strchr(p, ',');
                            size_t len = comma ? (size_t)(comma - p) : strlen(p);

                            // Skip trailing spaces
                            while (len > 0 && p[len-1] == ' ') len--;

                            if (len > 0) {
                                char target_str[32];
                                strncpy(target_str, p, len);
                                target_str[len] = '\0';

                                int target = atoi(target_str);
                                if (target >= 0 && target < MAX_STATES) {
                                    if (target_count == 0) {
                                        // First target goes in transitions array
                                        nfa[current_state].transitions[symbol_id] = target;
                                        nfa[current_state].transition_count++;
                                    } else {
                                        // Additional targets go to multi_targets
                                        char num_str[32];
                                        snprintf(num_str, sizeof(num_str), ",%d", target);
                                        size_t current_len = strlen(nfa[current_state].multi_targets[symbol_id]);
                                        if (current_len + strlen(num_str) < sizeof(nfa[current_state].multi_targets[symbol_id])) {
                                            strncat(nfa[current_state].multi_targets[symbol_id], num_str,
                                                    sizeof(nfa[current_state].multi_targets[symbol_id]) - current_len - 1);
                                            nfa[current_state].transition_count++;
                                        }
                                    }
                                    target_count++;
                                }
                            }

                            if (comma) {
                                p = comma + 1;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    fclose(file);
    DEBUG_PRINT("Loaded NFA with %d states and %d symbols from %s\n", nfa_state_count, alphabet_size, filename);
}

// Intermediate rule structure for compression
typedef struct {
    uint8_t type;
    uint8_t min;
    uint8_t max;
    int target_state_index;
} intermediate_rule_t;

// Compress transition table into rules
// Returns number of rules generated
int compress_state_rules(int state_idx, intermediate_rule_t* rules_out) {
    int rule_count = 0;
    int current_target = -1;
    int start_char = -1;
    
    // Iterate 0..256 (256 is end sentinel to flush last range)
    for (int c = 0; c <= 256; c++) {
        int target = (c < 256) ? dfa[state_idx].transitions[c] : -1;
        
        if (target != current_target) {
            if (current_target != -1) {
                // End of a contiguous block for 'current_target'
                // Range is [start_char, c-1]
                rules_out[rule_count].target_state_index = current_target;
                rules_out[rule_count].min = (uint8_t)start_char;
                rules_out[rule_count].max = (uint8_t)(c - 1);
                
                if (start_char == c - 1) {
                    rules_out[rule_count].type = DFA_RULE_LITERAL;
                } else {
                    rules_out[rule_count].type = DFA_RULE_RANGE;
                }
                rule_count++;
            }
            current_target = target;
            start_char = c;
        }
    }
    return rule_count;
}

// Write DFA to binary file (Version 5 format with compact rules)
void write_dfa_file(const char* filename) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot create file %s\n", filename);
        return;
    }

    // Step 1: Pre-calculate compression rules
    // We need to know the total size before allocating the binary blob
    intermediate_rule_t* state_rules[MAX_STATES];
    int state_rule_counts[MAX_STATES];
    size_t total_rules = 0;

    for (int i = 0; i < dfa_state_count; i++) {
        // Allocate worst-case: 256 rules per state
        state_rules[i] = malloc(256 * sizeof(intermediate_rule_t));
        if (!state_rules[i]) {
            fprintf(stderr, "Error: Memory allocation failed for rule compression\n");
            // Cleanup previous
            for (int j = 0; j < i; j++) free(state_rules[j]);
            fclose(file);
            return;
        }
        state_rule_counts[i] = compress_state_rules(i, state_rules[i]);
        total_rules += state_rule_counts[i];
    }

    DEBUG_PRINT("Total rules generated: %zu (vs %d states)\n", total_rules, dfa_state_count);

    // Step 2: Calculate binary layout
    size_t id_len = strlen(pattern_identifier);
    if (id_len > 255) id_len = 255;
    
    // Header size: 19 bytes base + identifier length
    size_t header_size = 19 + id_len;
    
    size_t states_size = dfa_state_count * sizeof(dfa_state_t);
    size_t rules_size = total_rules * sizeof(dfa_rule_t);
    size_t dfa_size = header_size + states_size + rules_size;
    
    DEBUG_PRINT("Binary Size: Header=%zu, States=%zu, Rules=%zu, Total=%zu bytes\n",
                header_size, states_size, rules_size, dfa_size);

    dfa_t* dfa_struct = malloc(dfa_size);
    if (dfa_struct == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for binary DFA\n");
        for (int i = 0; i < dfa_state_count; i++) free(state_rules[i]);
        fclose(file);
        return;
    }
    memset(dfa_struct, 0, dfa_size);

    // Step 3: Fill Header
    dfa_struct->magic = DFA_MAGIC;
    dfa_struct->version = DFA_VERSION; // V5
    dfa_struct->state_count = dfa_state_count;
    dfa_struct->initial_state = header_size;
    dfa_struct->accepting_mask = 0;
    dfa_struct->flags = 0;
    dfa_struct->identifier_length = (uint8_t)id_len;
    if (id_len > 0) {
        memcpy(dfa_struct->identifier, pattern_identifier, id_len);
    }

    // Step 4: Setup Pointers
    dfa_state_t* states = (dfa_state_t*)((char*)dfa_struct + header_size);
    dfa_rule_t* rules_blob = (dfa_rule_t*)((char*)states + states_size);
    
    // Step 5: Fill States and Rules
    size_t current_rule_offset = header_size + states_size; // Absolute offset in file
    uint32_t accepting_mask = 0;
    size_t global_rule_idx = 0;

    for (int i = 0; i < dfa_state_count; i++) {
        // Fill State Info
        states[i].transition_count = state_rule_counts[i]; // Reusing field name for rule count
        
        if (state_rule_counts[i] > 0) {
            states[i].transitions_offset = (uint32_t)current_rule_offset;
        } else {
            states[i].transitions_offset = 0;
        }
        
        states[i].flags = dfa[i].flags;
        states[i].capture_start_id = dfa[i].capture_start_id;
        states[i].capture_end_id = dfa[i].capture_end_id;
        states[i].capture_defer_id = dfa[i].capture_defer_id;
        states[i].eos_target = dfa[i].eos_target;

        // Accepting mask update
        if (dfa[i].flags & 0xFF00) {
            accepting_mask |= (1 << i);
        }

        // Fill Rules for this state
        for (int r = 0; r < state_rule_counts[i]; r++) {
            intermediate_rule_t* src = &state_rules[i][r];
            dfa_rule_t* dst = &rules_blob[global_rule_idx++];
            
            dst->type = src->type;
            dst->min = (char)src->min;
            dst->max = (char)src->max;
            dst->padding = 0;
            
            // Calculate absolute target offset
            int target_idx = src->target_state_index;
            size_t target_offset = header_size + (size_t)target_idx * sizeof(dfa_state_t);
            dst->target = (uint32_t)target_offset;
        }
        
        current_rule_offset += state_rule_counts[i] * sizeof(dfa_rule_t);
    }
    
    dfa_struct->accepting_mask = accepting_mask;

    // Step 6: Write to file
    size_t written = fwrite(dfa_struct, 1, dfa_size, file);
    if (written != dfa_size) {
        fprintf(stderr, "Error: Failed to write complete DFA file\n");
    }

    // Step 7: Cleanup
    free(dfa_struct);
    for (int i = 0; i < dfa_state_count; i++) free(state_rules[i]);
    fclose(file);
    DEBUG_PRINT("Wrote DFA V5 to %s\n", filename);
}

// Main function
int main(int argc, char* argv[]) {
    bool minimize = true;  // Enabled by default
    
    // Check for flags
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            flag_verbose = true;
            // Remove flag from arguments
            for (int j = i; j < argc - 1; j++) {
                argv[j] = argv[j + 1];
            }
            argc--;
            i--;
        } else if (strcmp(argv[i], "--minimize") == 0) {
            minimize = true;
            // Remove flag from arguments
            for (int j = i; j < argc - 1; j++) {
                argv[j] = argv[j + 1];
            }
            argc--;
            i--;
        } else if (strcmp(argv[i], "--no-minimize") == 0) {
            minimize = false;
            // Remove flag from arguments
            for (int j = i; j < argc - 1; j++) {
                argv[j] = argv[j + 1];
            }
            argc--;
            i--;
        }
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [options] <nfa_file> [dfa_file]\n", argv[0]);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  -v, --verbose    Enable verbose output\n");
        fprintf(stderr, "  --minimize       Enable DFA state minimization (default)\n");
        fprintf(stderr, "  --no-minimize    Disable DFA state minimization\n");
        return 1;
    }
    const char* nfa_file = argv[1];
    const char* dfa_file = argc > 2 ? argv[2] : "readonlybox.dfa";
    DEBUG_PRINT("NFA to DFA Converter (Version 3)\n");
    DEBUG_PRINT("================================\n\n");
    load_nfa_file(nfa_file);
    DEBUG_PRINT("Converting NFA to DFA...\n");
    nfa_to_dfa();
    DEBUG_PRINT("Flattening DFA (symbol -> character)...\n");
    flatten_dfa();
    
    // Minimization phase (optional)
    if (minimize) {
        DEBUG_PRINT("Minimizing DFA...\n");
        dfa_minimize_set_verbose(flag_verbose);
        dfa_state_count = dfa_minimize(dfa, dfa_state_count);
        dfa_minimize_stats_t stats;
        dfa_minimize_get_stats(&stats);
        if (flag_verbose) {
            fprintf(stderr, "Minimization: %d -> %d states (removed %d, %.1f%% reduction)\n",
                   stats.initial_states, stats.final_states, stats.states_removed,
                   stats.initial_states > 0 ? (100.0 * stats.states_removed / stats.initial_states) : 0.0);
        }
    }
    
    write_dfa_file(dfa_file);
    DEBUG_PRINT("\nConversion complete!\n");
    return 0;
}

