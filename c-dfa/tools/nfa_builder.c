#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include "../include/dfa_types.h"
#include "../include/nfa.h"

/**
 * Advanced NFA Builder with Alphabet Support
 *
 * This tool builds NFA (Non-deterministic Finite Automata) from advanced
 * command specifications using an optimized alphabet to reduce DFA state space.
 */

// Character class definition
typedef struct {
    int start_char;
    int end_char;
    int symbol_id;
    bool is_special;
} char_class_t;

// Negated transition structure
typedef struct {
    int target_state;
    char excluded_chars[MAX_SYMBOLS];
    int excluded_count;
} negated_transition_t;

// NFA State with termination tags and negated transitions
typedef struct {
    bool accepting;
    char* tags[MAX_TAGS];          // Termination tags
    int tag_count;
    int transitions[MAX_SYMBOLS];  // -1 = no transition, otherwise state index
    int transition_count;
    
    // Negated transitions: target state + excluded characters
    negated_transition_t negated_transitions[MAX_SYMBOLS];
    int negated_transition_count;
} nfa_state_t;

// State signature for on-the-fly minimization
typedef struct StateSignature {
    uint64_t signature;
    int state_index;
    struct StateSignature* next; // For hash table collision handling
} StateSignature;

// Command pattern with metadata
typedef struct {
    char pattern[MAX_LINE_LENGTH];
    char category[64];
    char subcategory[64];
    char operations[256];
    char action[32];
    int category_id;
    int subcategory_id;
} command_pattern_t;

// Global variables
static nfa_state_t nfa[MAX_STATES];
static command_pattern_t patterns[MAX_PATTERNS];
static char_class_t alphabet[MAX_SYMBOLS];
static int alphabet_size = 0;
static int nfa_state_count = 0;
static int pattern_count = 0;
static int current_pattern_index = 0;  // Track which pattern we're building
static StateSignature* signature_table[SIGNATURE_TABLE_SIZE] = {NULL};

// Category IDs
enum {
    CAT_SAFE = 0,
    CAT_CAUTION,
    CAT_MODIFYING,
    CAT_DANGEROUS,
    CAT_NETWORK,
    CAT_ADMIN,
    CAT_BUILD,
    CAT_CONTAINER,
    CAT_COUNT
};

const char* category_names[CAT_COUNT] = {
    "safe", "caution", "modifying", "dangerous",
    "network", "admin", "build", "container"
};

// Initialize NFA
void nfa_init(void) {
    for (int i = 0; i < MAX_STATES; i++) {
        nfa[i].accepting = false;
        nfa[i].tag_count = 0;
        for (int j = 0; j < MAX_TAGS; j++) {
            nfa[i].tags[j] = NULL;
        }
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            nfa[i].transitions[j] = -1;
        }
        nfa[i].transition_count = 0;
        
        // Initialize negated transitions
        nfa[i].negated_transition_count = 0;
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            nfa[i].negated_transitions[j].target_state = -1;
            nfa[i].negated_transitions[j].excluded_count = 0;
            for (int k = 0; k < MAX_SYMBOLS; k++) {
                nfa[i].negated_transitions[j].excluded_chars[k] = 0;
            }
        }
    }
    nfa_state_count = 1; // State 0 is initial state
}

// Negated transition helper functions
bool is_char_excluded(negated_transition_t* neg_trans, char test_char) {
    for (int i = 0; i < neg_trans->excluded_count; i++) {
        if (neg_trans->excluded_chars[i] == test_char) {
            return true;
        }
    }
    return false;
}

bool can_add_to_negated_transition(negated_transition_t* neg_trans, char new_char) {
    // Check if we have space and the char isn't already excluded
    return neg_trans->excluded_count < MAX_SYMBOLS && 
           !is_char_excluded(neg_trans, new_char);
}

negated_transition_t* find_negated_transition_for_target(nfa_state_t* state, int target_state) {
    for (int i = 0; i < state->negated_transition_count; i++) {
        if (state->negated_transitions[i].target_state == target_state) {
            return &state->negated_transitions[i];
        }
    }
    return NULL;
}

bool should_use_negation(int from_state, int to_state, char input_char) {
    // More aggressive heuristic: use negation more frequently
    // 1. Always use if we already have a negated transition to this target
    // 2. Use if we're adding a second transition to the same target
    // 3. Use for common patterns that benefit from negation
    
    nfa_state_t* state = &nfa[from_state];
    
    // If we already have a negated transition to this target, always use it
    if (find_negated_transition_for_target(state, to_state) != NULL) {
        return true;
    }
    
    // Count how many transitions go to this target
    int transitions_to_target = 0;
    for (int c = 0; c < MAX_SYMBOLS; c++) {
        if (state->transitions[c] == to_state) {
            transitions_to_target++;
        }
    }
    
    // Use negation if we'd have 2 or more transitions to the same target
    // This is more aggressive than the previous threshold of 3
    return transitions_to_target >= 1; // Use negation for any duplicate target
}

void add_negated_transition(int from_state, int to_state, char excluded_char) {
    nfa_state_t* state = &nfa[from_state];
    
    // Check if we already have a negated transition to this target
    negated_transition_t* existing_neg_trans = find_negated_transition_for_target(state, to_state);
    
    if (existing_neg_trans != NULL) {
        // Add to existing negated transition
        if (can_add_to_negated_transition(existing_neg_trans, excluded_char)) {
            existing_neg_trans->excluded_chars[existing_neg_trans->excluded_count++] = excluded_char;
            return;
        }
    }
    
    // Create new negated transition
    if (state->negated_transition_count < MAX_SYMBOLS) {
        negated_transition_t* new_neg_trans = &state->negated_transitions[state->negated_transition_count++];
        new_neg_trans->target_state = to_state;
        new_neg_trans->excluded_chars[0] = excluded_char;
        new_neg_trans->excluded_count = 1;
    }
}

// Load alphabet from file
void load_alphabet(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open alphabet file %s\n", filename);
        exit(1);
    }

    char line[MAX_LINE_LENGTH];
    alphabet_size = 0;

    while (fgets(line, sizeof(line), file)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }

        int symbol_id, start_char, end_char;
        char special[16] = "";

        if (sscanf(line, "%d %d %d %15s", &symbol_id, &start_char, &end_char, special) >= 3) {
            if (alphabet_size >= MAX_SYMBOLS) {
                fprintf(stderr, "Error: Maximum symbols reached\n");
                exit(1);
            }

            fprintf(stderr, "DEBUG load_alphabet: line='%s', symbol_id=%d, start_char=%d, end_char=%d, special='%s'\n",
                    line, symbol_id, start_char, end_char, special);

            alphabet[alphabet_size].symbol_id = symbol_id;
            alphabet[alphabet_size].start_char = start_char;
            alphabet[alphabet_size].end_char = end_char;
            alphabet[alphabet_size].is_special = (strcmp(special, "special") == 0);
            fprintf(stderr, "DEBUG load_alphabet: is_special=%d\n", alphabet[alphabet_size].is_special);
            alphabet_size++;
        }
    }

    fclose(file);
    printf("Loaded alphabet with %d symbols from %s\n", alphabet_size, filename);
}

// Find symbol ID for a character
int find_symbol_id(char c) {
    for (int i = 0; i < alphabet_size; i++) {
        if (c >= alphabet[i].start_char && c <= alphabet[i].end_char) {
            return alphabet[i].symbol_id;
        }
    }
    return -1; // Not found
}

// Forward declarations for minimization functions
static uint64_t compute_state_signature(int state);
static int find_equivalent_state(uint64_t signature, int current_state);
static void add_state_to_signature_table(int state, uint64_t signature);
static int nfa_finalize_state(int state);

// Add NFA state with on-the-fly minimization
// NOTE: We do NOT compute signature here because transitions haven't been added yet.
// The caller must call nfa_finalize_state() after adding all transitions.
int nfa_add_state_with_minimization(bool accepting) {
    // First create the state normally
    int new_state = nfa_state_count;
    nfa[new_state].accepting = accepting;
    nfa[new_state].tag_count = 0;
    for (int j = 0; j < MAX_TAGS; j++) {
        nfa[new_state].tags[j] = NULL;
    }
    for (int j = 0; j < MAX_SYMBOLS; j++) {
        nfa[new_state].transitions[j] = -1;
    }
    nfa[new_state].transition_count = 0;
    nfa_state_count++;

    // DON'T compute signature here - transitions aren't added yet!
    // The caller will call nfa_finalize_state() after adding all transitions.

    return new_state;
}

// Finalize state after all transitions have been added
// NOTE: State minimization is DISABLED to prevent states from different patterns
// from being incorrectly merged. Each pattern keeps its own distinct states.
int nfa_finalize_state(int state) {
    // Compute signature for this state (NOW transitions are set)
    uint64_t signature = compute_state_signature(state);

    // Check if an equivalent state already exists
    int equivalent_state = find_equivalent_state(signature, state);

    if (equivalent_state != -1) {
        // DISABLED: Don't merge states - we want each pattern to have distinct states
        // This prevents patterns like "git log" and "git status" from sharing
        // intermediate states, which causes incorrect transitions.
        //
        // If we wanted to re-enable minimization, we'd uncomment this:
        // return equivalent_state;

        // Instead, just add this state to the signature table without merging
    }

    // Add this state to signature table
    add_state_to_signature_table(state, signature);

    return state;
}

// Simple string duplication function
static char* my_strdup(const char* str) {
    if (str == NULL) return NULL;
    size_t len = strlen(str) + 1;
    char* copy = malloc(len);
    if (copy) {
        memcpy(copy, str, len);
    }
    return copy;
}

// Hash function for signature table
static unsigned int hash_signature(uint64_t signature) {
    return (unsigned int)(signature % SIGNATURE_TABLE_SIZE);
}

// Compute state signature for equivalence detection
// IMPORTANT: Includes current_pattern_index to prevent states from different patterns
// from being merged, even if they have the same structure
static uint64_t compute_state_signature(int state) {
    uint64_t signature = 0;

    // Include pattern index in signature - this ensures states from different patterns
    // are never considered equivalent, even if they have identical structure
    signature = signature * 31 + current_pattern_index;

    // Include accepting status in signature
    if (nfa[state].accepting) {
        signature |= 0x8000000000000000ULL;
    }

    // Include tags in signature (simple hash of tag strings)
    for (int i = 0; i < nfa[state].tag_count; i++) {
        if (nfa[state].tags[i] != NULL) {
            const char* tag = nfa[state].tags[i];
            while (*tag) {
                signature = signature * 31 + *tag;
                tag++;
            }
        }
    }

    // Include transitions in signature
    for (int s = 0; s < MAX_SYMBOLS; s++) {
        if (nfa[state].transitions[s] != -1) {
            signature = signature * 31 + s;
            signature = signature * 31 + nfa[state].transitions[s];
        }
    }

    return signature;
}

// Find equivalent state using signature
static int find_equivalent_state(uint64_t signature, int current_state) {
    unsigned int hash = hash_signature(signature);
    StateSignature* entry = signature_table[hash];

    while (entry != NULL) {
        if (entry->signature == signature) {
            // Found a state with matching signature, verify it's truly equivalent
            int candidate_state = entry->state_index;

            // Check if states are truly equivalent
            if (nfa[current_state].accepting == nfa[candidate_state].accepting &&
                nfa[current_state].tag_count == nfa[candidate_state].tag_count) {

                // Check tags
                bool tags_match = true;
                for (int i = 0; i < nfa[current_state].tag_count; i++) {
                    if (strcmp(nfa[current_state].tags[i], nfa[candidate_state].tags[i]) != 0) {
                        tags_match = false;
                        break;
                    }
                }

                // Check transitions
                bool transitions_match = true;
                for (int s = 0; s < MAX_SYMBOLS; s++) {
                    if (nfa[current_state].transitions[s] != nfa[candidate_state].transitions[s]) {
                        transitions_match = false;
                        break;
                    }
                }

                if (tags_match && transitions_match) {
                    return candidate_state; // States are equivalent
                }
            }
        }
        entry = entry->next;
    }

    return -1; // No equivalent state found
}

// Add state to signature table
static void add_state_to_signature_table(int state, uint64_t signature) {
    unsigned int hash = hash_signature(signature);

    StateSignature* new_entry = malloc(sizeof(StateSignature));
    if (new_entry == NULL) {
        return; // Memory allocation failed
    }

    new_entry->signature = signature;
    new_entry->state_index = state;
    new_entry->next = signature_table[hash];
    signature_table[hash] = new_entry;
}

// Add tag to state
void nfa_add_tag(int state, const char* tag) {
    if (state < 0 || state >= nfa_state_count) {
        return;
    }

    if (nfa[state].tag_count >= MAX_TAGS) {
        return;
    }

    nfa[state].tags[nfa[state].tag_count] = my_strdup(tag);
    nfa[state].tag_count++;
}

// Add NFA transition using symbol ID
void nfa_add_transition(int from, int to, int symbol_id) {
    if (from < 0 || from >= nfa_state_count || to < 0 || to >= nfa_state_count) {
        fprintf(stderr, "Error: Invalid state index\n");
        exit(1);
    }

    if (symbol_id < 0 || symbol_id >= MAX_SYMBOLS) {
        fprintf(stderr, "Error: Invalid symbol ID\n");
        exit(1);
    }

    // Check if we should use a negated transition instead
    if (should_use_negation(from, to, symbol_id)) {
        add_negated_transition(from, to, symbol_id);
    } else {
        // Use regular transition
        nfa[from].transitions[symbol_id] = to;
        nfa[from].transition_count++;
    }
}

// Parse category ID
int parse_category(const char* name) {
    for (int i = 0; i < CAT_COUNT; i++) {
        if (strcmp(name, category_names[i]) == 0) {
            return i;
        }
    }
    return CAT_SAFE; // Default to safe
}

// Parse advanced pattern
void parse_advanced_pattern(const char* line) {
    // Format: [category:subcategory:operations] pattern -> action

    char category[64] = "safe";
    char subcategory[64] = "";
    char operations[256] = "";
    char action[32] = "allow";
    char pattern[MAX_LINE_LENGTH] = "";

    // Skip leading whitespace
    while (*line == ' ' || *line == '\t') line++;

    // Parse category section
    if (*line == '[') {
        line++;
        char* end = strchr(line, ']');
        if (end != NULL) {
            char category_section[256];
            strncpy(category_section, line, end - line);
            category_section[end - line] = '\0';

            // Parse category:subcategory:operations
            char* tok = strtok(category_section, ":");
            if (tok != NULL) {
                strncpy(category, tok, sizeof(category) - 1);
            }

            tok = strtok(NULL, ":");
            if (tok != NULL) {
                strncpy(subcategory, tok, sizeof(subcategory) - 1);
            }

            tok = strtok(NULL, ":");
            if (tok != NULL) {
                strncpy(operations, tok, sizeof(operations) - 1);
            }

            line = end + 1;
        }
    }

    // Skip whitespace after category
    while (*line == ' ' || *line == '\t') line++;

    // Parse pattern
    char* arrow = strstr(line, "->");
    if (arrow != NULL) {
        strncpy(pattern, line, arrow - line);
        pattern[arrow - line] = '\0';

        // Trim whitespace
        char* end = pattern + strlen(pattern) - 1;
        while (end >= pattern && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }

        // Parse action
        arrow += 2; // Skip "->"
        while (*arrow == ' ' || *arrow == '\t') arrow++;
        strncpy(action, arrow, sizeof(action) - 1);

        // Trim action
        end = action + strlen(action) - 1;
        while (end >= action && (*end == ' ' || *end == '\t' || *end == '\n')) {
            *end = '\0';
            end--;
        }
    } else {
        // No action specified, use entire line as pattern
        strncpy(pattern, line, sizeof(pattern) - 1);
    }

    // Skip empty patterns
    if (pattern[0] == '\0') {
        return;
    }

    // Store pattern
    if (pattern_count < MAX_PATTERNS) {
        strncpy(patterns[pattern_count].pattern, pattern, MAX_LINE_LENGTH - 1);
        strncpy(patterns[pattern_count].category, category, sizeof(category) - 1);
        strncpy(patterns[pattern_count].subcategory, subcategory, sizeof(subcategory) - 1);
        strncpy(patterns[pattern_count].operations, operations, sizeof(operations) - 1);
        strncpy(patterns[pattern_count].action, action, sizeof(action) - 1);
        patterns[pattern_count].category_id = parse_category(category);
        pattern_count++;
    }

    // Set the pattern index for this NFA construction
    // This prevents states from different patterns from being merged
    current_pattern_index = pattern_count;
    
    fprintf(stderr, "DEBUG: Processing pattern %d: %s\n", pattern_count, pattern);

    // Build NFA for this pattern with alphabet support
    // For pattern 0 (first pattern), start fresh from state 0
    // For subsequent patterns, try to share states for common prefixes
    int current_state = 0;
    int divergence_point = 0;  // Point where this pattern diverges from existing paths
    int prefix_end_state = 0;  // The state at the end of the shared prefix
    int pattern_len = strlen(pattern);
    bool in_quote = false;
    
    // For the first pattern, build a simple chain
    // For subsequent patterns, find the longest common prefix with existing paths
    if (pattern_count > 0) {
        // Find how much of this pattern can share existing states
        int temp_state = 0;
        int shared_length = 0;
        
        for (int i = 0; i < pattern_len; i++) {
            char c = pattern[i];
            
            // Skip whitespace handling for prefix matching
            if (c == ' ' && !in_quote) {
                int symbol_id = find_symbol_id(DFA_CHAR_NORMALIZING_SPACE);
                if (symbol_id == -1) symbol_id = find_symbol_id(' ');
                if (nfa[temp_state].transitions[symbol_id] != -1) {
                    temp_state = nfa[temp_state].transitions[symbol_id];
                    shared_length++;
                } else {
                    break;
                }
            } else if (c == '\\' && i + 1 < pattern_len) {
                i++;
                char escaped_char = pattern[i];
                int symbol_id = find_symbol_id(escaped_char);
                if (symbol_id == -1) break;
                if (nfa[temp_state].transitions[symbol_id] != -1) {
                    temp_state = nfa[temp_state].transitions[symbol_id];
                    shared_length++;
                } else {
                    break;
                }
            } else if (c == '\'' && !in_quote) {
                in_quote = true;
                continue;
            } else if (c == '\'' && in_quote) {
                in_quote = false;
                continue;
            } else {
                // Regular character
                int symbol_id = find_symbol_id(c);
                if (symbol_id == -1) break;
                if (nfa[temp_state].transitions[symbol_id] != -1) {
                    temp_state = nfa[temp_state].transitions[symbol_id];
                    shared_length++;
                } else {
                    break;
                }
            }
        }
        
        if (shared_length > 0) {
            // Found shared prefix - continue from the end of the shared prefix
            // The normal loop will add new transitions from there
            divergence_point = shared_length;
            prefix_end_state = temp_state;
            current_state = temp_state;

            fprintf(stderr, "DEBUG: Pattern %d shares prefix of length %d, continuing from state %d\n",
                    pattern_count, shared_length, prefix_end_state);
        }
    }

    // Reset quote state after prefix matching
    in_quote = false;

    for (int i = divergence_point; i < pattern_len; i++) {
        char c = pattern[i];

        // Handle quoted verbatim sections
        if (c == '\'' && !in_quote) {
            // Start of quoted section - skip the quote character
            in_quote = true;
            continue;
        } else if (c == '\'' && in_quote) {
            // End of quoted section - skip the quote character
            in_quote = false;
            continue;
        }

        // Handle escape sequences
        if (c == '\\' && i + 1 < pattern_len) {
            i++;
            char escaped_char = pattern[i];

            // Handle special escape sequences
            switch (escaped_char) {
                case 't': escaped_char = '\t'; break;
                case 'n': escaped_char = '\n'; break;
                case 'r': escaped_char = '\r'; break;
                case 's': escaped_char = ' '; break;  // space
                case '\'': escaped_char = '\''; break; // single quote
                case '\\': escaped_char = '\\'; break; // backslash
                // Add more escape sequences as needed
            }

            int symbol_id = find_symbol_id(escaped_char);
            if (symbol_id == -1) {
                // Character not in alphabet, skip or handle error
                continue;
            }

            int new_state = nfa_add_state_with_minimization(false);
            nfa_add_transition(current_state, new_state, symbol_id);
            nfa_finalize_state(new_state);
            current_state = new_state;
            continue;
        }

        // Handle whitespace based on quote context
        if (c == ' ' && !in_quote) {
            // Normalizing whitespace - matches any sequence of 1+ space/tab chars
            int symbol_id = find_symbol_id(DFA_CHAR_NORMALIZING_SPACE);
            if (symbol_id == -1) {
                symbol_id = find_symbol_id(' '); // Fallback to regular space
            }

            int new_state = nfa_add_state_with_minimization(false);
            nfa_add_transition(current_state, new_state, symbol_id);
            // Add self-loop for additional whitespace characters
            nfa_add_transition(new_state, new_state, symbol_id);
            current_state = new_state;
        } else if (c == ' ' && in_quote) {
            // Verbatim whitespace - matches exactly one space character
            int symbol_id = find_symbol_id(DFA_CHAR_VERBATIM_SPACE);
            if (symbol_id == -1) {
                symbol_id = find_symbol_id(' '); // Fallback to regular space
            }

            int new_state = nfa_add_state_with_minimization(false);
            nfa_add_transition(current_state, new_state, symbol_id);
            current_state = new_state;
        } else if (c == '*') {
            // Wildcard: matches one character and can continue matching more
            // Key: After *, we need to be able to match the next char in pattern
            int any_symbol_id = find_symbol_id(DFA_CHAR_ANY);
            if (any_symbol_id == -1) {
                fprintf(stderr, "Error: ANY symbol not found in alphabet\n");
                exit(1);
            }

            fprintf(stderr, "DEBUG WILDCARD: pattern='%s', current_state=%d, any_symbol_id=%d\n",
                    pattern, current_state, any_symbol_id);

            // Create state that can both:
            // 1. Consume another char (self-loop on ANY)
            // 2. Continue to next pattern char (transition will be added by next char)
            int star_state = nfa_add_state_with_minimization(false);
            fprintf(stderr, "DEBUG WILDCARD: created star_state=%d\n", star_state);

            // Self-loop for consuming more chars
            nfa_add_transition(star_state, star_state, any_symbol_id);
            fprintf(stderr, "DEBUG WILDCARD: added self-loop on star_state %d for ANY\n", star_state);

            // Transition from current to star_state (consumes one char)
            nfa_add_transition(current_state, star_state, any_symbol_id);
            fprintf(stderr, "DEBUG WILDCARD: added transition from %d to %d on ANY\n", current_state, star_state);

            // Stay at star_state so next char adds transition from here
            current_state = star_state;
            fprintf(stderr, "DEBUG WILDCARD: current_state now=%d\n", current_state);
        } else if (c == '?') {
            // Single character wildcard
            int symbol_id = find_symbol_id(DFA_CHAR_ANY);
            if (symbol_id == -1) {
                fprintf(stderr, "Error: ANY symbol not found in alphabet\n");
                exit(1);
            }

            int new_state = nfa_add_state_with_minimization(false);
            nfa_add_transition(current_state, new_state, symbol_id);
            current_state = new_state;
        } else {
            // Regular character
            int symbol_id = find_symbol_id(c);
            if (symbol_id == -1) {
                // Character not in alphabet, skip or handle error
                continue;
            }

            int new_state = nfa_add_state_with_minimization(false);
            nfa_add_transition(current_state, new_state, symbol_id);
            current_state = new_state;
        }
    }

    // Mark final state as accepting and add tags
    // Add transition on EOS marker to a new accepting state
    // This ensures the pattern only accepts when the full input is consumed
    int eos_symbol_id = find_symbol_id(DFA_CHAR_EOS);
    fprintf(stderr, "DEBUG EOS: pattern='%s', current_state=%d, DFA_CHAR_EOS=%d, eos_symbol_id=%d\n",
            pattern, current_state, DFA_CHAR_EOS, eos_symbol_id);
    if (eos_symbol_id == -1) {
        // EOS not in alphabet - fall back to direct accepting
        fprintf(stderr, "DEBUG EOS: Using fallback accepting state\n");
        nfa[current_state].accepting = true;
        nfa_add_tag(current_state, category);
        if (subcategory[0] != '\0') {
            nfa_add_tag(current_state, subcategory);
        }
        if (operations[0] != '\0') {
            nfa_add_tag(current_state, operations);
        }
        nfa_add_tag(current_state, action);
        nfa_finalize_state(current_state);
    } else {
        // Create accepting state with EOS transition
        fprintf(stderr, "DEBUG EOS: Creating accepting state, transition from %d on symbol %d\n",
                current_state, eos_symbol_id);
        int accepting_state = nfa_add_state_with_minimization(true);
        nfa_add_transition(current_state, accepting_state, eos_symbol_id);

        // Add tags to the accepting state
        nfa_add_tag(accepting_state, category);
        if (subcategory[0] != '\0') {
            nfa_add_tag(accepting_state, subcategory);
        }
        if (operations[0] != '\0') {
            nfa_add_tag(accepting_state, operations);
        }
        nfa_add_tag(accepting_state, action);

        // Finalize states
        nfa_finalize_state(current_state);
        nfa_finalize_state(accepting_state);
    }
}

// Read advanced command specification file
void read_advanced_spec_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        exit(1);
    }

    char line[MAX_LINE_LENGTH];
    int line_num = 0;

    nfa_init();

    while (fgets(line, sizeof(line), file)) {
        line_num++;

        // Remove newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }

        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        // Parse and add pattern
        parse_advanced_pattern(line);
    }

    fclose(file);

    printf("Read %d patterns from %s\n", pattern_count, filename);
}

// Write NFA to file (for nfa2dfa to process)
void write_nfa_file(const char* filename) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot create file %s\n", filename);
        return;
    }

    // Write header
    fprintf(file, "NFA_ALPHABET\n");
    fprintf(file, "AlphabetSize: %d\n", alphabet_size);
    fprintf(file, "States: %d\n", nfa_state_count);
    fprintf(file, "Initial: 0\n\n");

    // Write alphabet mapping
    fprintf(file, "Alphabet:\n");
    for (int i = 0; i < alphabet_size; i++) {
        fprintf(file, "  Symbol %d: %d-%d",
                alphabet[i].symbol_id,
                (int)alphabet[i].start_char,
                (int)alphabet[i].end_char);
        if (alphabet[i].is_special) {
            fprintf(file, " (special)");
        }
        fprintf(file, "\n");
    }
    fprintf(file, "\n");

    // Write states
    for (int i = 0; i < nfa_state_count; i++) {
        fprintf(file, "State %d:\n", i);
        fprintf(file, "  Accepting: %s\n", nfa[i].accepting ? "yes" : "no");

        if (nfa[i].tag_count > 0) {
            fprintf(file, "  Tags:");
            for (int j = 0; j < nfa[i].tag_count; j++) {
                fprintf(file, " %s", nfa[i].tags[j]);
            }
            fprintf(file, "\n");
        }

        fprintf(file, "  Transitions: %d\n", nfa[i].transition_count);

        for (int s = 0; s < MAX_SYMBOLS; s++) {
            if (nfa[i].transitions[s] != -1) {
                fprintf(file, "    Symbol %d -> %d\n", s, nfa[i].transitions[s]);
            }
        }

        // Write negated transitions
        for (int n = 0; n < nfa[i].negated_transition_count; n++) {
            negated_transition_t* neg_trans = &nfa[i].negated_transitions[n];
            fprintf(file, "    NotSymbol ");
            
            // Write excluded characters
            for (int e = 0; e < neg_trans->excluded_count; e++) {
                if (e > 0) fprintf(file, ",");
                fprintf(file, "%d", neg_trans->excluded_chars[e]);
            }
            fprintf(file, " -> %d\n", neg_trans->target_state);
        }

        fprintf(file, "\n");
    }

    fclose(file);
    printf("Wrote NFA with %d states and %d symbols to %s\n", nfa_state_count, alphabet_size, filename);
}

// Cleanup
void cleanup(void) {
    for (int i = 0; i < nfa_state_count; i++) {
        for (int j = 0; j < nfa[i].tag_count; j++) {
            free(nfa[i].tags[j]);
        }
    }
}

// Main function
int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <alphabet_file> <spec_file> [output.nfa]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Advanced NFA Builder with Alphabet Support\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  %s alphabet.map commands_advanced.txt readonlybox.nfa\n", argv[0]);
        return 1;
    }

    const char* alphabet_file = argv[1];
    const char* spec_file = argv[2];
    const char* output_file = argc > 3 ? argv[3] : "readonlybox.nfa";

    printf("Advanced NFA Builder with Alphabet Support\n");
    printf("===========================================\n\n");

    // Load alphabet
    load_alphabet(alphabet_file);

    // Read specification
    read_advanced_spec_file(spec_file);

    // Write NFA file
    write_nfa_file(output_file);

    // Cleanup
    cleanup();

    printf("\nDone!\n");
    printf("Next step: Run nfa2dfa_with_alphabet to convert NFA to DFA\n");
    printf("  nfa2dfa_with_alphabet %s readonlybox.dfa\n", output_file);

    return 0;
}