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

// Category bitmask constants (8 categories, one bit each)
#define CAT_MASK_SAFE       0x01
#define CAT_MASK_CAUTION    0x02
#define CAT_MASK_MODIFYING  0x04
#define CAT_MASK_DANGEROUS  0x08
#define CAT_MASK_NETWORK    0x10
#define CAT_MASK_ADMIN      0x20
#define CAT_MASK_BUILD      0x40
#define CAT_MASK_CONTAINER  0x80

// NFA State with category bitmask for 8-way parallel acceptance
typedef struct {
    uint8_t category_mask;           // Bitmask of accepting categories (0-7)
    bool is_eos_target;              // This state can accept via EOS transition
    char* tags[MAX_TAGS];             // Termination tags
    int tag_count;
    int transitions[MAX_SYMBOLS];     // -1 = no transition, otherwise state index
    int transition_count;
    char multi_targets[MAX_SYMBOLS][256];  // For storing multiple targets as CSV strings

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

// Fragment storage for expansion
#define MAX_FRAGMENTS 100
#define MAX_FRAGMENT_NAME 64
#define MAX_FRAGMENT_VALUE 512

#define MAX_CAPTURES 16
#define MAX_CAPTURE_NAME 32

typedef struct {
    char name[MAX_FRAGMENT_NAME];
    char value[MAX_FRAGMENT_VALUE];
} fragment_t;

static fragment_t fragments[MAX_FRAGMENTS];
static int fragment_count = 0;

// Capture name to ID mapping
typedef struct {
    char name[MAX_CAPTURE_NAME];
    int id;
    bool used;
} capture_mapping_t;

static capture_mapping_t capture_map[MAX_CAPTURES];
static int capture_count = 0;
static int capture_stack[MAX_CAPTURES];
static int capture_stack_depth = 0;

// For + quantifier on single-char fragments: communicates the char from parse_rdp_fragment to parse_rdp_postfix
static char pending_loop_char = '\0';
static int pending_loop_state = -1;

// Find a fragment by name
static const char* find_fragment(const char* name) {
    for (int i = 0; i < fragment_count; i++) {
        if (strcmp(fragments[i].name, name) == 0) {
            return fragments[i].value;
        }
    }
    return NULL;
}

// Normalize fragment name: convert single colon to double colon for namespace separator
// e.g., "git:DIGIT" -> "git::DIGIT"
// Only normalizes if the name contains a single colon not followed by another colon
static void normalize_fragment_name(char* name) {
    // Check if already normalized (contains ::)
    if (strstr(name, "::") != NULL) {
        return; // Already has double colon, no normalization needed
    }
    // Find the first single colon (not followed by another colon)
    for (int i = 0; name[i] != '\0'; i++) {
        if (name[i] == ':' && name[i + 1] != ':') {
            // Shift remaining characters right by one position to make room
            int len = strlen(name);
            if (len + 1 < MAX_FRAGMENT_NAME) {
                for (int k = len; k > i; k--) {
                    name[k] = name[k - 1];
                }
                // Insert double colon
                name[i] = ':';
                name[i + 1] = ':';
            }
            break;
        }
    }
}

// Initialize NFA
void nfa_init(void) {
    for (int i = 0; i < MAX_STATES; i++) {
        nfa[i].category_mask = 0;
        nfa[i].is_eos_target = false;
        nfa[i].tag_count = 0;
        for (int j = 0; j < MAX_TAGS; j++) {
            nfa[i].tags[j] = NULL;
        }
        for (int j = 0; j < MAX_SYMBOLS; j++) {
            nfa[i].transitions[j] = -1;
            nfa[i].multi_targets[j][0] = '\0';  // Initialize multi-targets
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
    fragment_count = 0; // Reset fragments
    capture_count = 0;
    capture_stack_depth = 0;
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

            alphabet[alphabet_size].symbol_id = symbol_id;
            alphabet[alphabet_size].start_char = start_char;
            alphabet[alphabet_size].end_char = end_char;
            alphabet[alphabet_size].is_special = (strcmp(special, "special") == 0);
            alphabet_size++;
        }
    }

    fclose(file);
    printf("Loaded alphabet with %d symbols from %s\n", alphabet_size, filename);
}

// Find symbol ID for a character
int find_symbol_id(unsigned char c) {
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

// Forward declarations for capture functions
static int parse_capture_start(const char* pattern, int* pos, int start_state);
static int parse_capture_end(const char* pattern, int* pos, int start_state);
static int get_capture_id(const char* name);

// Add NFA state with on-the-fly minimization
// NOTE: We do NOT compute signature here because transitions haven't been added yet.
// The caller must call nfa_finalize_state() after adding all transitions.
int nfa_add_state_with_category(uint8_t category_mask) {
    // First create the state normally
    int new_state = nfa_state_count;
    nfa[new_state].category_mask = category_mask;
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

// Backward-compatible wrapper
int nfa_add_state_with_minimization(bool accepting) {
    return nfa_add_state_with_category(accepting ? CAT_MASK_SAFE : 0);
}

// Finalize state after all transitions have been added
// Enables state minimization for non-tagged states to allow prefix sharing
int nfa_finalize_state(int state) {
    // Compute signature for this state (NOW transitions are set)
    uint64_t signature = compute_state_signature(state);

    // Check if an equivalent state already exists
    int equivalent_state = find_equivalent_state(signature, state);

    if (equivalent_state != -1 && equivalent_state != state) {
        // Found an equivalent state - redirect all transitions to it
        // First, find all transitions pointing to 'state' and update them
        for (int s = 0; s < nfa_state_count; s++) {
            for (int t = 0; t < MAX_SYMBOLS; t++) {
                if (nfa[s].transitions[t] == state) {
                    nfa[s].transitions[t] = equivalent_state;
                }
            }
        }
        return equivalent_state;
    }

    // No equivalent found - add this state to signature table
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
// HOWEVER: For non-tagged states (intermediate states), we allow sharing to enable
// prefix sharing between patterns like "git log --oneline" and "git log --graph"
static uint64_t compute_state_signature(int state) {
    uint64_t signature = 0;

    // Only include pattern index if this state has tags (i.e., it's an accepting state
    // or has category/operation info). This allows intermediate states to be shared.
    if (nfa[state].tag_count > 0) {
        signature = signature * 31 + current_pattern_index;
    }

    // Include category_mask in signature (8-bit category bits)
    if (nfa[state].category_mask != 0) {
        signature |= 0x8000000000000000ULL;
        signature = signature * 31 + nfa[state].category_mask;
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
            if (nfa[current_state].category_mask == nfa[candidate_state].category_mask &&
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
// For State 0, if a transition already exists, create an intermediate dispatch state
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
        return;
    }

    // For State 0, store multiple targets per symbol
    if (from == 0) {
        if (nfa[0].transitions[symbol_id] == -1) {
            // First transition on this symbol - store in transitions array
            nfa[0].transitions[symbol_id] = to;
            nfa[0].transition_count++;
        } else if (nfa[0].transitions[symbol_id] != to) {
            // Additional transition - append to multi_targets
            char existing[256];
            sprintf(existing, "%d", nfa[0].transitions[symbol_id]);

            // Check if target already exists
            if (strstr(existing, ",") != NULL ||
                (nfa[0].transitions[symbol_id] != to &&
                 strstr(nfa[0].multi_targets[symbol_id], ",") == NULL &&
                 nfa[0].transitions[symbol_id] != to)) {

                // Append to multi_targets
                char new_target[32];
                sprintf(new_target, ",%d", to);

                if (strlen(nfa[0].multi_targets[symbol_id]) + strlen(new_target) < 255) {
                    strcat(nfa[0].multi_targets[symbol_id], new_target);
                    nfa[0].transition_count++;
                }
            }
        }
        return;
    }

    // Use regular transition for non-State-0
    nfa[from].transitions[symbol_id] = to;
    nfa[from].transition_count++;
}

// ============================================================================
// Capture Support
// ============================================================================
//
// Capture Syntax:
//   - <capname>pattern</capname>: capture named 'capname' around pattern
//   - Multiple </capname> alternatives allowed in alternations
//   - Each </capname> closes the same capture
//
// Examples:
//   cat <filename>((SAFE::FILENAME))+</filename>
//   git log -n <count>((git::DIGIT))+</count>
//   <cmd>git|svn|hg</cmd> <op>status|log</op>

// Get or create capture ID from name
static int get_capture_id(const char* name) {
    // Check if already registered
    for (int i = 0; i < capture_count; i++) {
        if (strcmp(capture_map[i].name, name) == 0) {
            return capture_map[i].id;
        }
    }
    
    // Register new capture
    if (capture_count >= MAX_CAPTURES) {
        fprintf(stderr, "Error: Maximum captures (%d) reached\n", MAX_CAPTURES);
        return -1;
    }
    
    strncpy(capture_map[capture_count].name, name, MAX_CAPTURE_NAME - 1);
    capture_map[capture_count].name[MAX_CAPTURE_NAME - 1] = '\0';
    capture_map[capture_count].id = capture_count;
    capture_map[capture_count].used = true;
    
    return capture_count++;
}

// Check if current position starts a capture end tag
static bool is_capture_end(const char* pattern, int pos, char* cap_name) {
    if (pattern[pos] != '<' || pattern[pos + 1] != '/') {
        return false;
    }
    
    // Find the closing >
    int j = pos + 2;
    while (pattern[j] != '\0' && pattern[j] != '>') {
        j++;
    }
    
    if (pattern[j] != '>') {
        return false;
    }
    
    // Extract capture name
    int name_len = j - (pos + 2);
    if (name_len >= MAX_CAPTURE_NAME) {
        return false;
    }
    
    strncpy(cap_name, &pattern[pos + 2], name_len);
    cap_name[name_len] = '\0';
    
    return true;
}

// Check if current position starts a capture start tag
static bool is_capture_start(const char* pattern, int pos, char* cap_name) {
    if (pattern[pos] != '<') {
        return false;
    }
    
    // Skip </ which is end tag
    if (pattern[pos + 1] == '/') {
        return false;
    }
    
    // Find the closing >
    int j = pos + 1;
    while (pattern[j] != '\0' && pattern[j] != '>') {
        j++;
    }
    
    if (pattern[j] != '>') {
        return false;
    }
    
    // Extract capture name
    int name_len = j - (pos + 1);
    if (name_len >= MAX_CAPTURE_NAME) {
        return false;
    }
    
    strncpy(cap_name, &pattern[pos + 1], name_len);
    cap_name[name_len] = '\0';
    
    return true;
}

// Parse capture start tag and emit CAPTURE_START transition
static int parse_capture_start(const char* pattern, int* pos, int start_state) {
    char cap_name[MAX_CAPTURE_NAME];
    if (!is_capture_start(pattern, *pos, cap_name)) {
        return start_state;
    }
    
    int cap_id = get_capture_id(cap_name);
    if (cap_id < 0) {
        return start_state;
    }
    
    // Create a state for the capture start
    int cap_state = nfa_add_state_with_minimization(false);
    
    // Push capture ID onto stack
    capture_stack[capture_stack_depth++] = cap_id;
    
    // Emit CAPTURE_START transition: CAPTURE_START followed by capture ID
    int start_sid = find_symbol_id(DFA_CHAR_CAPTURE_START);
    if (start_sid != -1) {
        nfa_add_transition(start_state, cap_state, start_sid);
    }
    
    // Add capture ID as a special symbol (0xF2 + capture_id)
    int capture_id_char = 0xF2 + cap_id;
    int id_sid = find_symbol_id(capture_id_char);
    if (id_sid != -1) {
        nfa_add_transition(cap_state, cap_state, id_sid);
    }
    
    // Skip past the tag
    while (pattern[*pos] != '\0' && pattern[*pos] != '>') {
        (*pos)++;
    }
    if (pattern[*pos] == '>') {
        (*pos)++;
    }
    
    return cap_state;
}

// Parse capture end tag and emit CAPTURE_END transition
static int parse_capture_end(const char* pattern, int* pos, int start_state) {
    char cap_name[MAX_CAPTURE_NAME];
    if (!is_capture_end(pattern, *pos, cap_name)) {
        return start_state;
    }
    
    int cap_id = get_capture_id(cap_name);
    if (cap_id < 0) {
        return start_state;
    }
    
    // Create a state for the capture end
    int cap_state = nfa_add_state_with_minimization(false);
    
    // Pop capture ID from stack (verify it matches)
    if (capture_stack_depth > 0) {
        capture_stack_depth--;
    }
    
    // Emit CAPTURE_END transition
    int end_sid = find_symbol_id(DFA_CHAR_CAPTURE_END);
    if (end_sid != -1) {
        nfa_add_transition(start_state, cap_state, end_sid);
    }
    
    // Add capture ID as a special symbol (0xF2 + capture_id)
    int capture_id_char = 0xF2 + cap_id;
    int id_sid = find_symbol_id(capture_id_char);
    if (id_sid != -1) {
        nfa_add_transition(cap_state, cap_state, id_sid);
    }
    
    // Skip past the tag
    while (pattern[*pos] != '\0' && pattern[*pos] != '>') {
        (*pos)++;
    }
    if (pattern[*pos] == '>') {
        (*pos)++;
    }
    
    return cap_state;
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

// ============================================================================
// Recursive Descent Pattern Parser
// ============================================================================
//
// Pattern Syntax:
//   - Literal character: matches itself
//   - \x: escaped character (matches x literally)
//   - 'x': quoted character (matches x literally)
//   - [abc]: character class (matches any one of a, b, or c)
//   - [a-z]: character range (matches any character from a to z)
//   - *: zero or more of preceding element
//   - +: one or more of preceding element
//   - ?: zero or one of preceding element
//   - (expr): grouping
//   - a|b|c: alternation (matches a or b or c)
//   - Space normalizes to [ \t]+ (one or more whitespace)
//   - ((namespace::name)): fragment reference (expands to predefined pattern)
//   - ((namespace::name))+ : fragment reference with one-or-more quantifier
//
// Character classes use | for alternation, e.g., [a|b|c] means a OR b OR c
// To match literal | outside character classes, escape it as \|
//
// Grammar (recursive descent):
//   pattern      ::= alternation
//   alternation  ::= sequence ('|' sequence)*
//   sequence     ::= element+
//   element      ::= primary quantifier?
//   primary      ::= char | escaped | quoted | class | group | fragment
//   quantifier   ::= '*' | '+' | '?'
//   char         ::= any non-special character
//   escaped      ::= '\' any_char
//   quoted       ::= '\'' char '\''
//   class        ::= '[' class_body ']'
//   group        ::= '(' pattern ')'
//   fragment     ::= '(' '(' NAME ('::' NAME)? ')' ')'
//   class_body   ::= alternation (within class)

static int parse_rdp_element(const char* pattern, int* pos, int start_state);
static int parse_rdp_class(const char* pattern, int* pos, int start_state);
static int parse_rdp_fragment(const char* pattern, int* pos, int start_state);
static int parse_rdp_postfix(const char* pattern, int* pos, int start_state);
static int parse_rdp_sequence(const char* pattern, int* pos, int start_state);
static int parse_rdp_alternation(const char* pattern, int* pos, int start_state);

// Parse fragment reference like ((SAFE::FILENAME)) or ((FILENAME))
// The fragment value is treated as a pattern and parsed recursively
// Returns the end state of the fragment, having connected start_state to it
static int parse_rdp_fragment(const char* pattern, int* pos, int start_state) {
    // Check for fragment reference ((name::subname)) or ((name))
    if (pattern[*pos] != '(' || pattern[*pos + 1] != '(') {
        return start_state;
    }

    size_t j = *pos + 2;

    // Find the end of fragment reference ))
    while (pattern[j] != '\0' && !(pattern[j] == ')' && pattern[j + 1] == ')')) {
        j++;
    }

    // Check for proper closing
    if (pattern[j] != ')' || pattern[j + 1] != ')') {
        fprintf(stderr, "WARNING: Malformed fragment reference at position %d\n", *pos);
        return start_state;
    }

    // Extract fragment name
    char frag_name[MAX_FRAGMENT_NAME];
    size_t name_len = j - (*pos + 2);
    if (name_len >= sizeof(frag_name)) {
        fprintf(stderr, "WARNING: Fragment name too long at position %d\n", *pos);
        *pos = j + 2;
        return start_state;
    }

    strncpy(frag_name, &pattern[*pos + 2], name_len);
    frag_name[name_len] = '\0';

    // fprintf(stderr, "DEBUG: Looking up fragment (raw): '%s'\n", frag_name);

    // Normalize fragment name (convert single colon to double colon)
    normalize_fragment_name(frag_name);

    // fprintf(stderr, "DEBUG: Looking up fragment (normalized): '%s'\n", frag_name);

    // Look up fragment
    const char* frag_value = find_fragment(frag_name);
    if (frag_value == NULL) {
        fprintf(stderr, "WARNING: Fragment '%s' not found, skipping\n", frag_name);
        *pos = j + 2;
        return start_state;
    }

    // Create a clean start state for the fragment
    int frag_start = nfa_add_state_with_minimization(false);

    // Add transition from start_state to frag_start using first char of fragment value
    if (frag_value[0] != '\0') {
        int first_sid = find_symbol_id(frag_value[0]);
        if (first_sid != -1) {
            nfa_add_transition(start_state, frag_start, first_sid);
        }

        // Check if this is a single-character fragment (for + quantifier optimization)
        if (frag_value[1] == '\0') {
            // Single-char fragment: remember the char for + quantifier
            pending_loop_char = frag_value[0];
            pending_loop_state = frag_start;
            // fprintf(stderr, "DEBUG: Single-char fragment '%s'='%c' (sid=%d), pending_loop_state=%d, returns frag_start=%d\n", frag_name, frag_value[0], first_sid, pending_loop_state, frag_start);
        } else {
            // fprintf(stderr, "DEBUG: Multi-char fragment '%s'='%s', NOT single-char\n", frag_name, frag_value);
        }
    }

    // Parse the fragment value starting from frag_start
    int frag_pos = 0;
    int frag_end = parse_rdp_alternation(frag_value, &frag_pos, frag_start);

    // For + quantifier: store the fragment's end state BEFORE adding EOS transition
    // pending_loop_char was set above for single-char fragments
    // pending_loop_state should be the END of the fragment (frag_end)
    if (pending_loop_char != '\0') {
        pending_loop_state = frag_end;
        // fprintf(stderr, "DEBUG: Fragment parsed, pending_loop_state set to frag_end=%d (was frag_start=%d)\n", pending_loop_state, frag_start);
    }

    // Add EOS transition to make it a proper accepting state
    int eos_sid = find_symbol_id(DFA_CHAR_EOS);
    if (eos_sid != -1) {
        int accepting = nfa_add_state_with_minimization(false);
        nfa_add_transition(frag_end, accepting, eos_sid);
        nfa[accepting].is_eos_target = true;  // This state can accept via EOS
        nfa_finalize_state(frag_end);
        nfa_finalize_state(accepting);
        frag_end = accepting;
    }

    *pos = j + 2; // Skip past the fragment reference

    // Return frag_start - the sequence parser will handle transitions
    return frag_start;
}

static int parse_rdp_class(const char* pattern, int* pos, int start_state) {
    int class_state = nfa_add_state_with_minimization(false);

    (*pos)++; // Skip opening [

    // Check for negation like [^abc]
    bool negated = false;
    if (pattern[*pos] == '^') {
        negated = true;
        (*pos)++;
    }

    // Collect all characters/alternatives in the class
    char alt_chars[256];
    int alt_count = 0;

    while (pattern[*pos] != '\0' && pattern[*pos] != ']') {
        if (pattern[*pos] == '\\' && pattern[*pos + 1] != '\0') {
            // Escaped character
            alt_chars[alt_count++] = pattern[*pos + 1];
            *pos += 2;
        } else if (pattern[*pos] == '|' || pattern[*pos] == ' ') {
            // Skip alternation markers and spaces within class
            (*pos)++;
        } else if (pattern[*pos] == '-' && alt_count > 0 &&
                   isalnum(alt_chars[alt_count - 1]) &&
                   isalnum(pattern[*pos + 1])) {
            // Range: previous char to next char
            char start_c = alt_chars[alt_count - 1];
            char end_c = pattern[*pos + 1];
            alt_chars[alt_count - 1] = start_c; // Keep start
            // Add range characters
            for (char c = start_c + 1; c <= end_c && alt_count < 250; c++) {
                alt_chars[alt_count++] = c;
            }
            *pos += 2;
        } else if (pattern[*pos] != ']') {
            alt_chars[alt_count++] = pattern[*pos];
            (*pos)++;
        }
    }

    // Add transitions for each unique character
    bool seen[256] = {false};
    for (int i = 0; i < alt_count; i++) {
        unsigned char uc = (unsigned char)alt_chars[i];
        if (!seen[uc]) {
            seen[uc] = true;
            int sid = find_symbol_id(alt_chars[i]);
            if (sid != -1) {
                nfa_add_transition(start_state, class_state, sid);
            }
        }
    }

    if (pattern[*pos] == ']') {
        (*pos)++; // Skip closing ]
    }

    nfa_finalize_state(class_state);
    return class_state;
}

// Parse primary element: char, escaped, quoted, class, group, or capture tag
static int parse_rdp_element(const char* pattern, int* pos, int start_state) {
    char c = pattern[*pos];

    // Check for capture start tag <name>
    char cap_name[MAX_CAPTURE_NAME];
    if (is_capture_start(pattern, *pos, cap_name)) {
        return parse_capture_start(pattern, pos, start_state);
    }

    // Check for capture end tag </name>
    if (is_capture_end(pattern, *pos, cap_name)) {
        return parse_capture_end(pattern, pos, start_state);
    }

    switch (c) {
        case '\\':
            // Escaped character
            if (pattern[*pos + 1] != '\0') {
                char ec = pattern[*pos + 1];
                int sid = find_symbol_id(ec);
                if (sid != -1) {
                    int new_state = nfa_add_state_with_minimization(false);
                    nfa_add_transition(start_state, new_state, sid);
                    int finalized_state = nfa_finalize_state(new_state);
                    *pos += 2;
                    return finalized_state;
                }
                *pos += 2;
            } else {
                (*pos)++;
            }
            break;

        case '\'':
            // Quoted character
            (*pos)++;
            if (pattern[*pos] != '\0' && pattern[*pos] != '\'') {
                char qc = pattern[*pos];
                int sid = find_symbol_id(qc);
                if (sid != -1) {
                    int new_state = nfa_add_state_with_minimization(false);
                    nfa_add_transition(start_state, new_state, sid);
                    int finalized_state = nfa_finalize_state(new_state);
                    (*pos)++;
                    return finalized_state;
                }
                (*pos)++;
            } else if (pattern[*pos] == '\'') {
                (*pos)++; // Skip empty ''
            }
            break;

        case '[':
            return parse_rdp_class(pattern, pos, start_state);

        case '(':
            // Check for fragment reference ((name::subname))
            if (pattern[*pos + 1] == '(') {
                return parse_rdp_fragment(pattern, pos, start_state);
            }
            // Regular grouping
            (*pos)++;
            return parse_rdp_alternation(pattern, pos, start_state);

        default:
            if (c != ' ' && c != '\t' && c != '\0') {
                // Special handling for * as wildcard (matches any argument)
                if (c == '*') {
                    int any_sid = find_symbol_id(DFA_CHAR_ANY);
                    if (any_sid != -1) {
                        int star_state = nfa_add_state_with_minimization(false);
                        nfa_add_transition(start_state, star_state, any_sid);
                        nfa_add_transition(star_state, star_state, any_sid);
                        int finalized_star = nfa_finalize_state(star_state);
                        (*pos)++;
                        return finalized_star;
                    }
                }
                int sid = find_symbol_id(c);
                if (sid != -1) {
                    int new_state = nfa_add_state_with_minimization(false);
                    nfa_add_transition(start_state, new_state, sid);
                    int finalized_state = nfa_finalize_state(new_state);
                    (*pos)++;
                    return finalized_state;
                }
            }
            (*pos)++;
            break;
    }

    return start_state;
}

// Parse postfix quantifier: * + ?
static int parse_rdp_postfix(const char* pattern, int* pos, int start_state) {
    int current = parse_rdp_element(pattern, pos, start_state);

    while (pattern[*pos] != '\0') {
        char op = pattern[*pos];

        if (op == '*') {
            (*pos)++;
            int any_sid = find_symbol_id(DFA_CHAR_ANY);
            if (any_sid == -1) return current;

            int star_state = nfa_add_state_with_minimization(false);
            nfa_add_transition(current, star_state, any_sid);
            nfa_add_transition(star_state, star_state, any_sid);
            int finalized_star = nfa_finalize_state(star_state);
            current = finalized_star;

        } else if (op == '+') {
            (*pos)++;

            // For + quantifier: fragment's end state becomes the loop entry
            // The pattern X+ means: X followed by zero or more X
            // Structure: current (from prev element) --frag--> frag_end (loop entry)
            //            frag_end --char--> frag_end (loop)
            //            frag_end --EOS--> accepting (exit)

            // pending_loop_char is set by parse_rdp_fragment for single-char fragments
            // pending_loop_state is the fragment's end state (frag_end)

            if (pending_loop_char != '\0' && pending_loop_state != -1) {
                int char_sid = find_symbol_id(pending_loop_char);
                int eos_sid = find_symbol_id(DFA_CHAR_EOS);

                if (char_sid != -1 && eos_sid != -1) {
                    // frag_end (pending_loop_state) becomes the loop entry
                    // Add loop transition: frag_end --char--> frag_end
                    nfa_add_transition(pending_loop_state, pending_loop_state, char_sid);

                    // Create accepting state
                    int accepting = nfa_add_state_with_minimization(true);
                    nfa_add_transition(pending_loop_state, accepting, eos_sid);
                    nfa[pending_loop_state].is_eos_target = true;

                    nfa_finalize_state(pending_loop_state);
                    nfa_finalize_state(accepting);

                    // fprintf(stderr, "DEBUG: + quantifier: pending_loop_state=%d becomes loop entry, char='%c', accepting=%d\n", pending_loop_state, pending_loop_char, accepting);

                    // Return accepting as the final state
                    current = accepting;
                }

                // Clear the pending loop info
                pending_loop_char = '\0';
                pending_loop_state = -1;
            } else {
                // No pending loop state (no fragment with + quantifier)
                // Fall back to ANY-based loop for complex patterns
                int any_sid = find_symbol_id(DFA_CHAR_ANY);
                int eos_sid = find_symbol_id(DFA_CHAR_EOS);
                if (any_sid == -1 || eos_sid == -1) return current;

                // current is the end of the previous element
                // We need to loop on current
                int star_state = nfa_add_state_with_minimization(false);
                nfa_add_transition(current, star_state, any_sid);
                nfa_add_transition(star_state, star_state, any_sid);

                int accepting = nfa_add_state_with_minimization(true);
                nfa_add_transition(star_state, accepting, eos_sid);
                nfa[accepting].is_eos_target = true;

                nfa_finalize_state(star_state);
                nfa_finalize_state(accepting);

                current = accepting;
            }

        } else if (op == '?') {
            (*pos)++;
            // Optional - for now just continue (would need parallel path for proper support)

        } else {
            break;
        }
    }

    return current;
}

// Parse sequence of elements (concatenation)
static int parse_rdp_sequence(const char* pattern, int* pos, int start_state) {
    int current = start_state;

    while (pattern[*pos] != '\0' && pattern[*pos] != ')' && pattern[*pos] != '|') {
        if (pattern[*pos] == ' ' || pattern[*pos] == '\t') {
            // Normalizing whitespace
            int sid = find_symbol_id(DFA_CHAR_NORMALIZING_SPACE);
            if (sid == -1) sid = find_symbol_id(' ');

            int ws_state = nfa_add_state_with_minimization(false);
            nfa_add_transition(current, ws_state, sid);
            nfa_add_transition(ws_state, ws_state, sid);
            int finalized_ws = nfa_finalize_state(ws_state);
            current = finalized_ws;
            (*pos)++;
        } else {
            current = parse_rdp_postfix(pattern, pos, current);
        }
    }

    return current;
}

// Parse alternation: sequence ('|' sequence)*
static int parse_rdp_alternation(const char* pattern, int* pos, int start_state) {
    // Parse first alternative
    int first_end = parse_rdp_sequence(pattern, pos, start_state);

    // Check for alternation operator
    if (pattern[*pos] == '|') {
        // Create merge state for alternation
        int merge_state = nfa_add_state_with_minimization(false);
        int finalized_first = nfa_finalize_state(first_end);

        // Connect first branch to merge via ANY (since we don't have epsilon)
        int any_sid = find_symbol_id(DFA_CHAR_ANY);
        if (any_sid != -1) {
            nfa_add_transition(finalized_first, merge_state, any_sid);
        }

        // Parse remaining alternatives
        while (pattern[*pos] == '|') {
            (*pos)++; // Skip |
            int branch_end = parse_rdp_sequence(pattern, pos, start_state);
            int finalized_branch = nfa_finalize_state(branch_end);

            if (any_sid != -1) {
                nfa_add_transition(finalized_branch, merge_state, any_sid);
            }
        }

        int finalized_merge = nfa_finalize_state(merge_state);
        return finalized_merge;
    }

    // Close paren if present
    if (pattern[*pos] == ')') {
        (*pos)++;
    }

    int finalized_end = nfa_finalize_state(first_end);
    return finalized_end;
}

// Main entry point: parse pattern and build NFA
static void parse_pattern_full(const char* pattern, const char* category,
                               const char* subcategory, const char* operations,
                               const char* action) {
    int pos = 0;

    // Find entry state - try to share prefix with existing patterns
    int start_state;
    int pattern_start_pos = 0;

    // fprintf(stderr, "DEBUG: parse_pattern_full '%s': nfa_state_count=%d, pattern[0]='%c' (sid=%d)\n", pattern, nfa_state_count, pattern[0], find_symbol_id(pattern[0]));

    if (nfa_state_count > 1 && pattern[0] != '\0') {
        // Try to find a common prefix with existing NFA paths
        int shared_state = 0;
        int shared_pos = 0;

        int first_char_sid = find_symbol_id(pattern[0]);

        // Check if this is a single-character symbol (not a range)
        // For ranges like 'a'-'z', we can't safely use prefix sharing because
        // the transition might have been built for a different character in the range
        bool is_single_char_symbol = (first_char_sid != -1 &&
                                       alphabet[first_char_sid].start_char == alphabet[first_char_sid].end_char);

        if (first_char_sid != -1 && nfa[0].transitions[first_char_sid] != -1 && is_single_char_symbol) {
            // Collect all target states for this transition (handles multi-target transitions)
            int targets[100];
            int target_count = 0;
            targets[target_count++] = nfa[0].transitions[first_char_sid];
            // Check for additional targets in multi_targets
            if (nfa[0].multi_targets[first_char_sid][0] != '\0') {
                char* p = nfa[0].multi_targets[first_char_sid];
                while (p != NULL && *p != '\0') {
                    if (*p == ',') p++;
                    int target = atoi(p);
                    if (target > 0 && target < MAX_STATES) {
                        targets[target_count++] = target;
                    }
                    p = strchr(p, ',');
                    if (p) p++;
                }
            }

            // Try following each target to find longest common prefix
            int best_shared_state = -1;
            int best_shared_pos = 0;

            for (int t = 0; t < target_count; t++) {
                int curr_state = targets[t];
                int curr_pos = 1;

                while (curr_pos < (int)strlen(pattern)) {
                    int c = pattern[curr_pos];
                    int sid = find_symbol_id(c);
                    int nsid = -1;

                    // For space/tab, also check NORMALIZING_SPACE as fallback
                    if (c == ' ' || c == '\t') {
                        nsid = find_symbol_id(DFA_CHAR_NORMALIZING_SPACE);
                    }

                    // Check if either the direct symbol or NORMALIZING_SPACE has a transition
                    int next_state = -1;
                    if (sid != -1 && nfa[curr_state].transitions[sid] != -1) {
                        next_state = nfa[curr_state].transitions[sid];
                    } else if (nsid != -1 && nfa[curr_state].transitions[nsid] != -1) {
                        next_state = nfa[curr_state].transitions[nsid];
                    }

                    if (next_state == -1) {
                        break;
                    }

                    curr_state = next_state;
                    curr_pos++;
                }

                // Track the best (longest) match
                if (curr_pos > best_shared_pos) {
                    best_shared_pos = curr_pos;
                    best_shared_state = curr_state;
                }
            }

            if (best_shared_pos > 1) {
                // Found common prefix - start from there
                shared_state = best_shared_state;
                shared_pos = best_shared_pos;
                start_state = shared_state;
                pattern_start_pos = shared_pos;
            } else {
                // No common prefix - create new start state
                start_state = nfa_add_state_with_minimization(false);
                nfa_add_transition(0, start_state, first_char_sid);
                pattern_start_pos = 1;  // Skip first character (already consumed)
            }
        } else {
            // First character has no transition from state 0, or it's a range symbol
            // Create new start state
            start_state = nfa_add_state_with_minimization(false);
            if (first_char_sid != -1) {
                nfa_add_transition(0, start_state, first_char_sid);
                pattern_start_pos = 1;  // Skip first character (already consumed)
            }
        }
    } else {
        // First pattern - use state 0 as start
        start_state = 0;
    }

    // Parse the remaining pattern starting from pattern_start_pos
    char remaining[512];
    strncpy(remaining, pattern + pattern_start_pos, sizeof(remaining) - 1);
    remaining[sizeof(remaining) - 1] = '\0';

    // DEBUG: Log pattern parsing
    // fprintf(stderr, "DEBUG: parse_pattern_full '%s': start_state=%d, pattern_start_pos=%d, remaining='%s'\n", pattern, start_state, pattern_start_pos, remaining);

    int parse_pos = 0;
    int end_state;
    if (remaining[0] != '\0') {
        end_state = parse_rdp_alternation(remaining, &parse_pos, start_state);
    } else {
        end_state = start_state;
    }

    // Add EOS transition to accepting state
    int eos_sid = find_symbol_id(DFA_CHAR_EOS);
    if (eos_sid != -1) {
        int eos_target_state = end_state;

        // Check if end_state is a shared state with outgoing transitions
        // If so, create a fork state to avoid marking the shared state as accepting
        bool has_outgoing = false;
        for (int s = 0; s < MAX_SYMBOLS; s++) {
            if (nfa[end_state].transitions[s] != -1 || nfa[end_state].multi_targets[s][0] != '\0') {
                has_outgoing = true;
                break;
            }
        }

        if (has_outgoing) {
            // Create a fork state - this is where the pattern can end
            // The shared end_state continues to its other transitions
            eos_target_state = nfa_add_state_with_minimization(false);
            nfa[eos_target_state].is_eos_target = true;  // This state can accept via EOS
            nfa_add_transition(end_state, eos_target_state, eos_sid);
            nfa_finalize_state(end_state);
            // Also mark end_state as EOS target so DFA recognizes it can accept at end of input
            nfa[end_state].is_eos_target = true;
        }

        int accepting = nfa_add_state_with_minimization(true);
        nfa[accepting].is_eos_target = true;  // This state can accept via EOS
        nfa_add_transition(eos_target_state, accepting, eos_sid);

        // When has_outgoing=false, eos_target_state == end_state, so mark it as EOS target
        if (!has_outgoing) {
            nfa[eos_target_state].is_eos_target = true;
        }

        nfa_add_tag(accepting, category);
        if (subcategory[0] != '\0') nfa_add_tag(accepting, subcategory);
        if (operations[0] != '\0') nfa_add_tag(accepting, operations);
        nfa_add_tag(accepting, action);

        nfa_finalize_state(eos_target_state);
        nfa_finalize_state(accepting);
    }
}

// Parse advanced pattern
void parse_advanced_pattern(const char* line) {
    // Format: [category:subcategory:operations] pattern -> action
    // Or: [fragment:name] value
    // Or: [characterset:name] value

    char category[64] = "safe";
    char subcategory[64] = "";
    char operations[256] = "";
    char action[32] = "allow";
    char pattern[MAX_LINE_LENGTH] = "";

    // Skip leading whitespace
    while (*line == ' ' || *line == '\t') line++;

    // Check if this is a fragment or character set definition BEFORE category parsing
    // Syntax: [fragment:name] value
    //         [fragment:namespace:name] value
    //         [characterset:name] value
    //         [characterset:namespace:name] value
    if (strncmp(line, "[fragment:", 10) == 0 || strncmp(line, "[characterset:", 14) == 0) {
        // Determine prefix length
        int prefix_len = (line[1] == 'f') ? 10 : 14;  // "[fragment:" or "[characterset:"
        
        // Extract fragment name (between [fragment: or [characterset: and ])
        const char* name_start = line + prefix_len;
        const char* name_end = strchr(name_start, ']');
        if (name_end != NULL && fragment_count < MAX_FRAGMENTS) {
            size_t name_len = name_end - name_start;
            if (name_len < MAX_FRAGMENT_NAME) {
                // Normalize separator from single colon to double colon for consistency
                strncpy(fragments[fragment_count].name, name_start, name_len);
                fragments[fragment_count].name[name_len] = '\0';
                // fprintf(stderr, "DEBUG: Storing fragment (before normalization): '%s'\n", fragments[fragment_count].name);
                // Replace first single colon with double colon
                // Only do this if the name contains a single colon (not already double colon)
                if (strstr(fragments[fragment_count].name, "::") == NULL) {
                    for (int i = 0; fragments[fragment_count].name[i]; i++) {
                        if (fragments[fragment_count].name[i] == ':') {
                            // Shift remaining characters to make room for second colon
                            int len = strlen(fragments[fragment_count].name);
                            for (int k = len; k > i; k--) {
                                fragments[fragment_count].name[k] = fragments[fragment_count].name[k - 1];
                            }
                            fragments[fragment_count].name[i] = ':';
                            fragments[fragment_count].name[i + 1] = ':';
                            // fprintf(stderr, "DEBUG: Storing fragment (after normalization): '%s'\n", fragments[fragment_count].name);
                            break;  // Only replace first colon (namespace separator)
                        }
                    }
                } else {
                    // fprintf(stderr, "DEBUG: Fragment '%s' already has ::, skipping normalization\n", fragments[fragment_count].name);
                }
                // Skip past ] and whitespace to get value
                const char* value_start = name_end + 1;
                while (*value_start == ' ' || *value_start == '\t') value_start++;
                strncpy(fragments[fragment_count].value, value_start, MAX_FRAGMENT_VALUE - 1);
                fragments[fragment_count].value[MAX_FRAGMENT_VALUE - 1] = '\0';

                fragment_count++;
            }
        }
        return; // Don't process fragment/characterset definitions as patterns
    }

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

    // Check if this is a scoped fragment definition (deprecated, use [fragment:...] format)
    // Syntax: SAFE::FILENAME = pattern
    //         SAFE::FILENAME = [a-zA-Z_.]+
    if (strchr(line, '=') != NULL) {
        char* eq = strchr(line, '=');
        char* name_start = (char*)line;
        char* name_end = eq;
        
        // Check if it looks like a scoped name (contains ::)
        if (strstr(name_start, "::") != NULL && fragment_count < MAX_FRAGMENTS) {
            // name_end points to '=', so name_len includes trailing space if present
            size_t name_len = name_end - name_start;
            // Trim trailing whitespace from name
            while (name_len > 0 && (name_start[name_len - 1] == ' ' || name_start[name_len - 1] == '\t')) {
                name_len--;
            }
            if (name_len > 0 && name_len < MAX_FRAGMENT_NAME) {
                strncpy(fragments[fragment_count].name, name_start, name_len);
                fragments[fragment_count].name[name_len] = '\0';

                // Skip past = and whitespace
                const char* value_start = eq + 1;
                while (*value_start == ' ' || *value_start == '\t') value_start++;
                strncpy(fragments[fragment_count].value, value_start, MAX_FRAGMENT_VALUE - 1);
                fragments[fragment_count].value[MAX_FRAGMENT_VALUE - 1] = '\0';

                fragment_count++;
            }
            return; // Don't process scoped fragment definitions as patterns
        }
    }

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

    // Use the new recursive descent parser to build NFA
    // parse_pattern_full handles NFA building, EOS transition, and tagging internally
    parse_pattern_full(pattern, category, subcategory, operations, action);
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
        fprintf(file, "  CategoryMask: 0x%02x\n", nfa[i].category_mask);
        fprintf(file, "  EosTarget: %s\n", nfa[i].is_eos_target ? "yes" : "no");

        if (nfa[i].tag_count > 0) {
            fprintf(file, "  Tags:");
            for (int j = 0; j < nfa[i].tag_count; j++) {
                fprintf(file, " %s", nfa[i].tags[j]);
            }
            fprintf(file, "\n");
        }

        fprintf(file, "  Transitions: %d\n", nfa[i].transition_count);

        for (int s = 0; s < MAX_SYMBOLS; s++) {
            if (nfa[i].transitions[s] != -1 || nfa[i].multi_targets[s][0] != '\0') {
                fprintf(file, "    Symbol %d", s);
                // Write first target from transitions array
                if (nfa[i].transitions[s] != -1) {
                    fprintf(file, " -> %d", nfa[i].transitions[s]);
                    // Write additional targets from multi_targets
                    if (nfa[i].multi_targets[s][0] != '\0') {
                        fprintf(file, ",%s", nfa[i].multi_targets[s]);
                    }
                } else if (nfa[i].multi_targets[s][0] != '\0') {
                    fprintf(file, " -> %s", nfa[i].multi_targets[s]);
                }
                fprintf(file, "\n");
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