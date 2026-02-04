#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include "../include/dfa_types.h"
#include "../include/nfa.h"

/**
 * Advanced NFA Builder with Integrated Validation and Alphabet Construction
 *
 * This tool builds NFA (Non-deterministic Finite Automata) from advanced
 * command specifications with:
 * 1. Full pattern file validation
 * 2. Automatic alphabet construction (in-memory)
 * 3. Optimized NFA building
 *
 * Usage: nfa_builder [options] <spec_file> [output.nfa]
 *
 * Options:
 *   --validate-only    Only validate pattern file, don't build NFA
 *   --verbose          Enable verbose output
 *   --verbose-alphabet Show alphabet construction details
 *   --verbose-validation Show validation details
 *   --verbose-nfa      Show NFA building details
 *   --alphabet FILE    Use external alphabet file (optional)
 *
 * If no external alphabet is provided, the builder constructs one automatically
 * from the pattern file.
 */

/**
 * Debug output control - set to 0 to disable all debug prints
 * These can be overridden with -DNFA_BUILDER_DEBUG=1 compiler flag
 */
#ifndef NFA_BUILDER_DEBUG
#define NFA_BUILDER_DEBUG 0
#endif

#ifndef NFA_BUILDER_VERBOSE
#define NFA_BUILDER_VERBOSE 0
#endif

// Conditional debug print macro - only prints if NFA_BUILDER_DEBUG is true
#if NFA_BUILDER_DEBUG
#define DEBUG_PRINT(fmt, ...) fprintf(stderr, "//DEBUG: " fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

// Conditional verbose print macro - only prints if NFA_BUILDER_VERBOSE is true
#if NFA_BUILDER_VERBOSE
#define VERBOSE_PRINT(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define VERBOSE_PRINT(fmt, ...) ((void)0)
#endif

// Character class definition
typedef struct {
    int start_char;
    int end_char;
    int symbol_id;
    bool is_special;
} char_class_t;

// Forward declarations for new functions
static void parse_arguments(int argc, char* argv[],
                           const char** spec_file, const char** output_file);
static bool validate_pattern_file(const char* spec_file);
static bool construct_alphabet_from_patterns(const char* spec_file);
static void print_usage(const char* progname);

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

// Alphabet construction state
static char_class_t built_alphabet[MAX_SYMBOLS];
static int built_alphabet_size = 0;
static bool alphabet_constructed = false;
static const char* spec_file_for_validation = NULL;

// Command-line flags
static bool flag_validate_only = false;
static bool flag_verbose = false;
static bool flag_verbose_alphabet = false;
static bool flag_verbose_validation = false;
static bool flag_verbose_nfa = false;
static const char* external_alphabet_file = NULL;

// Pattern file identifier (for NFA/DFA matching)
static char pattern_identifier[256] = "";

// NFA State with category bitmask for 8-way parallel acceptance
typedef struct {
    uint8_t category_mask;           // Bitmask of accepting categories (0-7)
    int16_t pattern_id;              // Pattern ID this state belongs to (-1 = none/shared)
    bool is_eos_target;              // This state can accept via EOS transition
    char* tags[MAX_TAGS];             // Termination tags
    int tag_count;
    int transitions[MAX_SYMBOLS];     // -1 = no transition, otherwise state index
    int transition_count;
    char multi_targets[MAX_SYMBOLS][256];  // For storing multiple targets as CSV strings

    // Negated transitions: target state + excluded characters
    negated_transition_t negated_transitions[MAX_SYMBOLS];
    int negated_transition_count;
    
    // Capture markers: -1 = no capture, otherwise capture ID
    int8_t capture_start_id;
    int8_t capture_end_id;
    // Capture defer: -1 = no defer, otherwise capture ID to defer until leaving state
    int8_t capture_defer_id;
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
static uint8_t current_pattern_cat_mask = 0x01;  // Category mask for current pattern (computed from #ACCEPTANCE_MAPPING)
static StateSignature* signature_table[SIGNATURE_TABLE_SIZE] = {NULL};

// CONSERVATIVE SHARING: Track states that should NOT be shared
// States marked as "do not share" cannot be merged with other states during
// NFA construction. This prevents acceptance category interference.
// A state is marked "do not share" if it:
//   - Might become accepting (has pending quantifier)
//   - Is already accepting (has category_mask or is_eos_target)
static bool state_do_not_share[MAX_STATES] = {false};

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

// For + quantifier on literal characters: tracks the last symbol added
static int last_element_sid = -1;

// For + quantifier: tracks if we're inside a capture (capture ID to defer)
static int8_t pending_capture_defer_id = -1;

// ============================================================================
// DECOUPLED ARCHITECTURE: Explicit data structures replacing globals
// ============================================================================

// Result of parsing a fragment - stores info needed by quantifier handlers
typedef struct {
    int loop_entry_state;      // State where quantifier loop should be added (-1 if multi-char)
    int exit_state;            // State after consuming the fragment
    bool is_single_char;       // Whether fragment is single character
    char loop_char;            // The character (if single char)
    int capture_defer_id;       // Capture ID to defer (for +/* quantifiers)
    bool has_capture;          // Whether fragment contains captures
    char capture_name[MAX_CAPTURE_NAME];  // Capture name if applicable
} FragmentResult;

// Stack-based context for nested quantifiers
#define MAX_QUANTIFIER_DEPTH 8
typedef struct {
    FragmentResult fragment;
    int capture_defer_id;
    int element_sid;
} QuantifierContext;

static QuantifierContext quantifier_stack[MAX_QUANTIFIER_DEPTH];
static int quantifier_stack_depth = 0;

// Current parsing context - explicit instead of scattered globals
static FragmentResult current_fragment;
// For character class symbols in current fragment
#define MAX_CLASS_SYMBOLS 64
static int current_class_symbols[MAX_CLASS_SYMBOLS];
static int current_class_symbol_count = 0;

static int current_element_sid = -1;
static int current_capture_defer_id = -1;
static bool current_is_char_class = false;
static int last_parsed_state = -1;
static bool has_pending_quantifier = false;

// ============================================================================

// Find a fragment by name
static const char* find_fragment(const char* name) {
    DEBUG_PRINT("find_fragment looking for: '%s'\n", name);
    for (int i = 0; i < fragment_count; i++) {
        DEBUG_PRINT("  comparing with fragment[%d]: '%s' = '%s'\n", i, fragments[i].name, fragments[i].value);
        if (strcmp(fragments[i].name, name) == 0) {
            DEBUG_PRINT("  found match!\n");
            return fragments[i].value;
        }
    }
    DEBUG_PRINT("  not found\n");
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
        
        // Initialize capture markers
        nfa[i].capture_start_id = -1;
        nfa[i].capture_end_id = -1;
        // Initialize "do not share" tracking for conservative state sharing
        state_do_not_share[i] = false;
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
    
    // DISABLE negation to ensure nfa2dfa compatibility
    // nfa2dfa does not support NotSymbol transitions
    return false;
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
    VERBOSE_PRINT("Loaded alphabet with %d symbols from %s\n", alphabet_size, filename);
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
    nfa[new_state].pattern_id = current_pattern_index;  // Set pattern_id
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

    // DEFERRED SHARING: Don't share during construction
    // All sharing/minimization will happen at the end after all patterns are built
    // This prevents interference between patterns with different acceptance categories
    // The DFA conversion process will handle proper state minimization
    
    // Still add to signature table for potential future optimization
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

    // Always include pattern index to prevent inappropriate state sharing
    // between patterns with different characteristics (especially different
    // acceptance categories assigned via #ACCEPTANCE_MAPPING directive)
    signature = signature * 31 + current_pattern_index;

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
        // Skip states that should not be shared
        if (state_do_not_share[current_state] || state_do_not_share[entry->state_index]) {
            entry = entry->next;
            continue;
        }

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
            // CRITICAL FIX: Allow appending when multi_targets already has commas (3rd+ target)
            if (strstr(existing, ",") != NULL || strstr(nfa[0].multi_targets[symbol_id], ",") != NULL ||
                (nfa[0].transitions[symbol_id] != to && nfa[0].transitions[symbol_id] != to)) {

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
    // Support multiple targets for the same symbol (for loops and exits)
    if (nfa[from].transitions[symbol_id] == -1) {
        // First transition on this symbol
        nfa[from].transitions[symbol_id] = to;
        nfa[from].transition_count++;
    } else if (nfa[from].transitions[symbol_id] != to) {
        // Additional transition on same symbol - use multi_targets
        char existing[256];
        sprintf(existing, "%d", nfa[from].transitions[symbol_id]);

        // Check if target already exists
        if (strstr(existing, ",") != NULL || strstr(nfa[from].multi_targets[symbol_id], ",") != NULL ||
            nfa[from].transitions[symbol_id] != to) {

            // Append to multi_targets
            char new_target[32];
            sprintf(new_target, ",%d", to);

            if (strlen(nfa[from].multi_targets[symbol_id]) + strlen(new_target) < 255) {
                strcat(nfa[from].multi_targets[symbol_id], new_target);
                nfa[from].transition_count++;
            }
        }
    }
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
// Then continue parsing the content inside the tags
static int parse_capture_start(const char* pattern, int* pos, int start_state) {
    DEBUG_PRINT("parse_capture_start ENTERED at pos %d, start_state=%d\n", *pos, start_state);
    char cap_name[MAX_CAPTURE_NAME];
    if (!is_capture_start(pattern, *pos, cap_name)) {
        DEBUG_PRINT("parse_capture_start: is_capture_start returned FALSE\n");
        return start_state;
    }

    int cap_id = get_capture_id(cap_name);
    DEBUG_PRINT("parse_capture_start '%s' called, cap_id=%d, capture_count=%d\n", cap_name, cap_id, capture_count);
    if (cap_id < 0) {
        DEBUG_PRINT("parse_capture_start returning early due to cap_id < 0\n");
        return start_state;
    }

    // Skip past the opening tag <name>
    while (pattern[*pos] != '\0' && pattern[*pos] != '>') {
        (*pos)++;
    }
    if (pattern[*pos] == '>') {
        (*pos)++;
    }

    // NEW APPROACH: Set capture_start_id on start_state directly
    // This way, the capture marker is intrinsic to the state and won't be lost
    // when states are merged during DFA construction
    nfa[start_state].capture_start_id = cap_id;
    DEBUG_PRINT("parse_capture_start '%s' -> cap_id=%d on state %d\n", cap_name, cap_id, start_state);

    // Push capture ID onto stack and mark for potential deferral (for + quantifier)
    capture_stack[capture_stack_depth++] = cap_id;
    pending_capture_defer_id = cap_id;  // Will be used if followed by + quantifier

    // Return start_state - the capture starts HERE before consuming any content
    return start_state;
}

// Parse capture end tag and emit CAPTURE_END transition
// Then continue parsing (for nested captures or following content)
static int parse_capture_end(const char* pattern, int* pos, int start_state) {
    char cap_name[MAX_CAPTURE_NAME];
    if (!is_capture_end(pattern, *pos, cap_name)) {
        return start_state;
    }

    int cap_id = get_capture_id(cap_name);
    if (cap_id < 0) {
        return start_state;
    }

    // Skip past the closing tag </name>
    while (pattern[*pos] != '\0' && pattern[*pos] != '>') {
        (*pos)++;
    }
    if (pattern[*pos] == '>') {
        (*pos)++;
    }

    // NEW APPROACH: Set capture_end_id on start_state directly
    // The capture ends at start_state (position after content, before 'c')
    nfa[start_state].capture_end_id = cap_id;
    DEBUG_PRINT("parse_capture_end '%s' -> cap_id=%d on state %d\n", cap_name, cap_id, start_state);

    // Pop capture ID from stack (verify it matches)
    if (capture_stack_depth > 0) {
        capture_stack_depth--;
    }

    // Return start_state - the capture ends HERE after consuming content
    return start_state;
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
static FragmentResult parse_rdp_fragment(const char* pattern, int* pos, int start_state);
static int parse_rdp_postfix(const char* pattern, int* pos, int start_state);
static int parse_rdp_sequence(const char* pattern, int* pos, int start_state);
static int parse_rdp_alternation(const char* pattern, int* pos, int start_state);

// Parse fragment reference like ((SAFE::FILENAME)) or ((FILENAME))
// The fragment value is treated as a pattern and parsed recursively
// Returns FragmentResult containing loop entry, exit state, and metadata
// REPLACES: previous approach that set pending_loop_* globals
static FragmentResult parse_rdp_fragment(const char* pattern, int* pos, int start_state) {
    FragmentResult result = {0};
    result.loop_entry_state = -1;
    result.exit_state = -1;
    result.is_single_char = false;
    result.loop_char = '\0';
    result.capture_defer_id = -1;
    result.has_capture = false;
    result.capture_name[0] = '\0';

    // Check for fragment reference ((name::subname)) or ((name))
    if (pattern[*pos] != '(' || pattern[*pos + 1] != '(') {
        // Not a fragment reference, return invalid result
        result.exit_state = start_state;
        return result;
    }

    size_t j = *pos + 2;

    // Find the end of fragment reference ))
    while (pattern[j] != '\0' && !(pattern[j] == ')' && pattern[j + 1] == ')')) {
        j++;
    }

    // Check for proper closing
    if (pattern[j] != ')' || pattern[j + 1] != ')') {
        fprintf(stderr, "WARNING: Malformed fragment reference at position %d\n", *pos);
        result.exit_state = start_state;
        return result;
    }

    // Extract fragment name
    char frag_name[MAX_FRAGMENT_NAME];
    size_t name_len = j - (*pos + 2);
    if (name_len >= sizeof(frag_name)) {
        fprintf(stderr, "WARNING: Fragment name too long at position %d\n", *pos);
        *pos = j + 2;
        result.exit_state = start_state;
        return result;
    }

    strncpy(frag_name, &pattern[*pos + 2], name_len);
    frag_name[name_len] = '\0';

    DEBUG_PRINT("Looking up fragment (raw): '%s'\n", frag_name);

    // Normalize fragment name
    normalize_fragment_name(frag_name);

    DEBUG_PRINT("Looking up fragment (normalized): '%s'\n", frag_name);

    DEBUG_PRINT("parse_rdp_fragment ENTER: frag_name='%s'\n", frag_name);

    // Look up fragment
    const char* frag_value = find_fragment(frag_name);
    if (frag_value == NULL) {
        fprintf(stderr, "WARNING: Fragment '%s' not found, skipping\n", frag_name);
        *pos = j + 2;
        result.exit_state = start_state;
        return result;
    }

    DEBUG_PRINT("parse_rdp_fragment: frag_name='%s', frag_value='%s'\n", frag_name, frag_value);

    // Create a clean start state for the fragment
    int frag_start = nfa_add_state_with_minimization(false);

    // Track if this is a single-char fragment
    bool is_single_char = (frag_value[0] != '\0' && frag_value[1] == '\0');

    // Add transition from start_state to frag_start using first char of fragment value
    // For single-char fragments, use start_state directly as frag_start
    if (frag_value[0] != '\0' && frag_value[1] != '\0') {
        // Multi-char fragment: add transition from start_state to frag_start
        int first_sid = find_symbol_id(frag_value[0]);
        if (first_sid != -1) {
            nfa_add_transition(start_state, frag_start, first_sid);
        }
    } else if (frag_value[0] != '\0') {
        // Single-char fragment: use start_state directly
        frag_start = start_state;
    }

    // Parse the fragment value starting from frag_start
    int frag_pos = 0;
    int frag_end_raw = parse_rdp_alternation(frag_value, &frag_pos, frag_start);
    int frag_end = frag_end_raw;

    // Populate FragmentResult
    if (is_single_char) {
        result.is_single_char = true;
        result.loop_char = frag_value[0];
        result.loop_entry_state = frag_end;  // Exit state after consuming the char
    } else {
        result.is_single_char = false;
        result.loop_char = '\0';
        result.loop_entry_state = -1;  // Multi-char fragments don't need char-specific loop
    }

    result.exit_state = frag_end;

    // Add EOS transition only for multi-char fragments
    // Single-char fragments should NOT have EOS here - the quantifier handler adds it
    // This prevents patterns like a((b))+ from incorrectly accepting zero iterations
    int eos_sid = find_symbol_id(DFA_CHAR_EOS);
    if (eos_sid != -1 && !is_single_char) {
        int accepting = nfa_add_state_with_category(current_pattern_cat_mask);
        nfa_add_transition(frag_end, accepting, eos_sid);
        nfa[accepting].is_eos_target = true;
        nfa_finalize_state(frag_end);
        nfa_finalize_state(accepting);
    } else if (is_single_char) {
        // For single-char fragments, finalize frag_end without EOS transition
        nfa_finalize_state(frag_end);
    }

    // Mark states as potentially accepting (for quantifier handling)
    state_do_not_share[frag_start] = true;
    state_do_not_share[frag_end] = true;

    *pos = j + 2;  // Skip past the fragment reference

    return result;
}

static int parse_rdp_class(const char* pattern, int* pos, int start_state) {
    memset(&current_fragment, 0, sizeof(current_fragment));
    current_is_char_class = true;
    current_class_symbol_count = 0;

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
                // Track this symbol for + quantifier loop creation
                if (current_class_symbol_count < MAX_CLASS_SYMBOLS) {
                    current_class_symbols[current_class_symbol_count++] = sid;
                }
            }
        }
    }

    if (pattern[*pos] == ']') {
        (*pos)++; // Skip closing ]
    }

    nfa_finalize_state(class_state);

    // Set current_fragment for quantifier handling
    current_fragment.is_single_char = false;
    current_fragment.loop_entry_state = class_state;
    current_fragment.exit_state = class_state;

    return class_state;
}

// Parse primary element: char, escaped, quoted, class, group, or capture tag
static int parse_rdp_element(const char* pattern, int* pos, int start_state) {
    char c = pattern[*pos];
    DEBUG_PRINT("parse_rdp_element: ENTER pos=%d, start_state=%d, c='%c' (0x%02x)\n", *pos, start_state, c, (unsigned char)c);

    // Check for capture start tag <name>
    char cap_name[MAX_CAPTURE_NAME];
    if (is_capture_start(pattern, *pos, cap_name)) {
        DEBUG_PRINT("is_capture_start TRUE at pos %d, name='%s'\n", *pos, cap_name);
        return parse_capture_start(pattern, pos, start_state);
    } else {
        DEBUG_PRINT("is_capture_start FALSE at pos %d (char='%c')\n", *pos, c);
    }

    // Check for capture end tag </name>
    if (is_capture_end(pattern, *pos, cap_name)) {
        DEBUG_PRINT("is_capture_end TRUE at pos %d, name='%s'\n", *pos, cap_name);
        return parse_capture_end(pattern, pos, start_state);
    } else {
        DEBUG_PRINT("is_capture_end FALSE at pos %d (char='%c')\n", *pos, c);
    }

    switch (c) {
        case '\\':
            // Escaped character
            if (pattern[*pos + 1] != '\0') {
                char ec = pattern[*pos + 1];
                
                // Check for hex escape \xHH
                if (ec == 'x' && pattern[*pos + 2] != '\0' && pattern[*pos + 3] != '\0') {
                    // Parse hex escape \xHH
                    char hex[3] = {pattern[*pos + 2], pattern[*pos + 3], 0};
                    int hex_val = (int)strtol(hex, NULL, 16);
                    DEBUG_PRINT("Found \\x%02x escape, char='%c', code=%d\n", hex_val, hex_val, hex_val);
                    if (hex_val > 0 && hex_val < 256) {
                        int sid = find_symbol_id(hex_val);
                        DEBUG_PRINT("find_symbol_id(%d) = %d\n", hex_val, sid);
                        if (sid != -1) {
                            int new_state = nfa_add_state_with_minimization(false);
                            nfa_add_transition(start_state, new_state, sid);
                            int finalized_state = nfa_finalize_state(new_state);
                            memset(&current_fragment, 0, sizeof(current_fragment));
                            current_fragment.is_single_char = true;
                            current_fragment.loop_char = (char)hex_val;
                            current_fragment.loop_entry_state = finalized_state;
                            current_fragment.exit_state = finalized_state;
                            current_is_char_class = false;
                            *pos += 4;
                            DEBUG_PRINT("Created transition on '%c' (symbol %d)\n", hex_val, sid);
                            return finalized_state;
                        }
                    }
                }
                
                int sid = find_symbol_id(ec);
                if (sid != -1) {
                    int new_state = nfa_add_state_with_minimization(false);
                    nfa_add_transition(start_state, new_state, sid);
                    int finalized_state = nfa_finalize_state(new_state);
                    memset(&current_fragment, 0, sizeof(current_fragment));
                    current_fragment.is_single_char = true;
                    current_fragment.loop_char = ec;
                    current_fragment.loop_entry_state = finalized_state;
                    current_fragment.exit_state = finalized_state;
                    current_is_char_class = false;
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
                    memset(&current_fragment, 0, sizeof(current_fragment));
                    current_fragment.is_single_char = true;
                    current_fragment.loop_char = qc;
                    current_fragment.loop_entry_state = finalized_state;
                    current_fragment.exit_state = finalized_state;
                    current_is_char_class = false;
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
                // Extract fragment name and check if it exists
                size_t j = *pos + 2;
                while (pattern[j] != '\0' && !(pattern[j] == ')' && pattern[j + 1] == ')')) {
                    j++;
                }
                if (pattern[j] == ')' && pattern[j + 1] == ')') {
                    char frag_name[MAX_FRAGMENT_NAME];
                    size_t name_len = j - (*pos + 2);
                    if (name_len < sizeof(frag_name)) {
                        strncpy(frag_name, &pattern[*pos + 2], name_len);
                        frag_name[name_len] = '\0';
                        normalize_fragment_name(frag_name);
                        // Only treat as fragment if it exists
                        if (find_fragment(frag_name) != NULL) {
                            FragmentResult frag_result = parse_rdp_fragment(pattern, pos, start_state);
                            // Store in current_fragment for quantifier handler
                            current_fragment = frag_result;
                            // For element parsing, return the exit state
                            return frag_result.exit_state;
                        }
                    }
                }
                // Not a valid fragment reference, treat as nested group
            }
            // Regular grouping
            (*pos)++;
            return parse_rdp_alternation(pattern, pos, start_state);

        default:
            DEBUG_PRINT("parse_rdp_element: default case, c='%c' (0x%02x)\n", c, (unsigned char)c);
            if (c == '*') {
                DEBUG_PRINT("parse_rdp_element: Found wildcard '*'\n");
                int any_sid = find_symbol_id(DFA_CHAR_ANY);
                DEBUG_PRINT("parse_rdp_element: any_sid=%d for DFA_CHAR_ANY (0x%02x)\n", any_sid, (unsigned char)DFA_CHAR_ANY);
                if (any_sid != -1) {
                    int star_state = nfa_add_state_with_minimization(false);
                    state_do_not_share[star_state] = true;
                    nfa_add_transition(start_state, star_state, any_sid);
                    nfa_add_transition(star_state, star_state, any_sid);
                    int finalized_star = nfa_finalize_state(star_state);
                    (*pos)++;
                    return finalized_star;
                }
            }
            if (c == ' ' || c == '\t') {
                // Handle space and tab characters - create transitions
                // Space is Symbol 2 (char 32), Tab is Symbol 3 (char 9) in alphabet_per_char.map
                int space_sid = find_symbol_id(32);  // Space character
                int tab_sid = find_symbol_id(9);     // Tab character
                int sid = (c == ' ') ? space_sid : tab_sid;
                if (sid != -1) {
                    int new_state = nfa_add_state_with_minimization(false);
                    nfa_add_transition(start_state, new_state, sid);
                    int finalized_state = nfa_finalize_state(new_state);
                    memset(&current_fragment, 0, sizeof(current_fragment));
                    current_fragment.is_single_char = true;
                    current_fragment.loop_char = c;
                    current_fragment.loop_entry_state = finalized_state;
                    current_fragment.exit_state = finalized_state;
                    current_is_char_class = false;
                    (*pos)++;
                    return finalized_state;
                }
                (*pos)++;
                break;
            }
            if (c != '\0') {
                // Special handling for * as wildcard (matches any argument)
                // This MUST come BEFORE the postfix operator check
                if (c == '*') {
                    DEBUG_PRINT("parse_rdp_element: Found wildcard '*'\n");
                    int any_sid = find_symbol_id(DFA_CHAR_ANY);
                    DEBUG_PRINT("parse_rdp_element: any_sid=%d for DFA_CHAR_ANY (0x%02x)\n", any_sid, (unsigned char)DFA_CHAR_ANY);
                    if (any_sid != -1) {
                        int star_state = nfa_add_state_with_minimization(false);
                        state_do_not_share[star_state] = true;
                        nfa_add_transition(start_state, star_state, any_sid);
                        nfa_add_transition(star_state, star_state, any_sid);
                        int finalized_star = nfa_finalize_state(star_state);
                        (*pos)++;
                        return finalized_star;
                    }
                }
                // Don't consume postfix operators - let parse_rdp_postfix handle them
                if (c == '+' || c == '?') {
                    return start_state;
                }
                int sid = find_symbol_id(c);
                if (sid != -1) {
                    int new_state = nfa_add_state_with_minimization(false);
                    nfa_add_transition(start_state, new_state, sid);
                    int finalized_state = nfa_finalize_state(new_state);
                    memset(&current_fragment, 0, sizeof(current_fragment));
                    current_fragment.is_single_char = true;
                    current_fragment.loop_char = c;
                    current_fragment.loop_entry_state = finalized_state;
                    current_fragment.exit_state = finalized_state;
                    current_is_char_class = false;
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
    int current;
    if (has_pending_quantifier && current_fragment.exit_state != -1) {
        // Element was already parsed in parse_rdp_sequence, use its exit state
        current = current_fragment.exit_state;
    } else if (!has_pending_quantifier && current_fragment.exit_state != -1) {
        // Element was already parsed (no quantifier), return start_state without re-parsing
        // This handles the case where parse_rdp_alternation calls us after parse_rdp_sequence
        current = start_state;
    } else {
        // Element not yet parsed, parse it now
        current = parse_rdp_element(pattern, pos, start_state);
    }

    while (pattern[*pos] != '\0') {
        char op = pattern[*pos];

        if (op == '*') {
            int eos_sid = find_symbol_id(DFA_CHAR_EOS);
            if (eos_sid == -1) return current;

            // Check if we have a valid quantifier context
            // A valid quantifier context means we have a single character fragment (not space/tab)
            // that was just parsed and should be quantified
            bool has_valid_quantifier_context = false;
            if (current_fragment.is_single_char && current_fragment.loop_entry_state != -1) {
                // Check if the fragment is NOT from space/tab handling
                // Space/tab should not be quantified - * after space is a standalone wildcard
                if (!(current_fragment.loop_char == ' ' || current_fragment.loop_char == '\t')) {
                    has_valid_quantifier_context = true;
                }
            }

            // If no valid quantifier context, this * is a standalone wildcard
            // Handle it here by creating a wildcard transition
            if (!has_valid_quantifier_context) {
                int any_sid = find_symbol_id(DFA_CHAR_ANY);
                if (any_sid != -1) {
                    int star_state = nfa_add_state_with_minimization(false);
                    state_do_not_share[star_state] = true;
                    nfa_add_transition(current, star_state, any_sid);
                    nfa_add_transition(star_state, star_state, any_sid);
                    int accepting = nfa_add_state_with_category(current_pattern_cat_mask);
                    state_do_not_share[accepting] = true;
                    nfa_add_transition(star_state, accepting, eos_sid);
                    nfa[accepting].is_eos_target = true;
                    nfa_finalize_state(star_state);
                    nfa_finalize_state(accepting);
                    (*pos)++; // Consume the *
                    return accepting;
                }
            }

            // Only increment pos if we're actually handling the quantifier
            (*pos)++;

            if (current_fragment.is_single_char && current_fragment.loop_entry_state != -1) {
                int char_sid = find_symbol_id(current_fragment.loop_char);
                if (char_sid != -1) {
                    // For * quantifier with single-char fragment:
                    // The START state should be accepting (for zero iterations)
                    // loop_entry_state is frag_start (state after 'a')
                    // Set it as the accepting state
                    nfa[current_fragment.loop_entry_state].is_eos_target = true;
                    nfa[current_fragment.loop_entry_state].category_mask = current_pattern_cat_mask;
                    nfa_finalize_state(current_fragment.loop_entry_state);

                    // Create loop state
                    int star_state = nfa_add_state_with_minimization(false);
                    state_do_not_share[star_state] = true;
                    nfa_add_transition(current_fragment.loop_entry_state, star_state, char_sid);
                    nfa_add_transition(star_state, star_state, char_sid);

                    // Continue to next pattern part (or create final accepting if end)
                    current = current_fragment.loop_entry_state;

                    // If at end of pattern (current is already accepting), we're done
                    // The loop state allows continuing with more iterations
                    // For patterns ending here, we need a final accepting state
                    // Check if there's more pattern after this quantifier
                    if (pattern[*pos] == '\0' || pattern[*pos] == ')') {
                        // End of pattern - create final accepting state
                        int final_accepting = nfa_add_state_with_category(current_pattern_cat_mask);
                        state_do_not_share[final_accepting] = true;
                        nfa_add_transition(star_state, final_accepting, eos_sid);
                        nfa[final_accepting].is_eos_target = true;
                        nfa_finalize_state(final_accepting);
                        current = final_accepting;
                    }

                    // Clear current_fragment after use
                    memset(&current_fragment, 0, sizeof(current_fragment));
                    current_fragment.exit_state = -1;
                } else {
                    int any_sid = find_symbol_id(DFA_CHAR_ANY);
                    if (any_sid != -1) {
                        int star_state = nfa_add_state_with_minimization(false);
                        state_do_not_share[star_state] = true;
                        nfa_add_transition(current, star_state, any_sid);
                        nfa_add_transition(star_state, star_state, any_sid);
                        int accepting = nfa_add_state_with_category(current_pattern_cat_mask);
                        state_do_not_share[accepting] = true;
                        nfa_add_transition(star_state, accepting, eos_sid);
                        nfa[accepting].is_eos_target = true;
                        nfa_finalize_state(star_state);
                        nfa_finalize_state(accepting);
                        current = accepting;
                    }
                }
            } else if (last_element_sid != -1) {
                int char_sid = last_element_sid;
                int star_state = nfa_add_state_with_minimization(false);
                state_do_not_share[star_state] = true;
                nfa_add_transition(current, star_state, char_sid);
                nfa_add_transition(star_state, star_state, char_sid);
                int accepting = nfa_add_state_with_category(current_pattern_cat_mask);
                state_do_not_share[accepting] = true;
                nfa_add_transition(star_state, accepting, eos_sid);
                nfa[accepting].is_eos_target = true;
                nfa_finalize_state(star_state);
                nfa_finalize_state(accepting);
                current = accepting;
                last_element_sid = -1;
            } else {
                int any_sid = find_symbol_id(DFA_CHAR_ANY);
                if (any_sid != -1) {
                    int star_state = nfa_add_state_with_minimization(false);
                    state_do_not_share[star_state] = true;
                    nfa_add_transition(current, star_state, any_sid);
                    nfa_add_transition(star_state, star_state, any_sid);
                    int accepting = nfa_add_state_with_category(current_pattern_cat_mask);
                    state_do_not_share[accepting] = true;
                    nfa_add_transition(star_state, accepting, eos_sid);
                    nfa[accepting].is_eos_target = true;
                    nfa_finalize_state(star_state);
                    nfa_finalize_state(accepting);
                    current = accepting;
                }
            }

        } else if (op == '+') {
            (*pos)++;

            int eos_sid = find_symbol_id(DFA_CHAR_EOS);
            if (eos_sid == -1) return current;

            if (current_fragment.is_single_char && current_fragment.loop_entry_state != -1) {
                int char_sid = find_symbol_id(current_fragment.loop_char);
                if (char_sid != -1) {

                    // For + quantifier: need to handle the multi-target transition bug
                    // where loop_state gets added to the transition. Use separate states.
                    //
                    // Structure:
                    //   Entry --char--> First (for first iteration)
                    //   Loop --char--> Loop (for subsequent iterations)
                    //   Loop --EOS--> Accepting
                    int first_iter = nfa_add_state_with_minimization(false);
                    int loop_state = nfa_add_state_with_minimization(false);
                    DEBUG_PRINT("+ handler: loop_entry=%d, first_iter=%d, loop_state=%d\n",
                              current_fragment.loop_entry_state, first_iter, loop_state);

                    // Mark quantifier states as non-shareable to prevent pattern interference
                    state_do_not_share[first_iter] = true;
                    state_do_not_share[loop_state] = true;

                    // Entry -> First on char (first iteration)
                    nfa_add_transition(current_fragment.loop_entry_state, first_iter, char_sid);

                    // First -> Loop on char (transition to loop state)
                    nfa_add_transition(first_iter, loop_state, char_sid);
                    DEBUG_PRINT("+ handler: Added %d -> %d on char %d\n",
                              first_iter, loop_state, char_sid);

                    // Loop -> Loop on char (subsequent iterations)
                    nfa_add_transition(loop_state, loop_state, char_sid);
                    DEBUG_PRINT("+ handler: Added %d -> %d on char %d (loop)\n",
                              loop_state, loop_state, char_sid);

                    // Loop -> Accepting on EOS
                    int new_accepting = nfa_add_state_with_category(current_pattern_cat_mask);
                    state_do_not_share[new_accepting] = true;
                    nfa[new_accepting].is_eos_target = true;
                    nfa_add_transition(loop_state, new_accepting, eos_sid);
                    DEBUG_PRINT("+ handler: Added %d -> %d on EOS\n",
                              loop_state, new_accepting);
                    nfa_finalize_state(new_accepting);
                    current = new_accepting;
                    DEBUG_PRINT("+ handler: Final current=%d\n", current);

                    memset(&current_fragment, 0, sizeof(current_fragment));
                    current_fragment.exit_state = -1;
                    current_is_char_class = false;
                } else {
                    DEBUG_PRINT("+ handler: char_sid not found for '%c'\n", current_fragment.loop_char);
                }
            } else if (current_is_char_class && current_class_symbol_count > 0) {
                for (int i = 0; i < current_class_symbol_count; i++) {
                    nfa_add_transition(current, current, current_class_symbols[i]);
                }

                int accepting = nfa_add_state_with_category(current_pattern_cat_mask);
                state_do_not_share[accepting] = true;
                nfa_add_transition(current, accepting, eos_sid);
                nfa[accepting].is_eos_target = true;
                nfa_finalize_state(accepting);
                current = accepting;

                memset(&current_fragment, 0, sizeof(current_fragment));
                current_fragment.exit_state = -1;
                current_is_char_class = false;
                current_class_symbol_count = 0;
            } else if (current_fragment.exit_state != -1) {
                int new_accepting = nfa_add_state_with_category(current_pattern_cat_mask);
                state_do_not_share[new_accepting] = true;
                nfa[new_accepting].is_eos_target = true;
                nfa_add_transition(current_fragment.exit_state, new_accepting, eos_sid);
                nfa_finalize_state(new_accepting);
                current = new_accepting;

                memset(&current_fragment, 0, sizeof(current_fragment));
                current_fragment.exit_state = -1;
            }
        } else if (op == '?') {
            (*pos)++;
            int eos_sid = find_symbol_id(DFA_CHAR_EOS);
            if (eos_sid == -1) return current;

            int fork_state = nfa_add_state_with_minimization(false);
            state_do_not_share[fork_state] = true;
            int accepting = nfa_add_state_with_category(current_pattern_cat_mask);
            state_do_not_share[accepting] = true;
            nfa[accepting].is_eos_target = true;

            nfa_add_transition(current, fork_state, eos_sid);
            nfa[fork_state].is_eos_target = true;
            nfa_add_transition(fork_state, accepting, eos_sid);
            nfa_finalize_state(fork_state);
            nfa_finalize_state(accepting);
            current = accepting;

        } else {
            break;
        }
    }

    return current;
}

// Parse sequence of elements (concatenation)
static int parse_rdp_sequence(const char* pattern, int* pos, int start_state) {
    int current = start_state;

    while (*pos < (int)strlen(pattern) && pattern[*pos] != ')' && pattern[*pos] != '|') {
        // Check for postfix operators after parsing each element
        char next_char = pattern[*pos];
        if (next_char == '+' || next_char == '*' || next_char == '?') {
            // Postfix operator applies to the previous element - break and let caller handle it
            break;
        }
        current = parse_rdp_element(pattern, pos, current);

        // After parsing element, check if next char is a postfix operator
        // If so, we need to handle it before continuing
        if (pattern[*pos] == '+' || pattern[*pos] == '*' || pattern[*pos] == '?') {
            has_pending_quantifier = true;
            current = parse_rdp_postfix(pattern, pos, current);
            has_pending_quantifier = false;
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

    // Handle postfix quantifiers (* + ?) on the alternation result
    // This is needed because parse_rdp_element calls parse_rdp_alternation directly
    // for grouping, bypassing parse_rdp_postfix where quantifier handling lives
    int postfix_result = parse_rdp_postfix(pattern, pos, first_end);

    int finalized_end = nfa_finalize_state(postfix_result);
    return finalized_end;
}

// Forward declaration for category mapping lookup
static int lookup_acceptance_category(const char* category, const char* subcategory, const char* operations);

// Main entry point: parse pattern and build NFA
static void parse_pattern_full(const char* pattern, const char* category,
                                const char* subcategory, const char* operations,
                                const char* action) {
    int pos = 0;

    // Clear per-pattern globals to avoid stale values between patterns
    last_element_sid = -1;
    pending_capture_defer_id = -1;
    memset(&current_fragment, 0, sizeof(current_fragment));
    current_fragment.exit_state = -1;
    current_is_char_class = false;
    current_class_symbol_count = 0;
    has_pending_quantifier = false;

    // Find entry state - try to share prefix with existing patterns
    int start_state;
    int pattern_start_pos = 0;

     DEBUG_PRINT("parse_pattern_full '%s': nfa_state_count=%d, pattern[0]='%c' (sid=%d)\n", pattern, nfa_state_count, pattern[0], find_symbol_id(pattern[0]));

    // DEBUG: Check if there's a shared prefix
    int first_char_sid = find_symbol_id(pattern[0]);
    if (nfa_state_count > 1 && pattern[0] != '\0' && first_char_sid != -1) {
        DEBUG_PRINT("  Checking prefix: pattern[0]='%c', sid=%d, nfa[0].transitions[%d]=%d\n", 
                   pattern[0], first_char_sid, first_char_sid, nfa[0].transitions[first_char_sid]);
    }

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

            // CRITICAL FIX: Check if shared states have the same pattern_id as current pattern
            // If not, don't share - patterns with different acceptance categories must be isolated
            bool all_targets_have_same_pattern_id = true;
            int first_target_pattern_id = -1;
            DEBUG_PRINT("Prefix sharing for '%s': target_count=%d, current_pattern_index=%d\n",
                    pattern, target_count, current_pattern_index);
            for (int t = 0; t < target_count; t++) {
                DEBUG_PRINT("  target[%d]=%d, pattern_id=%d\n", t, targets[t], nfa[targets[t]].pattern_id);
                if (first_target_pattern_id == -1) {
                    first_target_pattern_id = nfa[targets[t]].pattern_id;
                } else if (nfa[targets[t]].pattern_id != first_target_pattern_id) {
                    all_targets_have_same_pattern_id = false;
                    break;
                }
            }

            for (int t = 0; t < target_count; t++) {
                int curr_state = targets[t];
                int curr_pos = 1;

                // CRITICAL: Don't follow paths from states with different pattern_id
                // This prevents contamination between patterns with different acceptance categories
                if (nfa[curr_state].pattern_id != current_pattern_index) {
                    continue;  // Skip this target - different pattern
                }

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

            // CRITICAL: Only share prefix if:
            // 1. A common prefix was found (best_shared_pos > 1)
            // 2. All target states have the same pattern_id (no pattern mixing)
            // 3. That pattern_id matches the current pattern (current_pattern_index)
            if (best_shared_pos > 1 && all_targets_have_same_pattern_id &&
                first_target_pattern_id == current_pattern_index) {
                // Found common prefix - start from there
                shared_state = best_shared_state;
                shared_pos = best_shared_pos;
                start_state = shared_state;
                pattern_start_pos = shared_pos;
                DEBUG_PRINT("SHARED prefix at pos %d, state %d\n", best_shared_pos, best_shared_state);
            } else {
                // No common prefix - create new start state
                start_state = nfa_add_state_with_minimization(false);
                DEBUG_PRINT("NEW start_state=%d for pattern_id %d, adding transition 0->%d on %d\n",
                        start_state, current_pattern_index, start_state, first_char_sid);
                nfa_add_transition(0, start_state, first_char_sid);
                DEBUG_PRINT("After add_transition: transitions[%d]=%d, multi_targets[%d]='%s'\n",
                        first_char_sid, nfa[0].transitions[first_char_sid], first_char_sid,
                        nfa[0].multi_targets[first_char_sid]);
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

    // When pattern_start_pos=1 and remaining starts with a postfix operator,
    // the first character was consumed during prefix sharing but never processed.
    // We need to set last_element_sid from pattern[0] for proper quantifier handling.
    if (pattern_start_pos == 1 && remaining[0] != '\0') {
        char first_char = pattern[0];
        int first_sid = find_symbol_id(first_char);
        if (first_sid != -1) {
            last_element_sid = first_sid;
        }
    }

    // CRITICAL FIX: Determine acceptance category BEFORE pattern parsing
    // so that quantifier handlers can access current_pattern_cat_mask
    int acceptance_cat = lookup_acceptance_category(category, subcategory, operations);
    uint8_t cat_mask = (1 << acceptance_cat);  // Convert 0-7 to bit mask 0x01, 0x02, etc.
    current_pattern_cat_mask = cat_mask;  // Store for use by quantifier handlers

    int parse_pos = 0;
    int end_state;
    DEBUG_PRINT("parse_pattern_full: remaining='%s', pattern_start_pos=%d\n", remaining, pattern_start_pos);
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
        // CRITICAL: Also create fork state if end_state is an accepting state (category_mask != 0)
        // This prevents marking + quantifier intermediate states as EOS target
        bool has_outgoing = false;
        for (int s = 0; s < MAX_SYMBOLS; s++) {
            if (nfa[end_state].transitions[s] != -1 || nfa[end_state].multi_targets[s][0] != '\0') {
                has_outgoing = true;
                break;
            }
        }
        // If end_state is an accepting state (has category_mask), treat as having outgoing
        // This ensures + quantifier states like 129 don't get marked as EOS target
        if (nfa[end_state].category_mask != 0) {
            has_outgoing = true;
        }
        DEBUG_PRINT("finalize: end_state=%d, has_outgoing=%d, is_eos_target before=%d, cat_mask=0x%02x\n",
                end_state, has_outgoing, nfa[end_state].is_eos_target, nfa[end_state].category_mask);

        if (has_outgoing) {
            // Create a fork state - this is where the pattern can end
            // The shared end_state continues to its other transitions
            // IMPORTANT: Don't mark end_state as EOS target - it's shared and shouldn't accept here
            eos_target_state = nfa_add_state_with_minimization(false);
            nfa[eos_target_state].is_eos_target = true;  // Only the fork state accepts
            nfa_add_transition(end_state, eos_target_state, eos_sid);
            nfa_finalize_state(end_state);
            // DO NOT mark end_state as EOS target - it has outgoing transitions (shared state)
        }

        int accepting = nfa_add_state_with_category(cat_mask);
        nfa[accepting].is_eos_target = true;  // This state can accept via EOS
        state_do_not_share[accepting] = true;  // CONSERVATIVE: Don't share accepting states
        nfa_add_transition(eos_target_state, accepting, eos_sid);

        // When has_outgoing=false, eos_target_state == end_state, so mark it as EOS target
        if (!has_outgoing) {
            nfa[eos_target_state].is_eos_target = true;
            nfa[eos_target_state].category_mask = cat_mask;  // Set category for end_state
            state_do_not_share[eos_target_state] = true;  // CONSERVATIVE: Don't share accepting states
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
                 DEBUG_PRINT("Storing fragment (before normalization): '%s'\n", fragments[fragment_count].name);
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
                             DEBUG_PRINT("Storing fragment (after normalization): '%s'\n", fragments[fragment_count].name);
                            break;  // Only replace first colon (namespace separator)
                        }
                    }
                } else {
                     DEBUG_PRINT("Fragment '%s' already has ::, skipping normalization\n", fragments[fragment_count].name);
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
        current_pattern_index = pattern_count;  // Set BEFORE incrementing
        pattern_count++;
    }

    // Set the pattern index for this NFA construction
    // This prevents states from different patterns from being merged
    // current_pattern_index was already set to the current pattern's index above

    // Use the new recursive descent parser to build NFA
    // parse_pattern_full handles NFA building, EOS transition, and tagging internally
    parse_pattern_full(pattern, category, subcategory, operations, action);
}

// Category mapping table for #ACCEPTANCE_MAPPING directive
#define MAX_CATEGORY_MAPPINGS 64
typedef struct {
    char category[64];
    char subcategory[64];
    char operations[256];
    int acceptance_category;  // 0-7
} category_mapping_t;

static category_mapping_t category_mappings[MAX_CATEGORY_MAPPINGS];
static int category_mapping_count = 0;

// Parse #ACCEPTANCE_MAPPING directive
// Syntax: #ACCEPTANCE_MAPPING [category:subcategory:operations] -> N
// Where N is 0-7 representing the 8 acceptance categories
static void parse_acceptance_mapping(const char* line) {
    // Find the mapping arrow
    const char* arrow = strstr(line, "->");
    if (arrow == NULL) {
        fprintf(stderr, "Warning: Invalid ACCEPTANCE_MAPPING syntax (no ->): %s\n", line);
        return;
    }

    // Parse the category part [category:subcategory:operations]
    const char* bracket_open = strchr(line, '[');
    const char* bracket_close = strchr(line, ']');
    if (bracket_open == NULL || bracket_close == NULL || bracket_close > arrow) {
        fprintf(stderr, "Warning: Invalid ACCEPTANCE_MAPPING syntax (bad brackets): %s\n", line);
        return;
    }

    // Extract category string
    char category_str[512];
    size_t cat_len = bracket_close - bracket_open - 1;
    if (cat_len >= sizeof(category_str)) cat_len = sizeof(category_str) - 1;
    strncpy(category_str, bracket_open + 1, cat_len);
    category_str[cat_len] = '\0';

    // Parse the acceptance category number after ->
    int acceptance_cat = atoi(arrow + 2);
    if (acceptance_cat < 0 || acceptance_cat > 7) {
        fprintf(stderr, "Warning: Invalid acceptance category %d (must be 0-7): %s\n", acceptance_cat, line);
        return;
    }

    // Parse category:subcategory:operations
    char category[64] = "";
    char subcategory[64] = "";
    char operations[256] = "";

    char* tok = strtok(category_str, ":");
    if (tok != NULL) {
        strncpy(category, tok, sizeof(category) - 1);
        category[sizeof(category) - 1] = '\0';
    }

    tok = strtok(NULL, ":");
    if (tok != NULL) {
        strncpy(subcategory, tok, sizeof(subcategory) - 1);
        subcategory[sizeof(subcategory) - 1] = '\0';
    }

    tok = strtok(NULL, ":");
    if (tok != NULL) {
        strncpy(operations, tok, sizeof(operations) - 1);
        operations[sizeof(operations) - 1] = '\0';
    }

    // Store the mapping
    if (category_mapping_count < MAX_CATEGORY_MAPPINGS) {
        category_mapping_t* mapping = &category_mappings[category_mapping_count++];
        strncpy(mapping->category, category, sizeof(mapping->category) - 1);
        strncpy(mapping->subcategory, subcategory, sizeof(mapping->subcategory) - 1);
        strncpy(mapping->operations, operations, sizeof(mapping->operations) - 1);
        mapping->acceptance_category = acceptance_cat;
        VERBOSE_PRINT("ACCEPTANCE_MAPPING: [%s:%s:%s] -> %d\n",
                category, subcategory, operations, acceptance_cat);
    } else {
        fprintf(stderr, "Warning: Too many category mappings, ignoring: %s\n", line);
    }
}

// Look up acceptance category for a given category:subcategory:operations
static int lookup_acceptance_category(const char* category, const char* subcategory, const char* operations) {
    for (int i = 0; i < category_mapping_count; i++) {
        category_mapping_t* mapping = &category_mappings[i];
        // Match category (required)
        if (strcmp(mapping->category, category) != 0) continue;
        // Match subcategory: if pattern has non-empty subcategory, mapping must match
        if (subcategory[0] != '\0' && strcmp(mapping->subcategory, subcategory) != 0) continue;
        // Match operations: if pattern has non-empty operations, mapping must match
        if (operations[0] != '\0' && strcmp(mapping->operations, operations) != 0) continue;
        return mapping->acceptance_category;
    }
    // No explicit mapping found - fall back to category name
    return parse_category(category);
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

        // Skip empty lines
        if (line[0] == '\0') {
            continue;
        }

        // Handle #ACCEPTANCE_MAPPING directive
        if (strncmp(line, "#ACCEPTANCE_MAPPING", 19) == 0) {
            parse_acceptance_mapping(line);
            continue;
        }

        // Skip other comments
        if (line[0] == '#') {
            continue;
        }

        // Parse and add pattern
        parse_advanced_pattern(line);
    }

    fclose(file);

    VERBOSE_PRINT("Read %d patterns from %s\n", pattern_count, filename);
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
    fprintf(file, "Identifier: %s\n", pattern_identifier[0] ? pattern_identifier : "(none)");
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
        fprintf(file, "  PatternId: %d\n", nfa[i].pattern_id);
        fprintf(file, "  EosTarget: %s\n", nfa[i].is_eos_target ? "yes" : "no");
        // Debug: print states with non-zero pattern_id
        if (nfa[i].pattern_id != 0 && nfa[i].category_mask != 0) {
            DEBUG_PRINT("State %d has pattern_id=%d, category=0x%02x\n", 
                    i, nfa[i].pattern_id, nfa[i].category_mask);
        }
        
        // Write capture markers
        if (nfa[i].capture_start_id >= 0) {
            fprintf(file, "  CaptureStart: %d\n", nfa[i].capture_start_id);
        }
        if (nfa[i].capture_end_id >= 0) {
            fprintf(file, "  CaptureEnd: %d\n", nfa[i].capture_end_id);
        }

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
    VERBOSE_PRINT("Wrote NFA with %d states and %d symbols to %s\n", nfa_state_count, alphabet_size, filename);
}

// Cleanup
void cleanup(void) {
    for (int i = 0; i < nfa_state_count; i++) {
        for (int j = 0; j < nfa[i].tag_count; j++) {
            free(nfa[i].tags[j]);
        }
    }

    for (int i = 0; i < SIGNATURE_TABLE_SIZE; i++) {
        StateSignature* entry = signature_table[i];
        while (entry != NULL) {
            StateSignature* next = entry->next;
            free(entry);
            entry = next;
        }
        signature_table[i] = NULL;
    }
}

// =============================================================================
// NEW: Integrated Validation and Alphabet Construction Functions
// =============================================================================

static void print_usage(const char* progname) {
    fprintf(stderr, "Usage: %s [options] <spec_file> [output.nfa]\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "Advanced NFA Builder with Integrated Validation and Alphabet Construction\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --validate-only       Only validate pattern file, don't build NFA\n");
    fprintf(stderr, "  --verbose              Enable verbose output\n");
    fprintf(stderr, "  --verbose-alphabet     Show alphabet construction details\n");
    fprintf(stderr, "  --verbose-validation   Show validation details\n");
    fprintf(stderr, "  --verbose-nfa          Show NFA building details\n");
    fprintf(stderr, "  --alphabet FILE        Use external alphabet file (optional)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "If no external alphabet is provided, the builder constructs one automatically\n");
    fprintf(stderr, "from the pattern file.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s patterns_safe_commands.txt readonlybox.nfa\n", progname);
    fprintf(stderr, "  %s --validate-only patterns_safe_commands.txt\n", progname);
    fprintf(stderr, "  %s --verbose patterns_safe_commands.txt\n", progname);
}

static void parse_arguments(int argc, char* argv[],
                          const char** spec_file, const char** output_file) {
    // Reset flags
    flag_validate_only = false;
    flag_verbose = false;
    flag_verbose_alphabet = false;
    flag_verbose_validation = false;
    flag_verbose_nfa = false;
    external_alphabet_file = NULL;
    
    // Skip program name
    argc--;
    argv++;
    
    // Parse arguments
    while (argc > 0) {
        if (strcmp(argv[0], "--validate-only") == 0) {
            flag_validate_only = true;
        } else if (strcmp(argv[0], "--verbose") == 0) {
            flag_verbose = true;
        } else if (strcmp(argv[0], "--verbose-alphabet") == 0) {
            flag_verbose_alphabet = true;
        } else if (strcmp(argv[0], "--verbose-validation") == 0) {
            flag_verbose_validation = true;
        } else if (strcmp(argv[0], "--verbose-nfa") == 0) {
            flag_verbose_nfa = true;
        } else if (strcmp(argv[0], "--alphabet") == 0) {
            if (argc < 2) {
                fprintf(stderr, "Error: --alphabet requires a filename\n");
                exit(1);
            }
            external_alphabet_file = argv[1];
            argc--;
            argv++;
        } else if (argv[0][0] == '-') {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[0]);
            print_usage(argv[0]);
            exit(1);
        } else {
            break;  // First non-option argument is spec_file
        }
        argc--;
        argv++;
    }
    
    // Check for spec_file
    if (argc < 1) {
        fprintf(stderr, "Error: No spec file provided\n");
        print_usage("nfa_builder");
        exit(1);
    }
    
    *spec_file = argv[0];
    *output_file = argc > 1 ? argv[1] : "readonlybox.nfa";
}

static bool validate_pattern_file(const char* spec_file) {
    if (flag_verbose_validation) {
        fprintf(stderr, "\n=== Validation Phase ===\n");
        fprintf(stderr, "Validating: %s\n", spec_file);
    }
    
    FILE* file = fopen(spec_file, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open spec file '%s'\n", spec_file);
        return false;
    }
    
    char line[MAX_LINE_LENGTH];
    int line_num = 0;
    int errors = 0;
    int patterns_seen = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_num++;
        
        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '\n' || line[0] == '\r' || line[0] == '#') {
            continue;
        }
        
        // Remove trailing newline
        line[strcspn(line, "\r\n")] = 0;
        
        // Check for fragment definition [fragment:name] value
        if (strncmp(line, "[fragment:", 11) == 0) {
            char* bracket = strchr(line, ']');
            if (!bracket) {
                fprintf(stderr, "Error: Malformed fragment definition at line %d: %s\n", line_num, line);
                errors++;
                continue;
            }
            if (flag_verbose_validation) {
                char fragment_name[64] = {0};
                strncpy(fragment_name, line + 11, bracket - (line + 11));
                fprintf(stderr, "  Line %d: Fragment '%s'\n", line_num, fragment_name);
            }
            continue;
        }
        
        // Check for character set definition [characterset:name] value
        if (strncmp(line, "[characterset:", 15) == 0) {
            if (flag_verbose_validation) {
                fprintf(stderr, "  Line %d: Character set definition\n", line_num);
            }
            continue;
        }
        
        // Check for ACCEPTANCE_MAPPING directive
        if (strncmp(line, "ACCEPTANCE_MAPPING", 19) == 0) {
            if (flag_verbose_validation) {
                fprintf(stderr, "  Line %d: Acceptance mapping\n", line_num);
            }
            continue;
        }

        // Check for IDENTIFIER directive
        if (strncmp(line, "IDENTIFIER", 10) == 0 && (line[10] == ' ' || line[10] == '"')) {
            // Extract the quoted string
            char* id_start = line + 11;
            // Skip leading whitespace
            while (*id_start == ' ' || *id_start == '\t') id_start++;

            if (*id_start != '"') {
                fprintf(stderr, "Error: IDENTIFIER must be a quoted string at line %d\n", line_num);
                errors++;
                continue;
            }
            id_start++; // Skip opening quote

            char* id_end = strchr(id_start, '"');
            if (!id_end) {
                fprintf(stderr, "Error: Unclosed IDENTIFIER string at line %d\n", line_num);
                errors++;
                continue;
            }

            size_t id_len = id_end - id_start;
            if (id_len >= sizeof(pattern_identifier)) {
                fprintf(stderr, "Error: IDENTIFIER too long at line %d\n", line_num);
                errors++;
                continue;
            }

            strncpy(pattern_identifier, id_start, id_len);
            pattern_identifier[id_len] = '\0';

            if (flag_verbose_validation) {
                fprintf(stderr, "  Line %d: Identifier = \"%s\"\n", line_num, pattern_identifier);
            }
            continue;
        }

        // Check for category pattern [category:subcategory:operations] pattern
        if (line[0] == '[') {
            char* bracket = strchr(line, ']');
            if (!bracket) {
                fprintf(stderr, "Error: Malformed pattern at line %d: %s\n", line_num, line);
                errors++;
                continue;
            }

            // Extract pattern part (everything after the closing bracket)
            char* pattern_start = bracket + 1;
            while (*pattern_start == ' ' || *pattern_start == '\t') pattern_start++;

            // Skip empty lines after bracket (just a category/fragment definition, not a pattern)
            if (*pattern_start == '\0' || *pattern_start == '\n' || *pattern_start == '\r') {
                continue;
            }

            // Basic validation of pattern syntax
            // Count parentheses
            int open_parens = 0, close_parens = 0;
            for (char* p = pattern_start; *p; p++) {
                if (*p == '(') open_parens++;
                else if (*p == ')') close_parens++;
            }

            if (open_parens != close_parens) {
                fprintf(stderr, "Error: Unmatched parentheses at line %d: %s\n", line_num, line);
                errors++;
            }

            // Check for common issues
            if (*pattern_start != '\0' && strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789*?[]()-+.:\\", *pattern_start) == NULL) {
                fprintf(stderr, "Error: Invalid pattern start at line %d: %s\n", line_num, line);
                errors++;
            }

            patterns_seen++;
            continue;
        }
        
        // Skip lines without category brackets (empty or other)
    }
    
    fclose(file);
    
    if (flag_verbose_validation) {
        fprintf(stderr, "  Total patterns found: %d\n", patterns_seen);
        fprintf(stderr, "  Validation errors: %d\n", errors);
    }
    
    if (errors > 0) {
        fprintf(stderr, "\nValidation FAILED: %d error(s) found\n", errors);
        return false;
    }
    
    if (patterns_seen == 0) {
        fprintf(stderr, "\nWarning: No patterns found in spec file\n");
    }
    
    if (flag_verbose_validation) {
        fprintf(stderr, "\nValidation PASSED: No errors found\n");
    }
    
    return true;
}

static bool construct_alphabet_from_patterns(const char* spec_file) {
    if (flag_verbose_alphabet) {
        fprintf(stderr, "\n=== Alphabet Construction Phase ===\n");
        fprintf(stderr, "Building alphabet from: %s\n", spec_file);
    }
    
    FILE* file = fopen(spec_file, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open spec file '%s'\n", spec_file);
        return false;
    }
    
    // Reset alphabet
    built_alphabet_size = 0;
    alphabet_constructed = false;
    
    // Add required special symbols
    // Symbol 0: DFA_CHAR_ANY (matches any character)
    built_alphabet[0].start_char = 0;
    built_alphabet[0].end_char = 0;
    built_alphabet[0].symbol_id = 0;
    built_alphabet[0].is_special = true;
    built_alphabet_size++;
    
    // Symbol 1: DFA_CHAR_SPACE (space)
    built_alphabet[1].start_char = 32;
    built_alphabet[1].end_char = 32;
    built_alphabet[1].symbol_id = 1;
    built_alphabet[1].is_special = true;
    built_alphabet_size++;
    
    // Symbol 2: DFA_CHAR_TAB (tab)
    built_alphabet[2].start_char = 9;
    built_alphabet[2].end_char = 9;
    built_alphabet[2].symbol_id = 2;
    built_alphabet[2].is_special = true;
    built_alphabet_size++;
    
    // Symbol 3: DFA_CHAR_EOS (end of string marker, value 5)
    built_alphabet[3].start_char = 5;
    built_alphabet[3].end_char = 5;
    built_alphabet[3].symbol_id = 3;
    built_alphabet[3].is_special = true;
    built_alphabet_size++;
    
    char line[MAX_LINE_LENGTH];
    int line_num = 0;
    int symbols_added = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_num++;
        
        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '\n' || line[0] == '\r' || line[0] == '#') {
            continue;
        }
        
        // Remove trailing newline
        line[strcspn(line, "\r\n")] = 0;
        
        // Skip fragment definitions
        if (strncmp(line, "[fragment:", 11) == 0) {
            continue;
        }
        
        // Skip character set definitions
        if (strncmp(line, "[characterset:", 15) == 0) {
            continue;
        }
        
        // Skip ACCEPTANCE_MAPPING directives
        if (strncmp(line, "ACCEPTANCE_MAPPING", 19) == 0) {
            continue;
        }
        
        // Extract pattern (between ] and ->, or full line)
        char* pattern_start = NULL;
        char* pattern_end = NULL;
        
        if (line[0] == '[') {
            pattern_start = strchr(line, ']');
            if (!pattern_start) continue;
            pattern_start++;  // Skip ]
            
            // Find arrow
            char* arrow = strstr(pattern_start, "->");
            if (arrow) {
                pattern_end = arrow;
            } else {
                // No action, rest of line is pattern
                pattern_end = pattern_start + strlen(pattern_start);
            }
        } else {
            continue;
        }
        
        // Process pattern characters
        for (char* p = pattern_start; p < pattern_end && *p; p++) {
            char c = *p;
            
            // Skip escaped characters
            if (c == '\\') {
                p++;
                if (*p) {
                    // Add escaped character
                    bool found = false;
                    for (int i = 0; i < built_alphabet_size; i++) {
                        if (built_alphabet[i].start_char == (unsigned char)*p &&
                            built_alphabet[i].end_char == (unsigned char)*p) {
                            found = true;
                            break;
                        }
                    }
                    if (!found && built_alphabet_size < MAX_SYMBOLS) {
                        built_alphabet[built_alphabet_size].start_char = (unsigned char)*p;
                        built_alphabet[built_alphabet_size].end_char = (unsigned char)*p;
                        built_alphabet[built_alphabet_size].symbol_id = built_alphabet_size;
                        built_alphabet[built_alphabet_size].is_special = false;
                        built_alphabet_size++;
                        symbols_added++;
                    }
                }
                continue;
            }
            
            // Skip quantifiers
            if (c == '+' || c == '*' || c == '?') {
                continue;
            }
            
            // Skip brackets and parentheses
            if (c == '[' || c == ']' || c == '(' || c == ')') {
                continue;
            }
            
            // Skip special characters
            if (c == '-' && *(p+1) == '>') {
                break;
            }
            if (c == '|') {
                continue;
            }
            
            // Add character if not already in alphabet
            if (c >= 32 && c < 127) {  // Printable ASCII
                bool found = false;
                for (int i = 0; i < built_alphabet_size; i++) {
                    if (built_alphabet[i].start_char == (unsigned char)c &&
                        built_alphabet[i].end_char == (unsigned char)c) {
                        found = true;
                        break;
                    }
                }
                if (!found && built_alphabet_size < MAX_SYMBOLS) {
                    built_alphabet[built_alphabet_size].start_char = (unsigned char)c;
                    built_alphabet[built_alphabet_size].end_char = (unsigned char)c;
                    built_alphabet[built_alphabet_size].symbol_id = built_alphabet_size;
                    built_alphabet[built_alphabet_size].is_special = false;
                    built_alphabet_size++;
                    symbols_added++;
                }
            }
        }
    }
    
    fclose(file);
    
    if (flag_verbose_alphabet) {
        fprintf(stderr, "  Special symbols: 4 (ANY, SPACE, TAB, EOS)\n");
        fprintf(stderr, "  Pattern symbols: %d\n", symbols_added);
        fprintf(stderr, "  Total alphabet size: %d\n", built_alphabet_size);
    }
    
    // Copy to global alphabet
    for (int i = 0; i < built_alphabet_size && i < MAX_SYMBOLS; i++) {
        alphabet[i] = built_alphabet[i];
    }
    alphabet_size = built_alphabet_size;
    alphabet_constructed = true;
    
    if (flag_verbose_alphabet) {
        fprintf(stderr, "\nAlphabet constructed successfully\n");
    }
    
    return true;
}

// Main function
int main(int argc, char* argv[]) {
    const char* spec_file = NULL;
    const char* output_file = NULL;

    parse_arguments(argc, argv, &spec_file, &output_file);

    if (flag_verbose) {
        VERBOSE_PRINT("Advanced NFA Builder with Integrated Validation and Alphabet Construction\n");
        VERBOSE_PRINT("================================================================================\n\n");
    }

    if (flag_validate_only) {
        bool valid = validate_pattern_file(spec_file);
        if (!valid) {
            fprintf(stderr, "Validation failed\n");
            return 1;
        }
        fprintf(stderr, "Validation passed\n");
        return 0;
    }

    // Always validate first to parse identifier and check syntax
    if (!validate_pattern_file(spec_file)) {
        fprintf(stderr, "Pattern validation failed\n");
        return 1;
    }

    if (external_alphabet_file) {
        load_alphabet(external_alphabet_file);
    } else {
        if (!construct_alphabet_from_patterns(spec_file)) {
            fprintf(stderr, "Failed to construct alphabet from patterns\n");
            return 1;
        }
    }

    read_advanced_spec_file(spec_file);

    write_nfa_file(output_file);

    cleanup();

    if (flag_verbose) {
        VERBOSE_PRINT("\nDone!\n");
        VERBOSE_PRINT("Next step: Run nfa2dfa_with_alphabet to convert NFA to DFA\n");
        VERBOSE_PRINT("  nfa2dfa_with_alphabet %s readonlybox.dfa\n", output_file);
    }

    return 0;
}