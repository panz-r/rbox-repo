#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include "../include/multi_target_array.h"
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
#define NFA_BUILDER_VERBOSE 1
#endif

// Conditional debug print macro - only prints if NFA_BUILDER_DEBUG is true
#if NFA_BUILDER_DEBUG
#define DEBUG_PRINT(...) fprintf(stderr, "//DEBUG: " __VA_ARGS__); fflush(stderr)
#else
#define DEBUG_PRINT(...) ((void)0)
#endif

// Conditional verbose print macro - uses runtime flag_verbose
#define VERBOSE_PRINT(...) do { if (flag_verbose) fprintf(stderr, __VA_ARGS__); } while (0)

// Debug print macro for NFA/DFA construction details - uses runtime flag_verbose_nfa
#define DEBUG_NFA_PRINT(fmt, ...) do { if (flag_verbose_nfa) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

// Character class definition
typedef struct {
    int start_char;
    int end_char;
    int symbol_id;
    bool is_special;
} char_class_t;

// Forward declarations for main binary functions
#ifndef NFABUILDER_NO_MAIN
static void parse_arguments(int argc, char* argv[],
                           const char** spec_file, const char** output_file);
static bool validate_pattern_file(const char* spec_file);
static bool construct_alphabet_from_patterns(const char* spec_file);
static void print_usage(const char* progname);
#endif

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

#ifndef NFABUILDER_NO_MAIN
// Alphabet construction state
static char_class_t built_alphabet[MAX_SYMBOLS];
static int built_alphabet_size = 0;

// Command-line flags (main binary only)
static bool flag_validate_only = false;
static bool flag_verbose_alphabet = false;
static bool flag_verbose_validation = false;
static const char* external_alphabet_file = NULL;
#endif

// Shared flags (used by VERBOSE_PRINT/DEBUG macros)
static bool flag_verbose = false;
static bool flag_verbose_nfa = false;

// Pattern file identifier (for NFA/DFA matching)
static char pattern_identifier[256] = "";

// Current input file name (for error messages)
static const char* current_input_file = NULL;

// Extended NFA state for nfa_builder - includes additional fields not needed for DFA construction
typedef struct {
    uint8_t category_mask;
    int16_t pattern_id;
    bool is_eos_target;
    char* tags[MAX_TAGS];
    int tag_count;
    int transitions[MAX_SYMBOLS];
    int transition_count;
    multi_target_array_t multi_targets;

    // Negated transitions
    negated_transition_t negated_transitions[MAX_SYMBOLS];
    int negated_transition_count;

    // Capture markers
    int8_t capture_start_id;
    int8_t capture_end_id;
    int8_t capture_defer_id;
} nfa_builder_state_t;

// State signature for on-the-fly minimization
typedef struct StateSignature {
    uint64_t signature;
    int state_index;
    struct StateSignature* next;
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

// Global NFA array
static nfa_builder_state_t nfa[MAX_STATES];
static command_pattern_t patterns[MAX_PATTERNS];
static char_class_t alphabet[MAX_SYMBOLS];
static int alphabet_size = 0;

// Virtual Symbol Mapping
#define VSYM_ANY 256
#define VSYM_EPS 257
#define VSYM_EOS 258
#define VSYM_SPACE 259
#define VSYM_TAB 260
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

// Phase 2: Marker system constants
#define MAX_MARKERS_PER_TRANSITION 8
#define MAX_MARKER_LISTS 4096

typedef struct {
    char name[MAX_FRAGMENT_NAME];
    char value[MAX_FRAGMENT_VALUE];
} fragment_t;

static fragment_t fragments[MAX_FRAGMENTS];
static int fragment_count = 0;
static bool has_fragment_error = false;  // Flag for fragment validation errors

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

// ============================================================================
// PHASE 2: Marker System Type Definitions
// ============================================================================

// Marker types
#define MARKER_TYPE_START 0
#define MARKER_TYPE_END 1

// Individual marker entry
typedef struct {
    uint16_t pattern_id;    // Which pattern this marker belongs to
    uint32_t uid;          // Unique identifier for this capture point
    uint8_t type;          // MARKER_TYPE_START or MARKER_TYPE_END
} MarkerEntry;

// Capture name to UID mapping (for metadata table)
typedef struct {
    char name[MAX_CAPTURE_NAME];
    uint32_t uid;
    bool used;
} CaptureUIDMapping;

// ============================================================================
// END PHASE 2 TYPE DEFINITIONS
// ============================================================================

// Pending markers for the next character transitions
// When a capture tag is parsed, markers are queued here. When nfa_add_transition
// is called for a non-EPSILON symbol, ALL queued markers are attached to that transition.
// This supports multiple pending markers (for nested/adjacent captures).
static pending_marker_t pending_markers[MAX_PENDING_MARKERS];
static int pending_marker_count = 0;

// For + quantifier on literal characters: tracks the last symbol added
static int last_element_sid = -1;

// For + quantifier: tracks if we're inside a capture (capture ID to defer)
static int8_t pending_capture_defer_id = -1;

// For fragment chaining: tracks the fragment's entry point for alternation branches
static int pending_frag_start = -1;

// Reset pattern state - clears pending markers and capture stack for a new pattern
// This prevents cross-pattern contamination when states are shared
static void reset_nfa_builder_pattern_state(void) {
    pending_marker_count = 0;
    capture_stack_depth = 0;
    pending_capture_defer_id = -1;
    last_element_sid = -1;
}

// ============================================================================
// DECOUPLED ARCHITECTURE: Explicit data structures replacing globals
// ============================================================================

// Result of parsing a fragment - stores info needed by quantifier handlers
// IMPORTANT: loop_entry_state is the state AFTER the first character is consumed.
// This is used by quantifier handlers to copy transitions for loop-back.
// For multi-char fragments, loop_back copies ALL transitions from loop_entry_state
// to exit_state, allowing the fragment to restart from wherever it would go
// after consuming any character.
typedef struct {
    int anchor_state;          // Dedicated Entry Point (for EPSILON loop-back)
    int loop_entry_state;      // State AFTER first char consumed (source for loop-back transitions)
    int exit_state;            // State after consuming the entire fragment
    bool is_single_char;       // Whether fragment is single character
    char loop_char;            // The character (if single char)
    int capture_defer_id;       // Capture ID to defer (for +/* quantifiers)
    bool has_capture;          // Whether fragment contains captures
    char capture_name[MAX_CAPTURE_NAME];  // Capture name if applicable
    int fragment_entry_state;  // State BEFORE first char transition (legacy, rarely used)
    char loop_first_char;      // First character of fragment (legacy, rarely used)
} FragmentResult;

// Stack-based context for nested quantifiers
// Current parsing context - explicit instead of scattered globals
static FragmentResult current_fragment;

static bool current_is_char_class = false;
static bool has_pending_quantifier = false;
static bool current_is_in_group = false;

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
        }
        mta_free(&nfa[i].multi_targets);
        mta_init(&nfa[i].multi_targets);
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

// ============================================================================
// PHASE 2: NFA Edge Payloads & Marker System
// ============================================================================

// Marker types
#define MARKER_TYPE_START 0
#define MARKER_TYPE_END 1

// Generate a globally unique marker UID
// ============================================================================
// END PHASE 2 MARKER SYSTEM
// ============================================================================

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

negated_transition_t* find_negated_transition_for_target(nfa_builder_state_t* state, int target_state) {
    for (int i = 0; i < state->negated_transition_count; i++) {
        if (state->negated_transitions[i].target_state == target_state) {
            return &state->negated_transitions[i];
        }
    }
    return NULL;
}

bool should_use_negation(int from_state, int to_state, char input_char) {
    (void)input_char;  // Reserved for future negation support
    // More aggressive heuristic: use negation more frequently
    // 1. Always use if we already have a negated transition to this target
    // 2. Use if we're adding a second transition to the same target
    // 3. Use for common patterns that benefit from negation

    nfa_builder_state_t* state = &nfa[from_state];
    
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
    nfa_builder_state_t* state = &nfa[from_state];

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
    return (int)c;
}

int find_special_symbol_id(int special_char) {
    switch (special_char) {
        case DFA_CHAR_ANY:     return VSYM_ANY;
        case DFA_CHAR_EPSILON: return VSYM_EPS;
        case DFA_CHAR_EOS:     return VSYM_EOS;
        case 32:               return VSYM_SPACE;
        case 9:                return VSYM_TAB;
        default:               return -1;
    }
}

// Forward declarations for minimization functions
static uint64_t compute_state_signature(int state);
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
    // Only set pattern_id for accepting states (category_mask != 0)
    // pattern_id = 0 means "no pattern", so we use current_pattern_index + 1
    nfa[new_state].pattern_id = (category_mask != 0) ? (uint16_t)(current_pattern_index + 1) : 0;
    nfa[new_state].tag_count = 0;
    for (int j = 0; j < MAX_TAGS; j++) {
        nfa[new_state].tags[j] = NULL;
    }
    for (int j = 0; j < MAX_SYMBOLS; j++) {
        nfa[new_state].transitions[j] = -1;
    }
    nfa[new_state].transition_count = 0;
    mta_init(&nfa[new_state].multi_targets);
    nfa_state_count++;

    // FORCED NEW STATE - NO MINIMIZATION
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

// Simple string duplication function - aborts on allocation failure
static char* my_strdup(const char* str) {
    if (str == NULL) return NULL;
    size_t len = strlen(str) + 1;
    char* copy = malloc(len);
    if (copy == NULL) {
        fprintf(stderr, "FATAL: Failed to allocate %zu bytes for string duplication\n", len);
        exit(EXIT_FAILURE);
    }
    memcpy(copy, str, len);
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

// Add state to signature table
static void add_state_to_signature_table(int state, uint64_t signature) {
    unsigned int hash = hash_signature(signature);

    StateSignature* new_entry = malloc(sizeof(StateSignature));
    if (new_entry == NULL) {
        fprintf(stderr, "FATAL: Failed to allocate StateSignature for signature table\n");
        exit(EXIT_FAILURE);
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

    if (tag == NULL) {
        fprintf(stderr, "ERROR: Attempting to add NULL tag to state %d\n", state);
        return;
    }

    if (nfa[state].tag_count >= MAX_TAGS) {
        fprintf(stderr, "ERROR: Maximum tags (%d) reached for state %d\n", MAX_TAGS, state);
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

    // ALWAYS use multi-target array for all transitions in the builder
    // This avoids conflicts between transitions[] and multi_targets
    bool added = mta_add_target(&nfa[from].multi_targets, symbol_id, to);
    if (added) {
        nfa[from].transition_count++;
    }

    // CRITICAL: When transitioning TO a state, check if that state already has markers
    // from a different pattern (state sharing scenario). If so, clear those markers
    // to prevent cross-pattern marker contamination.
    // The target state might have been created by a previous pattern and have its markers.
    if (to >= 0 && to < nfa_state_count) {
        DEBUG_PRINT("nfa_add_transition: from=%d to=%d symbol=%d, to_pattern=%d current=%d\n",
                    from, to, symbol_id, nfa[to].pattern_id, current_pattern_index);
    }

    // Transfer ALL pending capture markers to character transitions (not EPSILON/EOS)
    // PATTERN-AWARE: Only transfer if marker belongs to current pattern
    // This prevents cross-pattern contamination when states are shared
    if (pending_marker_count > 0 && symbol_id < 256) {
        multi_target_array_t* mta = &nfa[from].multi_targets;
        for (int m = 0; m < pending_marker_count; m++) {
            pending_marker_t* marker = &pending_markers[m];
            // CRITICAL: Only transfer if marker pattern_id matches current pattern
            // This prevents END markers from Pattern 1 from leaking into Pattern 2
            if (marker->pattern_id == (uint16_t)current_pattern_index) {
                DEBUG_PRINT("nfa_add_transition: transferring marker pid=%d uid=%d type=%d to (%d -> %d) sym %d [CURRENT PATTERN]\n",
                            marker->pattern_id, marker->uid, marker->type, from, to, symbol_id);
                mta_add_marker(mta, symbol_id, marker->pattern_id, marker->uid, marker->type);
            } else {
                DEBUG_PRINT("nfa_add_transition: SKIP marker pid=%d (current pattern=%d)\n",
                            marker->pattern_id, current_pattern_index);
            }
        }
        // Clear all pending markers after transfer
        pending_marker_count = 0;
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

// Get capture name from ID
static const char* get_capture_name(int id) {
    for (int i = 0; i < capture_count; i++) {
        if (capture_map[i].id == id) {
            return capture_map[i].name;
        }
    }
    return NULL;
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

    // Queue START marker for the next character transition
    // Markers will be attached when nfa_add_transition is called
    // This supports multiple pending markers (for nested/adjacent captures)
    if (pending_marker_count < MAX_PENDING_MARKERS) {
        pending_markers[pending_marker_count].pattern_id = (uint16_t)current_pattern_index;
        pending_markers[pending_marker_count].uid = (uint32_t)cap_id;  // Just the capture ID
        pending_markers[pending_marker_count].type = MARKER_TYPE_START;
        pending_markers[pending_marker_count].active = true;
        pending_marker_count++;
        DEBUG_PRINT("parse_capture_start '%s' -> queued marker pid=%d uid=%d type=%d (count=%d)\n",
                    cap_name, pending_markers[pending_marker_count-1].pattern_id,
                    pending_markers[pending_marker_count-1].uid,
                    pending_markers[pending_marker_count-1].type, pending_marker_count);
    } else {
        DEBUG_PRINT("parse_capture_start '%s' -> ERROR: too many pending markers\n", cap_name);
    }

    // Push capture ID onto stack and mark for potential deferral (for + quantifier)
    capture_stack[capture_stack_depth++] = cap_id;
    pending_capture_defer_id = cap_id;  // Will be used if followed by + quantifier

    // Return start_state - the capture marker will be attached to the next transition
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

    // Set END marker on the current state (the state where capture ends)
    // ONLY if this is the end of the pattern (no more content after </name>)
    // For intermediate captures like <p1>abc</p1>d, we DON'T set capture_end_id
    // because the capture ends at the NEXT character, not at this state
    int after_tag_pos = *pos;
    while (pattern[after_tag_pos] != '\0' && isspace(pattern[after_tag_pos])) after_tag_pos++;
    bool is_pattern_end = (pattern[after_tag_pos] == '\0' || pattern[after_tag_pos] == '[' || pattern[after_tag_pos] == '<');

    if (is_pattern_end) {
        // This capture ends at the pattern boundary - set capture_end_id
        nfa[start_state].capture_end_id = (int8_t)cap_id;
        nfa[start_state].pattern_id = (uint16_t)current_pattern_index;
        DEBUG_PRINT("parse_capture_end '%s' -> setting capture_end_id=%d on state %d (END OF PATTERN)\n",
                    cap_name, cap_id, start_state);
        // DON'T queue END marker - it's handled by capture_end_id
    } else {
        // This is an intermediate capture - the END marker will be on the next character
        DEBUG_PRINT("parse_capture_end '%s' -> INTERMEDIATE capture, NOT setting capture_end_id\n", cap_name);
        // Queue END marker to pending_markers for the next character transition
        if (pending_marker_count < MAX_PENDING_MARKERS) {
            pending_markers[pending_marker_count].pattern_id = (uint16_t)current_pattern_index;
            pending_markers[pending_marker_count].uid = (uint32_t)cap_id;
            pending_markers[pending_marker_count].type = MARKER_TYPE_END;
            pending_markers[pending_marker_count].active = true;
            pending_marker_count++;
            DEBUG_PRINT("parse_capture_end '%s' -> queued END marker pid=%d uid=%d\n",
                        cap_name, current_pattern_index, cap_id);
        }
    }

    // Pop capture ID from stack (verify it matches)
    if (capture_stack_depth > 0) {
        capture_stack_depth--;
    }

    // Return start_state - the capture marker will be attached to the next transition
    return start_state;
}

// Parse category ID
int parse_category(const char* name) {
    for (int i = 0; i < CAT_COUNT; i++) {
        if (strcmp(name, category_names[i]) == 0) {
            return i;
        }
    }
    fprintf(stderr, "Warning: Unknown category '%s', defaulting to safe\n", name);
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
//   - [abc]: character class (matches any one of a, b, or c - SINGLE CHARS ONLY)
//   - (*): wildcard (matches any single argument)
//   - (expr)*: zero or more of preceding element (parentheses REQUIRED)
//   - +: one or more of preceding element
//   - ?: zero or one of preceding element
//   - (expr): grouping
//   - a|b|c: alternation (matches a or b or c)
//   - Space normalizes to [ \t]+ (one or more whitespace)
//   - ((namespace::name)): fragment reference (expands to predefined pattern)
//   - ((namespace::name))+ : fragment reference with one-or-more quantifier
//
// SYNTAX RULES:
//   (*)  = wildcard (matches any argument)
//   (a)* = zero or more 'a' (quantifier)
//   a*   = ERROR: ambiguous - use 'a (*)' for wildcard or '(a)*' for quantifier
//
// CHARACTER RANGES: Use fragments with explicit alternation
//   Character ranges like [a-z] or [0-9] are NOT supported.
//   Instead, define a fragment:
//     [fragment:DIGIT] 0|1|2|3|4|5|6|7|8|9
//     [fragment:LOWER] a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z
//   Reference with: ((DIGIT)) or ((LOWER))+
//
// Character classes use | for alternation, e.g., [a|b|c] means a OR b OR c
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
    result.anchor_state = -1;
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

    const char* frag_value = find_fragment(frag_name);
    if (frag_value == NULL) {
        fprintf(stderr, "WARNING: Fragment '%s' not found, skipping\n", frag_name);
        *pos = j + 2;
        result.exit_state = start_state;
        return result;
    }

    DEBUG_PRINT("parse_rdp_fragment: frag_name=\"%s\", frag_value=\"%s\"\n", frag_name, frag_value);

    // Create a clean start state for the fragment
    int frag_start = nfa_add_state_with_minimization(false);

    // Track if this is a single-char fragment
    bool is_single_char = (frag_value[0] != '\0' && frag_value[1] == '\0');

    // Detect if fragment contains alternation (Bug 2.9)
    // Must check for '|' anywhere in the value, not just at position 1
    // For example: [fragment:a] a|b contains alternation, not just at start
    bool has_alternation = false;
    for (int i = 0; frag_value[i] != '\0'; i++) {
        if (frag_value[i] == '|') {
            has_alternation = true;
            break;
        }
    }

    // Add transition from start_state to frag_start using first char of fragment value
    // For single-char fragments, use start_state directly as frag_start
    // SKIP if alternation is present (Bug 2.9)
    if (!has_alternation && frag_value[0] != '\0' && frag_value[1] != '\0') {
        // Multi-char fragment: add transition from start_state to frag_start
        int first_sid = find_symbol_id(frag_value[0]);
        if (first_sid != -1) {
            nfa_add_transition(start_state, frag_start, first_sid);
        }
    } else if (!has_alternation && frag_value[0] != '\0') {
        // Single-char fragment: use start_state directly
        frag_start = start_state;
    } else {
        // Alternation or complex fragment: use EPSILON to frag_start and parse all chars
        int epsilon_sid = VSYM_EPS;
        if (epsilon_sid != -1) {
            nfa_add_transition(start_state, frag_start, epsilon_sid);
        } else {
            frag_start = start_state;
        }
    }

    // Store frag_start in a global so alternation code can access it
    // This allows branches to connect to the fragment continuation
    pending_frag_start = frag_start;

    // Parse the fragment value starting from frag_start
    // For multi-char fragments (without alternation), skip first char since we handled it
    int frag_pos = 0;
    int frag_end;
    if (!has_alternation && frag_value[0] != '\0' && frag_value[1] != '\0') {
        frag_pos = 1;  // Skip first char
        frag_end = parse_rdp_alternation(frag_value, &frag_pos, frag_start);
    } else {
        frag_end = parse_rdp_alternation(frag_value, &frag_pos, frag_start);
    }

    // For fragments used in sequence (start_state != 0 and has_alternation),
    // we need to connect the fragment's exit to allow continuation to next fragment
    // This is handled by the caller when it chains fragments

    // Populate FragmentResult
    // For fragments with alternation, ALWAYS use frag_start as anchor
    // This is critical for patterns like ((x|y|z))+ where we need to loop back to the fragment start
    if (has_alternation) {
        result.anchor_state = frag_start;  // Always use actual fragment start for alternation
    } else {
        result.anchor_state = start_state;
    }
    if (is_single_char) {
        result.is_single_char = true;
        result.loop_char = frag_value[0];
        result.loop_entry_state = frag_start;  // State BEFORE consuming char
    } else {
        result.is_single_char = false;
        result.loop_char = '\0';
        result.loop_entry_state = frag_start;  // State BEFORE consuming fragment
        result.fragment_entry_state = start_state;
        result.loop_first_char = frag_value[0];
    }

    result.exit_state = frag_end;

    // Mark states as potentially accepting (for quantifier handling)
    state_do_not_share[frag_start] = true;
    state_do_not_share[frag_end] = true;

    *pos = j + 2;  // Skip past the fragment reference

    return result;
}

static int parse_rdp_class(const char* pattern, int* pos, int start_state) {
    (void)start_state;  // Not used - character classes are disallowed
    // Character classes [abc] are NOT supported.
    // Generate a clear error message explaining alternatives.
    fprintf(stderr, "ERROR: Character class syntax [abc] is not supported.\n");
    fprintf(stderr, "  The '[' character is reserved.\n");
    fprintf(stderr, "  To match '[' literally, escape it as '\\['\n");
    fprintf(stderr, "  For alternatives, use parentheses:\n");
    fprintf(stderr, "    - For single chars (a OR b OR c): (a|b|c)\n");
    fprintf(stderr, "    - For multi-char alternatives (ab OR bc): (ab|bc)\n");
    fprintf(stderr, "  For character ranges, use fragments:\n");
    fprintf(stderr, "    [fragment:LOWER] a|b|c|d|e|f|...\n");
    fprintf(stderr, "    Reference as: ((LOWER))\n");
    fprintf(stderr, "Pattern position: %d\n", *pos);
    fprintf(stderr, "Pattern: %s\n", pattern);
    
    // Exit with error to stop pattern processing
    exit(1);
    
    // Return value is unreachable due to exit()
    return -1;
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
                    if (hex_val > 0 && hex_val < 256) {
                        int sid = find_symbol_id(hex_val);
                        if (sid != -1) {
                            // Ensure dedicated anchor state
                            int anchor = start_state;
                            if (anchor == 0) {
                                anchor = nfa_add_state_with_minimization(false);
                                nfa_add_transition(0, anchor, VSYM_EPS);
                            }

                            int new_state = nfa_add_state_with_minimization(false);
                            nfa_add_transition(anchor, new_state, sid);
                            int finalized_state = nfa_finalize_state(new_state);
                            
                            memset(&current_fragment, 0, sizeof(current_fragment));
                            current_fragment.anchor_state = anchor;
                            current_fragment.is_single_char = true;
                            current_fragment.loop_char = (char)hex_val;
                            current_fragment.loop_entry_state = finalized_state;
                            current_fragment.exit_state = finalized_state;
                            current_is_char_class = false;
                            *pos += 4;
                            return finalized_state;
                        }
                    }
                }
                
                int sid = find_symbol_id(ec);
                if (sid != -1) {
                    // Ensure dedicated anchor state
                    int anchor = start_state;
                    if (anchor == 0) {
                        anchor = nfa_add_state_with_minimization(false);
                        nfa_add_transition(0, anchor, VSYM_EPS);
                    }

                    int new_state = nfa_add_state_with_minimization(false);
                    nfa_add_transition(anchor, new_state, sid);
                    int finalized_state = nfa_finalize_state(new_state);
                    
                    memset(&current_fragment, 0, sizeof(current_fragment));
                    current_fragment.anchor_state = anchor;
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
                    // Ensure dedicated anchor state
                    int anchor = start_state;
                    if (anchor == 0) {
                        anchor = nfa_add_state_with_minimization(false);
                        nfa_add_transition(0, anchor, VSYM_EPS);
                    }

                    int new_state = nfa_add_state_with_minimization(false);
                    nfa_add_transition(anchor, new_state, sid);
                    int finalized_state = nfa_finalize_state(new_state);
                    
                    memset(&current_fragment, 0, sizeof(current_fragment));
                    current_fragment.anchor_state = anchor;
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

        case '[': {
            int result = parse_rdp_class(pattern, pos, start_state);
            if (result < 0) {
                // Error already printed by parse_rdp_class
                exit(1);
            }
            return result;
        }

        case '(':
            // Check for (*) explicit wildcard syntax
            if (pattern[*pos + 1] == '*' && pattern[*pos + 2] == ')') {
                int any_sid = VSYM_ANY;
                // Ensure we have a dedicated anchor state (not State 0)
                int anchor = start_state;
                if (anchor == 0) {
                    anchor = nfa_add_state_with_minimization(false);
                    nfa_add_transition(0, anchor, VSYM_EPS);
                }

                int star_state = nfa_add_state_with_minimization(false);
                state_do_not_share[star_state] = true;
                // Zero or more: anchor --EPSILON--> star_state (zero chars)
                nfa_add_transition(anchor, star_state, VSYM_EPS);
                // One or more: anchor --ANY--> star_state (first char)
                nfa_add_transition(anchor, star_state, any_sid);
                // Loop: star_state --ANY--> star_state (additional chars)
                nfa_add_transition(star_state, star_state, any_sid);
                int finalized_star = nfa_finalize_state(star_state);
                
                // Set current_fragment
                memset(&current_fragment, 0, sizeof(current_fragment));
                current_fragment.anchor_state = anchor;
                current_fragment.is_single_char = false;
                current_fragment.exit_state = finalized_star;
                
                *pos += 3; // Consume (*)
                return finalized_star;
            }

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
                            
                            // For fragments in sequence like ((frag1))((frag2)):
                            // Connect from previous fragment's EXIT to this fragment's anchor
                            // This allows continuation after completing the first fragment
                            static int prev_frag_exit = -1;
                            
                            if (prev_frag_exit >= 0) {
                                int epsilon_sid = VSYM_EPS;
                                if (epsilon_sid != -1) {
                                    // Connect previous exit to this anchor
                                    DEBUG_PRINT("  Connecting prev_exit %d -> anchor %d via EPSILON\n",
                                                prev_frag_exit, frag_result.anchor_state);
                                    nfa_add_transition(prev_frag_exit, frag_result.anchor_state, epsilon_sid);
                                }
                            }
                            
                            // Store this fragment's exit for the next fragment
                            prev_frag_exit = frag_result.exit_state;
                            
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
                int any_sid = VSYM_ANY;
                // Ensure dedicated anchor state
                int anchor = start_state;
                if (anchor == 0) {
                    anchor = nfa_add_state_with_minimization(false);
                    nfa_add_transition(0, anchor, VSYM_EPS);
                }

                int star_state = nfa_add_state_with_minimization(false);
                state_do_not_share[star_state] = true;
                nfa_add_transition(anchor, star_state, any_sid);
                nfa_add_transition(star_state, star_state, any_sid);
                int finalized_star = nfa_finalize_state(star_state);
                (*pos)++;
                
                // Set current_fragment
                memset(&current_fragment, 0, sizeof(current_fragment));
                current_fragment.anchor_state = anchor;
                current_fragment.is_single_char = false;
                current_fragment.exit_state = finalized_star;
                
                return finalized_star;
            }
            if (c == ' ' || c == '\t') {
                // Handle space and tab characters - create transitions
                // Per documentation: "Space normalizes to [ \t]+ (one or more whitespace)"
                 int space_sid = VSYM_SPACE;
                int tab_sid = VSYM_TAB;
                int sid = (c == ' ') ? space_sid : tab_sid;
                if (sid != -1) {
                    // Ensure dedicated anchor state
                    int anchor = start_state;
                    if (anchor == 0) {
                        anchor = nfa_add_state_with_minimization(false);
                        nfa_add_transition(0, anchor, VSYM_EPS);
                    }

                    // Create loop state for one-or-more spaces (implicit + quantifier)
                    int loop_state = nfa_add_state_with_minimization(false);
                    state_do_not_share[loop_state] = true;

                    // Create exit state for when done consuming spaces
                    int exit_state = nfa_add_state_with_minimization(false);
                    state_do_not_share[exit_state] = true;

                    // Loop: loop_state --space/tab--> loop_state
                    nfa_add_transition(loop_state, loop_state, space_sid);
                    nfa_add_transition(loop_state, loop_state, tab_sid);

                    // Entry: anchor --space/tab--> loop_state (add BOTH space and tab)
                    nfa_add_transition(anchor, loop_state, space_sid);
                    nfa_add_transition(anchor, loop_state, tab_sid);

                    // Exit: loop_state --EPSILON--> exit_state (to continue after spaces)
                    nfa_add_transition(loop_state, exit_state, VSYM_EPS);

                    nfa_finalize_state(exit_state);
                    memset(&current_fragment, 0, sizeof(current_fragment));
                    current_fragment.anchor_state = anchor;
                    current_fragment.is_single_char = true;
                    current_fragment.loop_char = c;
                    current_fragment.loop_entry_state = loop_state;
                    current_fragment.exit_state = exit_state;
                    current_is_char_class = false;
                    (*pos)++;
                    return exit_state;
                }
                (*pos)++;
                break;
            }
            if (c != '\0') {
                // Don't consume postfix operators - let parse_rdp_postfix handle them
                if (c == '*' || c == '+' || c == '?') {
                    return start_state;
                }
                int sid = find_symbol_id(c);
                if (sid != -1) {
                    // Bug 1 fix: For root patterns (start_state == 0), don't add EPSILON
                    // Use state 0 directly as anchor for root patterns
                    int anchor = start_state;
                    if (anchor == 0) {
                        anchor = 0;  // Use state 0 directly as anchor for root
                    } else {
                        anchor = nfa_add_state_with_minimization(false);
                        nfa_add_transition(start_state, anchor, VSYM_EPS);
                    }

                    int new_state = nfa_add_state_with_minimization(false);
                    nfa_add_transition(anchor, new_state, sid);
                    int finalized_state = nfa_finalize_state(new_state);
                    memset(&current_fragment, 0, sizeof(current_fragment));
                    current_fragment.anchor_state = anchor;
                    current_fragment.is_single_char = true;
                    current_fragment.loop_char = c;
                    current_fragment.loop_entry_state = anchor;  // State BEFORE consuming char
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
    DEBUG_NFA_PRINT("parse_rdp_postfix: has_pending_quantifier=%d, exit_state=%d, loop_entry=%d\n",
                    has_pending_quantifier, current_fragment.exit_state, current_fragment.loop_entry_state);
#if NFA_BUILDER_VERBOSE
    fprintf(stderr, ">>> parse_rdp_postfix ENTRY: pattern='%s', pos=%d\n", pattern, *pos);
    fflush(stderr);
#endif
    int current;
    // CRITICAL FIX: Only use current_fragment if it was set for this specific element
    // The exit_state must be valid (>= 0) AND not be a stale value from a previous parse
    // We track this by checking if we're in a pending quantifier context
    bool current_fragment_valid = (current_fragment.exit_state >= 0 && has_pending_quantifier);
    if (current_fragment_valid) {
        // Element was already parsed in parse_rdp_sequence, use its exit state
        current = current_fragment.exit_state;
        DEBUG_NFA_PRINT("Using existing exit_state: %d\n", current);
    } else if (!has_pending_quantifier && current_fragment.exit_state != -1) {
        // Element was already parsed, use its exit state for potential quantifier processing
        current = current_fragment.exit_state;
        DEBUG_NFA_PRINT("Using exit_state for quantifier: %d\n", current);
    } else {
        // Element not yet parsed, parse it now
        current = parse_rdp_element(pattern, pos, start_state);
        DEBUG_NFA_PRINT("Parsed new element, current=%d\n", current);
    }

    while (pattern[*pos] != '\0') {
        char op = pattern[*pos];
        DEBUG_NFA_PRINT("while loop: pos=%d, op='%c' (0x%02x)\n", *pos, op, (unsigned char)op);

        int epsilon_sid = VSYM_EPS;
        if (epsilon_sid == -1) break;

        if (op == '*') {
            // Check for standalone wildcard (*) group - handled by parse_rdp_element
            if (*pos > 0 && pattern[*pos - 1] == '(') {
                break;
            }

            (*pos)++;

            // Create exit state
            int exit_state = nfa_add_state_with_minimization(false);
            state_do_not_share[exit_state] = true;

            // Loop back to the START of the element (anchor_state), not the end
            // This is critical for multi-character sequences like (AB)*
            int element_entry = current_fragment.anchor_state;
            if (element_entry < 0) element_entry = start_state;

            // Skip path (zero iterations): entry_state --EPS--> exit_state
            int skip_origin = element_entry;
            nfa_add_transition(skip_origin, exit_state, epsilon_sid);

            if (current_fragment.exit_state != -1) {
                // Loop back: exit_state_of_element --EPS--> element_entry
                int loop_target = element_entry;
                nfa_add_transition(current_fragment.exit_state, loop_target, epsilon_sid);
                
                // Connection to quantifier exit: exit_state_of_element --EPS--> exit_state
                nfa_add_transition(current_fragment.exit_state, exit_state, epsilon_sid);
            }

            nfa_finalize_state(exit_state);
            current = exit_state;
            
            // Update current_fragment for potential subsequent quantifiers
            current_fragment.anchor_state = skip_origin;
            current_fragment.exit_state = exit_state;

        } else if (op == '+') {
            (*pos)++;

            // Create exit state
            int exit_state = nfa_add_state_with_minimization(false);
            state_do_not_share[exit_state] = true;

            // Loop back to the START of the element (anchor_state), not the end
            // This is critical for multi-character sequences like (AB)+
            int element_entry = current_fragment.anchor_state;
            if (element_entry < 0) element_entry = start_state;

            if (current_fragment.exit_state != -1) {
                // Loop back: exit_state_of_element --EPS--> element_entry
                int loop_target = element_entry;
                nfa_add_transition(current_fragment.exit_state, loop_target, epsilon_sid);

                // Exit after at least one iteration: exit_state_of_element --EPS--> exit_state
                nfa_add_transition(current_fragment.exit_state, exit_state, epsilon_sid);
            }

            nfa_finalize_state(exit_state);
            current = exit_state;

            // Update current_fragment for potential subsequent quantifiers
            // For +, anchor remains same, exit is new
            current_fragment.exit_state = exit_state;

        } else if (op == '?') {
            (*pos)++;

            // Create exit state
            int exit_state = nfa_add_state_with_minimization(false);
            state_do_not_share[exit_state] = true;

            // Skip to the START of the element (anchor_state), not the end
            // This is critical for multi-character sequences like (AB)?
            int element_entry = current_fragment.anchor_state;
            if (element_entry < 0) element_entry = start_state;

            // Skip path (zero iterations): entry_state --EPS--> exit_state
            int skip_origin = element_entry;
            nfa_add_transition(skip_origin, exit_state, epsilon_sid);

            if (current_fragment.exit_state != -1) {
                // Take path (one iteration): exit_state_of_element --EPS--> exit_state
                nfa_add_transition(current_fragment.exit_state, exit_state, epsilon_sid);
            }

            nfa_finalize_state(exit_state);
            current = exit_state;
            
            // Update current_fragment
            current_fragment.anchor_state = skip_origin;
            current_fragment.exit_state = exit_state;

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
    // CRITICAL: Reset pattern state at the start of each alternative
    // This isolates each pattern's pending markers from other patterns
    // Prevents cross-pattern contamination when states are shared
    reset_nfa_builder_pattern_state();

    // Create Anchor State (Dedicated Entry Point)
    // CRITICAL FIX: Always create dedicated anchor state for alternation
    // This prevents multiple alternatives from sharing the same state and ensures
    // each branch gets its own literal transitions
    int anchor_state;
    int epsilon_sid = VSYM_EPS;
    if (start_state == 0) {
        // Create dedicated anchor for alternation - isolated from state 0
        anchor_state = nfa_add_state_with_minimization(false);
        nfa_add_transition(0, anchor_state, VSYM_EPS);
    } else {
        anchor_state = nfa_add_state_with_minimization(false);
        if (epsilon_sid != -1) {
            nfa_add_transition(start_state, anchor_state, epsilon_sid);
        } else {
            anchor_state = start_state;
        }
    }

    // Mark that we're inside a group - this allows quantifiers on parenthesized groups
    bool was_in_group = current_is_in_group;
    current_is_in_group = true;

    // Parse first alternative
    int first_end = parse_rdp_sequence(pattern, pos, anchor_state);

    // Restore previous group state
    current_is_in_group = was_in_group;

    // Check for alternation operator
    if (pattern[*pos] == '|') {
        // Create merge state for alternation
        int merge_state = nfa_add_state_with_minimization(false);

        // Connect first branch to merge via EPSILON (non-consuming transition)
        int epsilon_sid = VSYM_EPS;
        if (epsilon_sid != -1) {
            nfa_add_transition(first_end, merge_state, epsilon_sid);
        }

        // Parse remaining alternatives
        int last_branch_end = first_end;
        bool has_empty_alternative = false;
        while (pattern[*pos] == '|') {
            (*pos)++; // Skip |
            
            // FIX: Check for empty alternative - nothing after | before ) or end
            if (pattern[*pos] == ')' || pattern[*pos] == '\0') {
                // Empty alternative - connect anchor to merge for empty match
                if (epsilon_sid != -1) {
                    nfa_add_transition(anchor_state, merge_state, epsilon_sid);
                }
                has_empty_alternative = true;
                continue;
            }
            
            int branch_end = parse_rdp_sequence(pattern, pos, anchor_state);

            if (epsilon_sid != -1) {
                nfa_add_transition(branch_end, merge_state, epsilon_sid);
            }
            
            // Track the last branch end for continuation
            last_branch_end = branch_end;
        }

        // CRITICAL FIX: Propagate continuation from last branch to merge_state
        // The merge_state (where all branches converge) needs outgoing transitions
        // to allow continuation to subsequent fragments in the pattern.
        // Add EPSILON from merge_state to last_branch_end, so from merge_state
        // you can continue to the next fragment via the last branch's path.
        if (last_branch_end != merge_state && epsilon_sid != -1) {
            nfa_add_transition(merge_state, last_branch_end, epsilon_sid);
        }

        // Mark merge_state as accepting IF:
        // - This is a real pattern (current_pattern_index >= 0)
        // - AND (the group has an empty alternative OR the group ends at pattern end)
        // NOTE: Don't mark as accepting when followed by * or ? - those are handled by parse_rdp_postfix
        // This fixes premature acceptance where (git|svn) would match "git" alone
        // while still allowing (a|)b to match "b"
        // CRITICAL FIX: Don't include followed_by_plus - + quantifier requires at least one match
        // and should NOT be marked as is_eos_target (which allows empty matching)
        if (current_pattern_index >= 0) {
            // First, skip past any ) to find what really follows the group
            int check_pos = *pos;
            while (pattern[check_pos] == ')') check_pos++;
            
            char next_char = pattern[check_pos];
            bool end_of_pattern = (next_char == '\0');
            
            if (has_empty_alternative || end_of_pattern) {
                nfa[merge_state].category_mask = current_pattern_cat_mask;
                nfa[merge_state].is_eos_target = true;
                nfa[merge_state].pattern_id = current_pattern_index + 1;
            }
        }

        // Close paren if present
        if (pattern[*pos] == ')') {
            (*pos)++;
            // Update current_fragment to reflect the group structure
            memset(&current_fragment, 0, sizeof(current_fragment));
            current_fragment.is_single_char = false;
            current_fragment.anchor_state = anchor_state;
            current_fragment.exit_state = merge_state;
            current_fragment.fragment_entry_state = start_state;
            // Find first character of the group
            for (int s = 0; s < MAX_SYMBOLS; s++) {
                if (nfa[start_state].transitions[s] != -1) {
                    current_fragment.loop_first_char = alphabet[s].start_char;
                    break;
                }
            }
        }

        // CRITICAL FIX: Ensure anchor_state is set before quantifier handling
        // For patterns like (a|b)+, we reach here without going through the ) branch above,
        // so current_fragment.anchor_state is not set. The + quantifier needs anchor_state
        // to properly loop back to the start of the alternation.
        if (current_fragment.anchor_state < 0) {
            current_fragment.anchor_state = anchor_state;
        }
        if (current_fragment.exit_state < 0) {
            current_fragment.exit_state = merge_state;
        }

        // Handle postfix quantifiers (* + ?) on the alternation result
        // IMPORTANT: Pass merge_state, not first_end
        int postfix_result = parse_rdp_postfix(pattern, pos, merge_state);

        nfa_finalize_state(merge_state);
        return postfix_result;
    }

    // Close paren if present
    if (pattern[*pos] == ')') {
        (*pos)++;
        // CRITICAL FIX: Preserve is_single_char and loop_entry_state from inner element
        // The parse_rdp_element call inside parse_rdp_sequence may have set these
        // We must NOT overwrite them as the + and ? quantifiers depend on them
        bool preserved_is_single_char = current_fragment.is_single_char;
        int preserved_loop_entry_state = current_fragment.loop_entry_state;

        // Update current_fragment to reflect the group structure
        memset(&current_fragment, 0, sizeof(current_fragment));
        // Restore preserved values - single-char groups need loop_entry_state for +/* handlers
        current_fragment.anchor_state = anchor_state;
        current_fragment.is_single_char = preserved_is_single_char;
        current_fragment.loop_entry_state = preserved_loop_entry_state;
        current_fragment.exit_state = first_end;
        current_fragment.fragment_entry_state = start_state;
        // Find first character of the group (only if not single-char which already has it)
        if (!preserved_is_single_char) {
            for (int s = 0; s < MAX_SYMBOLS; s++) {
                if (nfa[start_state].transitions[s] != -1) {
                    current_fragment.loop_first_char = alphabet[s].start_char;
                    break;
                }
            }
        }
    }

    // Handle postfix quantifiers (* + ?) on the sequence result
    // CRITICAL: Set current_is_in_group=true for postfix handler - it checks this flag
    bool saved_in_group = current_is_in_group;
    current_is_in_group = true;
    int postfix_result = parse_rdp_postfix(pattern, pos, first_end);
    current_is_in_group = saved_in_group;

    int finalized_end = nfa_finalize_state(postfix_result);
    return finalized_end;
}

// Forward declaration for category mapping lookup
static int lookup_acceptance_category(const char* category, const char* subcategory, const char* operations);

// Main entry point: parse pattern and build NFA
static void parse_pattern_full(const char* pattern, const char* category,
                                const char* subcategory, const char* operations,
                                const char* action) {
    fprintf(stderr, "DEBUG parse_pattern_full called: pattern='%s'\n", pattern);
    // Clear per-pattern globals to avoid stale values between patterns
    last_element_sid = -1;
    pending_capture_defer_id = -1;
    memset(&current_fragment, 0, sizeof(current_fragment));
    current_fragment.exit_state = -1;
    current_is_char_class = false;
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

        int first_char_sid = find_symbol_id(pattern[0]);

        // Check if this is a single-character symbol (not a range)
        // For ranges like 'a'-'z', we can't safely use prefix sharing because
        // the transition might have been built for a different character in the range
        bool is_single_char_symbol = (first_char_sid != -1 &&
                                       alphabet[first_char_sid].start_char == alphabet[first_char_sid].end_char);

        // Check if pattern[0] is safe to share (not start of complex syntax or quantified)
        // Also exclude '<' and '>' as they start capture groups which are not literal transitions
        bool is_safe_first = (strchr("()[]*+?|\\'\"<>", pattern[0]) == NULL) &&
                             (pattern[1] != '*' && pattern[1] != '+' && pattern[1] != '?');

        if (first_char_sid != -1 && nfa[0].transitions[first_char_sid] != -1 && is_single_char_symbol && is_safe_first) {
            // Collect all target states for this transition (handles multi-target transitions)
            int targets[MAX_STATES];
            int target_count = 0;
            targets[target_count++] = nfa[0].transitions[first_char_sid];
            // Check for additional targets in multi_targets
            if (mta_is_multi(&nfa[0].multi_targets, first_char_sid)) {
                int mta_count = 0;
                int* mta_targets = mta_get_target_array(&nfa[0].multi_targets, first_char_sid, &mta_count);
                if (mta_targets) {
                    for (int i = 0; i < mta_count; i++) {
                        if (target_count < MAX_STATES) {
                            targets[target_count++] = mta_targets[i];
                        }
                    }
                }
            }

            // Try following each target to find longest common prefix
            int best_shared_state = -1;
            int best_shared_pos = 0;

            // Relaxed prefix sharing: Allow sharing states from different patterns
            // provided they are intermediate states.
            
            for (int t = 0; t < target_count; t++) {
                int curr_state = targets[t];
                int curr_pos = 1;

                while (curr_pos < (int)strlen(pattern)) {
                    int c = pattern[curr_pos];
                    
                    // Only share safe literals to avoid breaking complex syntax (groups, classes, wildcards)
                    // and to allow quantifiers to work correctly
                    // Exclude '<' and '>' for capture groups
                    if (strchr("()[]*+?|\\'\"<>", c) != NULL) {
                        break;
                    }
                    // Also check lookahead for quantifiers
                    if (pattern[curr_pos+1] == '*' || pattern[curr_pos+1] == '+' || pattern[curr_pos+1] == '?') {
                        break;
                    }

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

            // Only share prefix if a common prefix was found (best_shared_pos > 1)
            if (best_shared_pos > 1) {
                // Found common prefix - start from there
                shared_state = best_shared_state;
                (void)best_shared_pos;
                start_state = shared_state;
                pattern_start_pos = best_shared_pos;
                DEBUG_PRINT("SHARED prefix at pos %d, state %d\n", best_shared_pos, best_shared_state);
            } else {
                // No common prefix - create new start state
                start_state = nfa_add_state_with_minimization(false);
                DEBUG_PRINT("NEW start_state=%d for pattern_id %d, adding transition 0->%d on %d\n",
                         start_state, current_pattern_index, start_state, first_char_sid);
                nfa_add_transition(0, start_state, first_char_sid);
                DEBUG_PRINT("After add_transition: transitions[%d]=%d\n",
                        first_char_sid, nfa[0].transitions[first_char_sid]);
                pattern_start_pos = 1;  // Skip first character (already consumed)
            }
        } else {
            // If it's a safe literal, we can still start a new path from State 0
            if (is_safe_first && first_char_sid != -1) {
                start_state = nfa_add_state_with_minimization(false);
                nfa_add_transition(0, start_state, first_char_sid);
                pattern_start_pos = 1;
            } else {
                // Not safe to consume (metacharacter or quantified), start RDP from State 0
                start_state = 0;
                pattern_start_pos = 0;
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
    
    // ROOT BRANCHING: If start_state is 0, we must avoid EPSILON if possible
    // to prevent pattern interference.
    if (remaining[0] != '\0') {
        if (start_state == 0) {
            // CRITICAL FIX: Create dedicated entry state to prevent
            // quantifier zero-match paths from making state 0 accepting.
            // Each pattern now gets its own entry state reachable from state 0 via epsilon,
            // rather than using state 0 directly. This prevents patterns like (a)+ from
            // creating accepting paths from the initial state.
            int real_start = nfa_add_state_with_minimization(false);
            nfa_add_transition(0, real_start, VSYM_EPS);
            
            // Check if remaining contains alternation - if so, use parse_rdp_alternation
            // to handle cases like (abc)| at root level
            bool has_alternation = false;
            for (int i = 0; remaining[i] != '\0'; i++) {
                if (remaining[i] == '|' && i > 0 && remaining[i-1] != '\\') {
                    has_alternation = true;
                    break;
                }
            }
            
            if (has_alternation) {
                end_state = parse_rdp_alternation(remaining, &parse_pos, real_start);
            } else {
                end_state = parse_rdp_sequence(remaining, &parse_pos, real_start);
            }
        } else {
            end_state = parse_rdp_alternation(remaining, &parse_pos, start_state);
        }
    } else {
        end_state = start_state;
    }

    // Add EOS transition to accepting state
    int eos_sid = VSYM_EOS;
    if (eos_sid != -1) {
        int eos_target_state = end_state;

        // CRITICAL: If end_state is 0, we MUST NOT set its category_mask
        // Create a new state instead.
        if (end_state == 0) {
            eos_target_state = nfa_add_state_with_minimization(false);
            nfa_add_transition(0, eos_target_state, VSYM_EPS);
        }

        // Check if eos_target_state is a shared state with outgoing transitions
        // If so, create a fork state to avoid marking the shared state as accepting
        // CRITICAL: Also create fork state if end_state is an accepting state (category_mask != 0)
        // This prevents marking + quantifier intermediate states as EOS target
        // PHASE 2 FIX: Exclude self-loops (EPSILON from X to X) from has_outgoing check
        bool has_outgoing = false;
        for (int s = 0; s < MAX_SYMBOLS; s++) {
            int t = nfa[end_state].transitions[s];
            // Exclude self-loops: transition to same state
            if (t != -1 && t != end_state) {
                has_outgoing = true;
                break;
            }
            // Check multi-target transitions, excluding self-loops
            if (mta_is_multi(&nfa[end_state].multi_targets, s)) {
                int cnt = 0;
                int* targets = mta_get_target_array(&nfa[end_state].multi_targets, s, &cnt);
                for (int i = 0; i < cnt; i++) {
                    if (targets[i] != end_state) {  // Exclude self-loop
                        has_outgoing = true;
                        break;
                    }
                }
                if (has_outgoing) break;
            }
        }
        
        // PHASE 2 FIX: Also check EPSILON transitions, excluding self-loops
        if (!has_outgoing && mta_is_multi(&nfa[end_state].multi_targets, VSYM_EPS)) {
            int eps_cnt = 0;
            int* eps_targets = mta_get_target_array(&nfa[end_state].multi_targets, VSYM_EPS, &eps_cnt);
            for (int i = 0; i < eps_cnt; i++) {
                if (eps_targets[i] != end_state) {  // Exclude self-loop
                    has_outgoing = true;
                    break;
                }
            }
        }
        // If end_state is an accepting state (has category_mask), treat as having outgoing
        // This ensures + quantifier states like 129 don't get marked as EOS target
        if (nfa[end_state].category_mask != 0) {
            has_outgoing = true;
        }
        DEBUG_PRINT("finalize: end_state=%d, has_outgoing=%d, is_eos_target before=%d, cat_mask=0x%02x\n",
                end_state, has_outgoing, nfa[end_state].is_eos_target, nfa[end_state].category_mask);
        
        // Debug: print EPSILON transitions from end_state
        int eps_sid = VSYM_EPS;
        if (eps_sid != -1 && mta_is_multi(&nfa[end_state].multi_targets, eps_sid)) {
            int eps_cnt = 0;
            int* eps_targets = mta_get_target_array(&nfa[end_state].multi_targets, eps_sid, &eps_cnt);
            fprintf(stderr, "DEBUG: end_state=%d has %d EPSILON targets: ", end_state, eps_cnt);
            for (int i = 0; i < eps_cnt; i++) {
                fprintf(stderr, "%d ", eps_targets[i]);
            }
            fprintf(stderr, "\n");
        }

        if (has_outgoing) {
            fprintf(stderr, "DEBUG: has_outgoing=true, creating fork state\n");
            // Create a fork state - this is where the pattern can end
            // The shared end_state continues to its other transitions
            // IMPORTANT: Don't mark end_state as EOS target - it's shared and shouldn't accept here
            eos_target_state = nfa_add_state_with_minimization(false);
            nfa[eos_target_state].is_eos_target = true;  // Only the fork state accepts
            // QUANTIFIER FIX: Set category on fork state so DFA can see it in epsilon closure
            nfa[eos_target_state].category_mask = cat_mask;
            nfa_add_transition(end_state, eos_target_state, eos_sid);
            nfa_finalize_state(end_state);
            // DO NOT mark end_state as EOS target - it has outgoing transitions (shared state)

            // CRITICAL FIX: The accepting state needs pattern_id set to be recognized as accepting
            // Create accepting state with proper initialization
            int accepting = nfa_state_count;
            nfa_state_count++;
            nfa[accepting].category_mask = cat_mask;  // Set category for proper matching
            nfa[accepting].pattern_id = (current_pattern_index >= 0) ? (uint16_t)(current_pattern_index + 1) : 0;
            nfa[accepting].is_eos_target = true;
            nfa[accepting].tag_count = 0;
            for (int j = 0; j < MAX_TAGS; j++) nfa[accepting].tags[j] = NULL;
            for (int j = 0; j < MAX_SYMBOLS; j++) nfa[accepting].transitions[j] = -1;
            mta_init(&nfa[accepting].multi_targets);
            state_do_not_share[accepting] = true;
            nfa_add_transition(eos_target_state, accepting, eos_sid);
        }

        // When has_outgoing=false, eos_target_state == end_state, so mark it as EOS target
        if (!has_outgoing) {
            nfa[eos_target_state].is_eos_target = true;
            nfa[eos_target_state].category_mask = cat_mask;  // Set category for end_state
            nfa[eos_target_state].pattern_id = (current_pattern_index >= 0) ? (uint16_t)(current_pattern_index + 1) : 0;
            state_do_not_share[eos_target_state] = true;  // CONSERVATIVE: Don't share accepting states
        }

        nfa_add_tag(eos_target_state, category);
        if (subcategory[0] != '\0') nfa_add_tag(eos_target_state, subcategory);
        if (operations[0] != '\0') nfa_add_tag(eos_target_state, operations);
        nfa_add_tag(eos_target_state, action);

        nfa_finalize_state(eos_target_state);
    }
}

// Parse advanced pattern
void parse_advanced_pattern(const char* line) {
    // Format: [category:subcategory:operations] pattern -> action
    // Or: [fragment:name] value
    // Or: [characterset:name] value

    // Skip IDENTIFIER directive lines
    if (strncmp(line, "IDENTIFIER", 10) == 0 && (line[10] == ' ' || line[10] == '"')) {
        return;
    }

    char category[64] = "safe";
    char subcategory[64] = "";
    char operations[256] = "";
    char action[32] = "allow";
    char pattern[MAX_LINE_LENGTH] = "";

    // Skip leading whitespace
    while (*line == ' ' || *line == '\t') line++;

    // DETECT OLD FORMAT PATTERNS
    // Old format: pattern :one :cat :ops (annotations after pattern)
    // New format: [category:subcategory:operations] pattern -> action
    // Also check for patterns that start with annotations like :one :cat :ops
    if (*line != '[' && *line != '#') {
        // Check for old-style annotations at start of line
        if (*line == ':' || 
            (line[0] == 'a' && line[1] == '(') ||
            (strstr(line, " :one") != NULL) ||
            (strstr(line, " :cat") != NULL) ||
            (strstr(line, " :ops") != NULL) ||
            (strstr(line, " :fragment") != NULL) ||
            (strstr(line, " :allow") != NULL) ||
            (strstr(line, " :block") != NULL)) {
            fprintf(stderr, "ERROR: Detected OLD FORMAT pattern. Please update to new format.\n");
            fprintf(stderr, "  Old format: pattern :one :cat :ops\n");
            fprintf(stderr, "  New format: [category:subcategory:operations] pattern -> action\n");
            fprintf(stderr, "  Example: [safe:test] abc -> allow\n");
            fprintf(stderr, "  Found: %s\n", line);
            fprintf(stderr, "  NOTE: Annotations (:one, :cat, :ops) must now be inside brackets [].\n");
            fprintf(stderr, "  File: %s\n", current_input_file ? current_input_file : "(unknown)");
            exit(1);
        }
    }

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
                
                // Validate: Check for empty fragment value
                const char* value_start = name_end + 1;
                while (*value_start == ' ' || *value_start == '\t') value_start++;
                // Check for empty value (end of line, comment, or whitespace only)
                if (*value_start == '\0' || *value_start == '\n' || *value_start == '#') {
                    fprintf(stderr, "ERROR: Fragment '%s' has empty value. Fragment must have a non-empty value.\n",
                            fragments[fragment_count].name);
                    has_fragment_error = true;
                    return;
                }
                
                // Validate: Check for duplicate fragment name
                for (int i = 0; i < fragment_count; i++) {
                    if (strcmp(fragments[i].name, fragments[fragment_count].name) == 0) {
                        fprintf(stderr, "ERROR: Duplicate fragment name '%s'. Each fragment must have a unique name.\n",
                                fragments[fragment_count].name);
                        has_fragment_error = true;
                        return;
                    }
                }
                
                // Store fragment value
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
        strncpy(patterns[pattern_count].pattern, pattern, MAX_LINE_LENGTH);
        strncpy(patterns[pattern_count].category, category, sizeof(patterns[pattern_count].category));
        strncpy(patterns[pattern_count].subcategory, subcategory, sizeof(patterns[pattern_count].subcategory));
        strncpy(patterns[pattern_count].operations, operations, sizeof(patterns[pattern_count].operations));
        strncpy(patterns[pattern_count].action, action, sizeof(patterns[pattern_count].action));
        patterns[pattern_count].category_id = parse_category(category);
        current_pattern_index = pattern_count;  // Set BEFORE incrementing
        pattern_count++;
    }

    // CRITICAL: Clear all pending markers before starting new pattern
    // This prevents cross-pattern contamination from any leftover markers
    pending_marker_count = 0;

    // Use the new recursive descent parser to build NFA
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
    char* end;
    long acceptance_cat_long = strtol(arrow + 2, &end, 10);
    if (end == arrow + 2 || acceptance_cat_long < 0 || acceptance_cat_long > 7) {
        fprintf(stderr, "Warning: Invalid acceptance category: %s\n", line);
        return;
    }
    int acceptance_cat = (int)acceptance_cat_long;

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
        strncpy(mapping->category, category, sizeof(mapping->category));
        strncpy(mapping->subcategory, subcategory, sizeof(mapping->subcategory));
        strncpy(mapping->operations, operations, sizeof(mapping->operations));
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

    current_input_file = filename;

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

        // Skip leading whitespace
        const char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') continue;

        // Handle #ACCEPTANCE_MAPPING or ACCEPTANCE_MAPPING directive
        if (strncmp(p, "#ACCEPTANCE_MAPPING", 19) == 0 || strncmp(p, "ACCEPTANCE_MAPPING", 18) == 0) {
            parse_acceptance_mapping(p);
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
        
        // Write capture markers (Phase 2: with names for metadata table)
        if (nfa[i].capture_start_id >= 0) {
            const char* cap_name = get_capture_name(nfa[i].capture_start_id);
            if (cap_name) {
                fprintf(file, "  CaptureStart: %d %s\n", nfa[i].capture_start_id, cap_name);
            } else {
                fprintf(file, "  CaptureStart: %d\n", nfa[i].capture_start_id);
            }
        }
        if (nfa[i].capture_end_id >= 0) {
            const char* cap_name = get_capture_name(nfa[i].capture_end_id);
            if (cap_name) {
                fprintf(file, "  CaptureEnd: %d %s\n", nfa[i].capture_end_id, cap_name);
            } else {
                fprintf(file, "  CaptureEnd: %d\n", nfa[i].capture_end_id);
            }
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
            int count = mta_get_target_count(&nfa[i].multi_targets, s);
            if (count > 0) {
                int* targets = mta_get_target_array(&nfa[i].multi_targets, s, &count);
                if (targets && count > 0) {
                    fprintf(file, "    Symbol %d -> ", s);
                    for (int k = 0; k < count; k++) {
                        fprintf(file, "%d%s", targets[k], (k < count - 1) ? "," : "");
                    }
                    // Write markers attached to this transition
                    int marker_count = 0;
                    transition_marker_t* markers = mta_get_markers(&nfa[i].multi_targets, s, &marker_count);
                    if (markers && marker_count > 0) {
                        fprintf(stderr, "[WRITE NFA] State %d, sym %d: reading %d markers from MTA\n", i, s, marker_count);
                        fprintf(file, " [Markers:");
                        for (int m = 0; m < marker_count; m++) {
                            uint32_t full_marker = MARKER_PACK(markers[m].pattern_id, markers[m].uid, markers[m].type);
                            fprintf(stderr, "[WRITE NFA]   marker[%d] pid=%d uid=%d type=%d -> 0x%08X\n",
                                    m, markers[m].pattern_id, markers[m].uid, markers[m].type, full_marker);
                            fprintf(file, " 0x%08X", full_marker);
                        }
                        fprintf(file, "]");
                    } else if (marker_count > 0) {
                        fprintf(stderr, "[WRITE NFA] State %d, sym %d: MTA has %d markers but markers ptr is NULL!\n", i, s, marker_count);
                    }
                    fprintf(file, "\n");
                }
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
            nfa[i].tags[j] = NULL;
        }
        mta_free(&nfa[i].multi_targets);
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

#ifndef NFABUILDER_NO_MAIN

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
        if (strncmp(line, "[fragment:", 10) == 0) {
            char* name_start = line + 10;
            char* bracket = strchr(name_start, ']');
            if (!bracket) {
                fprintf(stderr, "Error: Malformed fragment definition at line %d: %s\n", line_num, line);
                errors++;
                continue;
            }
            
            // Extract fragment name
            size_t name_len = bracket - name_start;
            char frag_name[64];
            if (name_len >= sizeof(frag_name)) {
                fprintf(stderr, "Error: Fragment name too long at line %d\n", line_num);
                errors++;
                continue;
            }
            strncpy(frag_name, name_start, name_len);
            frag_name[name_len] = '\0';
            
            // Check for empty value
            const char* value_start = bracket + 1;
            while (*value_start == ' ' || *value_start == '\t') value_start++;
            if (*value_start == '\0' || *value_start == '\n' || *value_start == '#') {
                fprintf(stderr, "Error: Fragment '%s' has empty value at line %d. Fragment must have a non-empty value.\n", 
                        frag_name, line_num);
                errors++;
                continue;
            }
            
            if (flag_verbose_validation) {
                fprintf(stderr, "  Line %d: Fragment '%s' = '%s'\n", line_num, frag_name, value_start);
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
    (void)spec_file; 
    
    // Reset alphabet
    built_alphabet_size = 0;
    
    // 1. Literal Bytes (0-255)
    for (int i = 0; i < 256; i++) {
        built_alphabet[i].start_char = i;
        built_alphabet[i].end_char = i;
        built_alphabet[i].symbol_id = i;
        built_alphabet[i].is_special = false;
        built_alphabet_size++;
    }
    
    // 2. Virtual Symbols (256+)
    // ANY
    built_alphabet[VSYM_ANY].start_char = 0;
    built_alphabet[VSYM_ANY].end_char = 255;
    built_alphabet[VSYM_ANY].symbol_id = VSYM_ANY;
    built_alphabet[VSYM_ANY].is_special = true;
    built_alphabet_size++;

    // EPSILON
    built_alphabet[VSYM_EPS].start_char = 1;
    built_alphabet[VSYM_EPS].end_char = 1;
    built_alphabet[VSYM_EPS].symbol_id = VSYM_EPS;
    built_alphabet[VSYM_EPS].is_special = true;
    built_alphabet_size++;

    // EOS
    built_alphabet[VSYM_EOS].start_char = 5;
    built_alphabet[VSYM_EOS].end_char = 5;
    built_alphabet[VSYM_EOS].symbol_id = VSYM_EOS;
    built_alphabet[VSYM_EOS].is_special = true;
    built_alphabet_size++;

    // Normalized SPACE
    built_alphabet[VSYM_SPACE].start_char = 32;
    built_alphabet[VSYM_SPACE].end_char = 32;
    built_alphabet[VSYM_SPACE].symbol_id = VSYM_SPACE;
    built_alphabet[VSYM_SPACE].is_special = true;
    built_alphabet_size++;

    // Normalized TAB
    built_alphabet[VSYM_TAB].start_char = 9;
    built_alphabet[VSYM_TAB].end_char = 9;
    built_alphabet[VSYM_TAB].symbol_id = VSYM_TAB;
    built_alphabet[VSYM_TAB].is_special = true;
    built_alphabet_size++;
    
    if (flag_verbose_alphabet) {
        fprintf(stderr, "  Literal symbols: 256\n");
        fprintf(stderr, "  Virtual symbols: %d\n", built_alphabet_size - 256);
        fprintf(stderr, "  Total alphabet size: %d\n", built_alphabet_size);
    }
    
    // Copy to global alphabet
    for (int i = 0; i < built_alphabet_size && i < MAX_SYMBOLS; i++) {
        alphabet[i] = built_alphabet[i];
    }
    alphabet_size = built_alphabet_size;
    
    if (flag_verbose_alphabet) {
        fprintf(stderr, "\nAlphabet constructed successfully\n");
    }
    
    return true;
}

#endif  // NFABUILDER_NO_MAIN

// Main function
#ifndef NFABUILDER_NO_MAIN
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
#endif
