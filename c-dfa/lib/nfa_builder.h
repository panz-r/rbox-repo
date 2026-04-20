/**
 * nfa_builder.h - Shared context and types for NFA builder modules
 *
 * All modules (nfa_parser, nfa_construct, nfa_alphabet, nfa_capture, nfa_validate)
 * communicate through nfa_builder_context_t, eliminating global state.
 */

#ifndef NFA_BUILDER_H
#define NFA_BUILDER_H

#include <stdbool.h>
#include <stdint.h>
#include "../include/nfa.h"
#include "../include/dfa_types.h"
#include "../include/multi_target_array.h"

// Category IDs (generic, pattern-defined)
enum {
    CAT_0 = 0,
    CAT_1,
    CAT_2,
    CAT_3,
    CAT_4,
    CAT_5,
    CAT_6,
    CAT_7,
    CAT_COUNT
};

// Fragment constants
#define MAX_FRAGMENTS     100
#define MAX_FRAGMENT_NAME  64
#define MAX_FRAGMENT_VALUE 512

// Capture constants
#define MAX_CAPTURE_NAME 32
// DFA_MAX_CAPTURES comes from dfa_types.h

// Marker constants
#define MAX_MARKER_LISTS 4096

// Category mapping
#define MAX_CATEGORY_MAPPINGS 64
#define MAX_CATEGORY_NAME     64

// ============================================================================
// Type Definitions
// ============================================================================

// Character class definition
typedef struct {
    int start_char;
    int end_char;
    int symbol_id;
    bool is_special;
} char_class_t;

// Extended NFA state for nfa_builder - includes fields not needed for DFA construction
typedef struct {
    uint8_t category_mask;
    int16_t pattern_id;
    bool is_eos_target;
    char* tags[MAX_TAGS];
    int tag_count;
    int transitions[MAX_SYMBOLS];
    int transition_count;
    multi_target_array_t multi_targets;
    int8_t capture_start_id;
    int8_t capture_end_id;
    int8_t capture_defer_id;
} nfa_builder_state_t;

// State signature for on-the-fly minimization
typedef struct state_signature {
    uint64_t signature;
    int state_index;
    struct state_signature* next;
} state_signature_t;

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

// Fragment storage
typedef struct {
    char name[MAX_FRAGMENT_NAME];
    char value[MAX_FRAGMENT_VALUE];
} fragment_t;

// Capture name to ID mapping
typedef struct {
    char name[MAX_CAPTURE_NAME];
    int id;
    bool used;
} capture_mapping_t;

// Pending marker for tracking markers that need to be attached to transitions
// (re-uses pending_marker_t from nfa.h)

// Marker entry
typedef struct {
    uint16_t pattern_id;
    uint32_t uid;
    uint8_t type;
} marker_entry_t;

// Capture name to UID mapping (for metadata table)
typedef struct {
    char name[MAX_CAPTURE_NAME];
    uint32_t uid;
    bool used;
} capture_uid_mapping_t;

// Category mapping table entry
typedef struct {
    char category[64];
    char subcategory[64];
    char operations[256];
    int acceptance_category;
} category_mapping_t;

// Result of parsing a fragment
typedef struct {
    int anchor_state;
    int loop_entry_state;
    int exit_state;
    bool is_single_char;
    char loop_char;
    int capture_defer_id;
    bool has_capture;
    char capture_name[MAX_CAPTURE_NAME];
    int fragment_entry_state;
    char loop_first_char;
} fragment_result_t;

// ============================================================================
// Context Struct — all NFA builder state
// ============================================================================

typedef struct {
    // NFA state
    nfa_builder_state_t nfa[MAX_STATES];
    int nfa_state_count;

    // Pattern storage
    command_pattern_t patterns[MAX_PATTERNS];
    int pattern_count;
    int current_pattern_index;
    uint8_t current_pattern_cat_mask;

    // Alphabet
    char_class_t alphabet[MAX_SYMBOLS];
    int alphabet_size;

    // Fragment storage
    fragment_t fragments[MAX_FRAGMENTS];
    int fragment_count;
    bool has_fragment_error;

    // Capture system
    capture_mapping_t capture_map[DFA_MAX_CAPTURES];
    int capture_count;
    int capture_stack[DFA_MAX_CAPTURES];
    int capture_stack_depth;

    // Pending markers (for capture → transition attachment)
    pending_marker_t pending_markers[MAX_PENDING_MARKERS];
    int pending_marker_count;

    // Quantifier tracking
    int last_element_sid;
    int8_t pending_capture_defer_id;

    // Fragment connection tracking
    int prev_frag_exit;

    // Parse state
    fragment_result_t current_fragment;
    bool current_is_char_class;
    bool has_pending_quantifier;
    bool current_is_in_group;
    bool parsing_fragment_value;

    // Category system
    char dynamic_category_names[CAT_COUNT][MAX_CATEGORY_NAME];
    int dynamic_category_count;
    bool categories_defined;

    // Category mapping table
    category_mapping_t category_mappings[MAX_CATEGORY_MAPPINGS];
    int category_mapping_count;

    // State signature table (for minimization)
    state_signature_t* signature_table[SIGNATURE_TABLE_SIZE];

    // Configuration
    char pattern_identifier[256];
    bool flag_verbose;
    bool flag_verbose_nfa;

    // Input file tracking (for error messages)
    const char* current_input_file;
} nfa_builder_context_t;

// ============================================================================
// Context Lifecycle
// ============================================================================

/**
 * Allocate and initialize a new builder context.
 * Returns NULL on allocation failure.
 */
nfa_builder_context_t* nfa_builder_context_create(void);

/**
 * Free all memory associated with the builder context.
 */
void nfa_builder_context_destroy(nfa_builder_context_t* ctx);

/**
 * Finalize the NFA builder, converting internal format to nfa_graph_t.
 * Returns a newly allocated nfa_graph_t that caller owns.
 * The builder context can be destroyed after finalize.
 */
nfa_graph_t* nfa_builder_finalize(nfa_builder_context_t* ctx, bool preminimize);

// ============================================================================
// Module Function Declarations
// ============================================================================

// --- nfa_alphabet.c ---
void nfa_alphabet_load(nfa_builder_context_t* ctx, const char* filename);
bool nfa_alphabet_construct_from_patterns(nfa_builder_context_t* ctx, const char* spec_file);
int nfa_alphabet_find_symbol_id(unsigned char c);
int nfa_alphabet_find_special_symbol_id(int special_char);

// --- nfa_construct.c ---
void nfa_construct_init(nfa_builder_context_t* ctx);
int nfa_construct_add_state_with_category(nfa_builder_context_t* ctx, uint8_t category_mask);
int nfa_construct_add_state_with_minimization(nfa_builder_context_t* ctx, bool accepting);
int nfa_construct_finalize_state(nfa_builder_context_t* ctx, int state);
void nfa_construct_add_tag(nfa_builder_context_t* ctx, int state, const char* tag);
void nfa_construct_add_transition(nfa_builder_context_t* ctx, int from, int to, int symbol_id);
void nfa_construct_write_file(nfa_builder_context_t* ctx, const char* filename);
void nfa_construct_cleanup(nfa_builder_context_t* ctx);

// --- nfa_capture.c ---
int nfa_capture_get_id(nfa_builder_context_t* ctx, const char* name);
const char* nfa_capture_get_name(nfa_builder_context_t* ctx, int id);
bool nfa_capture_is_end(const char* pattern, int pos, char* cap_name);
bool nfa_capture_is_start(const char* pattern, int pos, char* cap_name);
int nfa_capture_parse_start(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state);
int nfa_capture_parse_end(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state);

// --- nfa_parser.c ---
void nfa_parser_parse_pattern(nfa_builder_context_t* ctx, const char* line);
void nfa_parser_read_spec_file(nfa_builder_context_t* ctx, const char* filename);

// RDP functions (called by nfa_capture.c for inline fragment parsing)
int nfa_parser_rdp_alternation(nfa_builder_context_t* ctx, const char* pattern, int* pos, int start_state);

// --- nfa_validate.c ---
bool nfa_validate_pattern_file(nfa_builder_context_t* ctx, const char* spec_file, bool verbose);
bool nfa_validate_pattern_input(const char* line, size_t len);

// --- Category helpers (in nfa_parser.c, used by multiple modules) ---
void nfa_category_init_defaults(nfa_builder_context_t* ctx);
void nfa_category_parse_definition(nfa_builder_context_t* ctx, const char* line);
int nfa_category_parse(nfa_builder_context_t* ctx, const char* name);
void nfa_category_add_mapping(nfa_builder_context_t* ctx, const char* category,
                               const char* subcategory, const char* operations, int acceptance_cat);
int nfa_category_lookup(nfa_builder_context_t* ctx, const char* category,
                        const char* subcategory, const char* operations);
void nfa_category_parse_mapping(nfa_builder_context_t* ctx, const char* line);

// --- Legacy compatibility (for nfa2dfa.c which uses find_symbol_id directly) ---
int find_symbol_id(unsigned char c);

#endif // NFA_BUILDER_H
