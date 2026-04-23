/**
 * nfa_dsl.h - Compact NFA serialization/deserialization DSL
 *
 * Provides a human-readable text format for dumping, comparing, and
 * verifying NFA structures. Used for testing and debugging only.
 *
 * Format overview:
 *   - Version header: "version: 1" on first line
 *   - States are numbered from 0
 *   - One state definition line per state, transitions listed below
 *   - Accepting states marked with annotations
 *   - Virtual symbols: EPS, ANY, EOS, SPACE, TAB
 *   - Markers encoded as hex 0xPPUUUT
 *
 * Example:
 *   version: 1
 *   0: start
 *   0 'a' -> 1
 *   1: accept category=0x01 pattern=1
 */

#ifndef NFA_DSL_H
#define NFA_DSL_H

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "cdfa_defines.h"
#include "dfa_types.h"
#include "nfa.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ============================================================================ */

#define NFA_DSL_VERSION       1
#define DSL_MAX_TRANSITIONS   64
#define DSL_MAX_MARKERS       8
#define DSL_MAX_TARGETS       32

/* ============================================================================
 * Parsed NFA Graph (result of deserialization)
 * ============================================================================ */

typedef struct {
    uint32_t value;
} dsl_marker_t;

typedef struct {
    int symbol_id;              /* Raw symbol ID (0-255 literal, 256+ virtual) */
    int target_count;
    int targets[DSL_MAX_TARGETS];
    int marker_count;
    dsl_marker_t markers[DSL_MAX_MARKERS];
} dsl_transition_t;

typedef struct {
    int state_id;
    bool is_start;
    bool is_accept;
    bool is_defined;             /* true if a "N:" state definition line was seen */
    uint8_t category_mask;
    int pattern_id;
    bool is_eos_target;
    int transition_count;
    dsl_transition_t transitions[DSL_MAX_TRANSITIONS];
} dsl_state_t;

typedef struct {
    int state_count;
    dsl_state_t* states;        /* Array of parsed states, indexed by state_id */
    int max_state_id;           /* Highest state ID seen (for allocation) */
    int start_state;            /* Which state is start (-1 if unspecified, default 0) */
    int alphabet_size;          /* From global metadata, or -1 if not specified */
    char identifier[256];       /* From global metadata */
    int version;                /* DSL format version (0 if absent, NFA_DSL_VERSION if current) */
    int dsl_type;               /* DSL_TYPE_NFA or DSL_TYPE_DFA */
} dsl_nfa_t;

/* ============================================================================
 * NFA Graph Serializer: Dump nfa_graph_t to DSL format
 *
 * Serializes a finalized nfa_graph_t (from nfa_builder_finalize) to DSL.
 * Uses BFS canonicalization for deterministic output.
 * ============================================================================ */

/**
 * Serialize an nfa_graph_t to DSL format (canonicalized).
 * Includes version header. Output is deterministic.
 *
 * @param out   Output FILE stream
 * @param graph Pointer to nfa_graph_t (from nfa_builder_finalize)
 */
void nfa_graph_dsl_dump(FILE *out, const nfa_graph_t *graph);

/**
 * Serialize an nfa_graph_t to a malloc'd string.
 * Caller must free() the returned pointer.
 * Returns NULL on allocation failure.
 *
 * @param graph Pointer to nfa_graph_t
 */
char *nfa_graph_dsl_to_string(const nfa_graph_t *graph);

/* ============================================================================
 * Focused Serialization: Sub-graph extraction
 * ============================================================================ */

/** Filter options for focused serialization. */
typedef struct {
    int start_state;     /* State index to start BFS from. -1 = use state 0. */
    int pattern_id_filter;  /* If >= 0, include only states reachable from
                             * start_state that belong to this pattern or are
                             * on a path to/from such states. -1 = no filter. */
    bool include_markers_for_other_patterns;  /* If false, omit markers whose
                                               packed pattern_id != pattern_id_filter.
                                               Ignored when pattern_id_filter < 0. */
} nfa_dsl_filter_t;

/** Convenience: create a filter for all states reachable from a given start. */
static inline nfa_dsl_filter_t nfa_dsl_filter_from_state(int start_state) {
    nfa_dsl_filter_t f;
    f.start_state = start_state;
    f.pattern_id_filter = -1;
    f.include_markers_for_other_patterns = true;
    return f;
}

/** Convenience: create a filter for a specific pattern. */
static inline nfa_dsl_filter_t nfa_dsl_filter_for_pattern(int pattern_id,
                                                           int start_state) {
    nfa_dsl_filter_t f;
    f.start_state = start_state;
    f.pattern_id_filter = pattern_id;
    f.include_markers_for_other_patterns = false;
    return f;
}

void nfa_graph_dsl_dump_filtered(FILE *out, const nfa_graph_t *graph, nfa_dsl_filter_t filter);
char *nfa_graph_dsl_to_string_filtered(const nfa_graph_t *graph, nfa_dsl_filter_t filter);

/* ============================================================================
 * Deserializer
 * ============================================================================ */

dsl_nfa_t *nfa_dsl_parse_file(const char *filename);
dsl_nfa_t *nfa_dsl_parse_string(const char *text);
void nfa_dsl_free(dsl_nfa_t *nfa);

/* ============================================================================
 * Comparison
 * ============================================================================ */

bool nfa_dsl_equal(const dsl_nfa_t *a, const dsl_nfa_t *b);

/* ============================================================================
 * Diff helpers
 *
 * Produce a unified-style diff between two NFA strings. Returns a malloc'd
 * string describing the differences (line-by-line), or NULL if identical.
 * Caller must free() the returned pointer.
 * ============================================================================ */

/**
 * Compute a line-by-line diff between two NFA DSL strings.
 * Returns NULL if identical, or a malloc'd diff string.
 * The diff uses "--- expected" / "+++ actual" markers and '+'/'-' prefixes.
 */
char *nfa_dsl_diff(const char *expected, const char *actual);

/**
 * Print a diff between two NFA DSL strings to stderr.
 * Returns true if they are identical, false if different.
 * On difference, prints the diff with a header showing the label.
 */
bool nfa_dsl_assert_equal(const char *label,
                           const char *expected,
                           const char *actual);

/* ============================================================================
 * Round-trip verification
 * ============================================================================ */

/**
 * Verify round-trip integrity: serialize graph -> parse -> serialize -> compare.
 * Returns NULL if the round-trip is consistent.
 * On mismatch, returns a malloc'd diff string (caller frees).
 */
char *nfa_graph_dsl_verify_roundtrip(const nfa_graph_t *graph);

/* ============================================================================
 * Validator / Linter
 * ============================================================================ */

/** Validation issue severity. */
typedef enum {
    DSL_SEVERITY_ERROR,     /* Must fix: invalid structure */
    DSL_SEVERITY_WARNING    /* May be intentional: suspicious structure */
} dsl_severity_t;

/** A single validation issue. */
typedef struct {
    dsl_severity_t severity;
    int state_id;           /* -1 if global */
    char message[256];
} dsl_issue_t;

/** Validation result. */
typedef struct {
    int issue_count;
    int issue_capacity;
    dsl_issue_t *issues;
    bool valid;             /* true if no ERROR-severity issues */
} dsl_validation_t;

/**
 * Validate a parsed NFA graph for semantic correctness.
 * Checks for:
 *   - Missing start state (ERROR)
 *   - States referenced in transitions but not defined (ERROR)
 *   - Accepting state with no category (WARNING)
 *   - Non-accepting state with no outgoing transitions (WARNING)
 *   - State with transitions to itself only (WARNING)
 *   - Version mismatch if present (WARNING)
 *
 * Returns a heap-allocated validation result. Caller must call
 * nfa_dsl_validation_free() to release.
 */
dsl_validation_t *nfa_dsl_validate(const dsl_nfa_t *nfa);

/**
 * Free a validation result.
 */
void nfa_dsl_validation_free(dsl_validation_t *v);

/**
 * Print validation issues to a FILE.
 */
void nfa_dsl_validation_print(FILE *out, const dsl_validation_t *v);

/* ============================================================================
 * DOT (Graphviz) visualization
 * ============================================================================ */

/**
 * Write a parsed NFA graph in Graphviz DOT format.
 * Produces a directed graph with states as nodes and transitions as edges.
 * Accepting states are shown as double circles. Start state has an arrow.
 *
 * @param out   Output FILE stream
 * @param nfa   Parsed NFA graph (from nfa_dsl_parse_string or nfa_dsl_parse_file)
 */
void nfa_dsl_dump_dot(FILE *out, const dsl_nfa_t *nfa);

/**
 * Write a parsed NFA graph in DOT format to a malloc'd string.
 * Caller must free() the returned pointer.
 */
char *nfa_dsl_to_dot(const dsl_nfa_t *nfa);

/* ============================================================================
 * Symbol helpers
 * ============================================================================ */

int nfa_dsl_symbol_from_name(const char *name);
const char *nfa_dsl_symbol_name(int symbol_id);

/* ============================================================================
 * DFA Serialization
 *
 * DFA uses a subset of the NFA DSL with additional features:
 *   - No epsilon transitions
 *   - Single target per symbol (deterministic)
 *   - Range syntax: 'a'-'z' -> target
 *   - Default transition: default -> target
 *
 * Header uses "type: DFA" to distinguish from NFA.
 * ============================================================================ */

/** DFA DSL type discriminator (stored in dsl_nfa_t::dsl_type). */
#define DSL_TYPE_NFA 0
#define DSL_TYPE_DFA 1

/** Parsed DFA range transition (for DFA deserialization). */
typedef struct {
    int start_char;
    int end_char;
    int target;
} dsl_dfa_range_t;

/** Parsed DFA state (extends dsl_state_t with DFA-specific fields). */
typedef struct {
    int state_id;
    bool is_start;
    bool is_accept;
    bool is_defined;
    uint8_t category_mask;
    int pattern_id;
    bool is_eos_target;
    bool has_default;
    int default_target;
    int eos_target;

    /* Individual symbol transitions (non-range, non-default) */
    int symbol_transition_count;
    dsl_transition_t symbol_transitions[DSL_MAX_TRANSITIONS];

    /* Range transitions (for compressed DFA output) */
    int range_count;
    dsl_dfa_range_t ranges[DSL_MAX_TRANSITIONS];
} dsl_dfa_state_t;

/** Parsed DFA graph. */
typedef struct {
    int dsl_type;               /* DSL_TYPE_DFA */
    int state_count;
    dsl_dfa_state_t *states;
    int max_state_id;
    int start_state;
    int alphabet_size;
    char identifier[256];
    int version;
} dsl_dfa_t;

/**
 * Serialize build-time DFA states to DSL format.
 * The DFA is an array of build_dfa_state_t pointers from the pipeline.
 *
 * Produces canonical output with:
 *   - BFS state renumbering
 *   - Range compression for consecutive same-target symbols
 *   - Default transitions for common targets
 *   - Sorted markers
 *
 * @param out              Output FILE stream
 * @param dfa              Array of DFA state pointers
 * @param state_count      Number of DFA states
 * @param alphabet         Alphabet entries
 * @param alphabet_size    Alphabet size
 * @param marker_lists     Marker list storage (may be NULL)
 * @param marker_list_count Number of marker lists
 */
void dfa_dsl_dump(FILE *out,
                   const build_dfa_state_t * const *dfa,
                   int state_count,
                   const alphabet_entry_t *alphabet,
                   int alphabet_size,
                   const void *marker_lists,
                   int marker_list_count);

/**
 * Serialize DFA to a malloc'd string.
 * Caller must free() the returned pointer.
 */
char *dfa_dsl_to_string(const build_dfa_state_t * const *dfa,
                         int state_count,
                         const alphabet_entry_t *alphabet,
                         int alphabet_size,
                         const void *marker_lists,
                         int marker_list_count);

/**
 * Parse a DFA-format DSL string.
 * Returns a heap-allocated dsl_dfa_t on success, NULL on failure.
 * Caller must call dfa_dsl_free() to release.
 */
dsl_dfa_t *dfa_dsl_parse_string(const char *text);

/**
 * Parse a DFA-format DSL file.
 */
dsl_dfa_t *dfa_dsl_parse_file(const char *filename);

/**
 * Free a parsed DFA graph.
 */
void dfa_dsl_free(dsl_dfa_t *dfa);

/**
 * Compare two parsed DFA graphs for structural equality.
 */
bool dfa_dsl_equal(const dsl_dfa_t *a, const dsl_dfa_t *b);

/**
 * Generate a unified diff between two DFA DSL strings.
 * Returns NULL if strings match, else returns malloc'd diff string.
 */
char *dfa_dsl_diff(const char *expected, const char *actual);

/**
 * Assert that two DFA DSL strings are equal, printing diff on failure.
 * Returns true if equal, false otherwise.
 */
bool dfa_dsl_assert_equal(const char *label, const char *expected, const char *actual);

/**
 * Verify DFA round-trip: serialize -> parse -> re-serialize.
 * Returns NULL on success, or malloc'd error message on failure.
 */
char *dfa_dsl_verify_roundtrip(const build_dfa_state_t * const *dfa,
                                 int state_count,
                                 const alphabet_entry_t *alphabet,
                                 int alphabet_size,
                                 const void *marker_lists,
                                 int marker_list_count);

/**
 * Validate a parsed DFA graph for semantic correctness.
 * Checks for determinism, range validity, target bounds, etc.
 */
dsl_validation_t *dfa_dsl_validate(const dsl_dfa_t *dfa);

/**
 * Dump DFA to Graphviz DOT format.
 */
void dfa_dsl_dump_dot(FILE *out, const dsl_dfa_t *dfa);

/**
 * Serialize DFA to DOT format malloc'd string.
 */
char *dfa_dsl_to_dot(const dsl_dfa_t *dfa);

/**
 * Filter parameters for focused DFA extraction.
 */
typedef struct {
    int start_state;         /* BFS start state (-1 = 0) */
    int state_id_filter;     /* Only include this state (-1 = all) */
    int pattern_id_filter;    /* Only include states for this pattern (-1 = all) */
} dfa_dsl_filter_t;

/**
 * Dump focused DFA sub-graph to DSL format.
 * Uses BFS from start_state to extract reachable states.
 */
void dfa_dsl_dump_filtered(FILE *out, const dsl_dfa_t *dfa, dfa_dsl_filter_t filter);

/**
 * Serialize focused DFA sub-graph to DSL string.
 */
char *dfa_dsl_to_string_filtered(const dsl_dfa_t *dfa, dfa_dsl_filter_t filter);

/* ============================================================================
 * Test assertion macros
 *
 * These macros are intended for use in test functions. They compare an
 * actual NFA graph output against an expected DSL string and produce
 * readable diff output on failure.
 * ============================================================================ */

/**
 * ASSERT_NFA_EQ_STR - Compare nfa_graph_t output against an expected string.
 * On mismatch, prints a diff to stderr and returns false from the test function.
 *
 * Usage:
 *   nfa_graph_t *graph = nfa_builder_finalize(ctx, NULL);
 *   const char *expected = "version: 1\n0: start\n0 'a' -> 1\n1: accept ...\n";
 *   ASSERT_NFA_EQ_STR(graph, expected, "literal 'a' test");
 *   nfa_graph_free(graph);
 */
#define ASSERT_NFA_EQ_STR(graph_ptr, expected_str, test_label) do {                \
    char *_actual = nfa_graph_dsl_to_string(graph_ptr);                          \
    if (!_actual) {                                                               \
        fprintf(stderr, "FAIL [%s]: nfa_graph_dsl_to_string returned NULL\n",   \
                test_label);                                                      \
        free(_actual);                                                             \
        return false;                                                              \
    }                                                                              \
    if (strcmp(_actual, expected_str) != 0) {                                      \
        fprintf(stderr, "FAIL [%s]: NFA output mismatch\n", test_label);        \
        nfa_dsl_assert_equal(test_label, expected_str, _actual);                  \
        free(_actual);                                                            \
        return false;                                                              \
    }                                                                              \
    free(_actual);                                                                \
} while(0)

/**
 * ASSERT_NFA_EQ_FILE - Compare nfa_graph_t output against a golden file.
 * Reads the golden file, compares against canonical output.
 * On mismatch, prints a diff and returns false.
 *
 * Usage:
 *   nfa_graph_t *graph = nfa_builder_finalize(ctx, NULL);
 *   ASSERT_NFA_EQ_FILE(graph, "tests/expected/literal_a.nfa", "literal 'a' test");
 *   nfa_graph_free(graph);
 */
#define ASSERT_NFA_EQ_FILE(graph_ptr, golden_path, test_label) do {                \
    char *_actual = nfa_graph_dsl_to_string(graph_ptr);                           \
    if (!_actual) {                                                               \
        fprintf(stderr, "FAIL [%s]: nfa_graph_dsl_to_string returned NULL\n",   \
                test_label);                                                      \
        return false;                                                              \
    }                                                                              \
    FILE *_gf = fopen(golden_path, "r");                                          \
    char *_expected = NULL;                                                        \
    if (_gf) {                                                                    \
        fseek(_gf, 0, SEEK_END);                                                  \
        long _gsz = ftell(_gf);                                                   \
        fseek(_gf, 0, SEEK_SET);                                                  \
        _expected = malloc((size_t)_gsz + 1);                                      \
        if (_expected) {                                                           \
            size_t _nr = fread(_expected, 1, (size_t)_gsz, _gf);                 \
            _expected[_nr] = '\0';                                                 \
        }                                                                         \
        fclose(_gf);                                                              \
    }                                                                             \
    if (!_expected) {                                                              \
        fprintf(stderr, "FAIL [%s]: cannot read golden file '%s'\n",               \
                test_label, golden_path);                                          \
        free(_actual);                                                            \
        return false;                                                              \
    }                                                                             \
    if (strcmp(_actual, _expected) != 0) {                                        \
        fprintf(stderr, "FAIL [%s]: NFA mismatch against %s\n",                    \
                test_label, golden_path);                                          \
        nfa_dsl_assert_equal(test_label, _expected, _actual);                     \
        free(_actual); free(_expected);                                           \
        return false;                                                              \
    }                                                                             \
    free(_actual); free(_expected);                                               \
} while(0)

/**
 * ASSERT_DFA_EQ_STR - Compare DFA output against an expected string.
 * Serializes the DFA, compares against expected, prints diff on failure.
 *
 * Usage:
 *   int count = dfa_get_state_count(dfa);
 *   ASSERT_DFA_EQ_STR(dfa, count, alphabet, 256, markers, 10, "type: DFA\n...", "dfa test");
 */
#define ASSERT_DFA_EQ_STR(dfa_ptr, dfa_state_count, alphabet, alphabet_sz, markers, marker_cnt, expected, label) do { \
    char *_actual = dfa_dsl_to_string(dfa_ptr, dfa_state_count, alphabet, alphabet_sz, markers, marker_cnt); \
    if (!_actual) {                                                               \
        fprintf(stderr, "FAIL [%s]: dfa_dsl_to_string returned NULL\n", label);  \
        return false;                                                              \
    }                                                                              \
    if (strcmp(_actual, expected) != 0) {                                          \
        fprintf(stderr, "FAIL [%s]: DFA output mismatch\n", label);                 \
        dfa_dsl_assert_equal(label, expected, _actual);                           \
        free(_actual);                                                            \
        return false;                                                              \
    }                                                                              \
    free(_actual);                                                                \
} while(0)

/**
 * ASSERT_DFA_EQ_FILE - Compare DFA output against a golden file.
 */
#define ASSERT_DFA_EQ_FILE(dfa_ptr, dfa_state_count, alphabet, alphabet_sz, markers, marker_cnt, golden_path, label) do { \
    char *_actual = dfa_dsl_to_string(dfa_ptr, dfa_state_count, alphabet, alphabet_sz, markers, marker_cnt); \
    if (!_actual) {                                                               \
        fprintf(stderr, "FAIL [%s]: dfa_dsl_to_string returned NULL\n", label);  \
        return false;                                                              \
    }                                                                              \
    FILE *_gf = fopen(golden_path, "r");                                          \
    char *_expected = NULL;                                                        \
    if (_gf) {                                                                    \
        fseek(_gf, 0, SEEK_END);                                                  \
        long _gsz = ftell(_gf);                                                   \
        fseek(_gf, 0, SEEK_SET);                                                  \
        _expected = malloc((size_t)_gsz + 1);                                      \
        if (_expected) {                                                           \
            size_t _nr = fread(_expected, 1, (size_t)_gsz, _gf);                 \
            _expected[_nr] = '\0';                                                 \
        }                                                                         \
        fclose(_gf);                                                              \
    }                                                                             \
    if (!_expected) {                                                              \
        fprintf(stderr, "FAIL [%s]: cannot read golden file '%s'\n", label, golden_path); \
        free(_actual);                                                            \
        return false;                                                              \
    }                                                                             \
    if (strcmp(_actual, _expected) != 0) {                                        \
        fprintf(stderr, "FAIL [%s]: DFA mismatch against %s\n", label, golden_path); \
        dfa_dsl_assert_equal(label, _expected, _actual);                          \
        free(_actual); free(_expected);                                           \
        return false;                                                              \
    }                                                                             \
    free(_actual); free(_expected);                                               \
} while(0)

#ifdef __cplusplus
}
#endif

#endif /* NFA_DSL_H */