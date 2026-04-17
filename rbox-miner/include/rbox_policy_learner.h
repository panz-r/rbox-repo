/*
 * rbox_policy_learner.h - Command Policy Learner (CPL)
 *
 * Observes allowed commands and incrementally suggests generalised policy rules.
 * Uses a Normalised Command Trie (NCT) with typed wildcards to generalise
 * variable parts of commands while maintaining precise control over policy scope.
 */

#ifndef RBOX_POLICY_LEARNER_H
#define RBOX_POLICY_LEARNER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * ERROR CODES
 * ============================================================ */

typedef enum {
    CPL_OK              =  0,
    CPL_ERR_INVALID     = -1,
    CPL_ERR_MEMORY      = -2,
    CPL_ERR_IO          = -3,
    CPL_ERR_TRUNCATED   = -4,
    CPL_ERR_FORMAT      = -5,
} cpl_error_t;

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define CPL_DEFAULT_MIN_SUPPORT    5    /* Minimum count to suggest a rule */
#define CPL_DEFAULT_MIN_CONFIDENCE 0.05 /* Minimum confidence threshold */
#define CPL_DEFAULT_MAX_SUGGESTIONS 20  /* Max suggestions per query */
#define CPL_MAX_PATTERN_LEN     1024    /* Max length of a pattern string */
#define CPL_MAX_TOKEN_LEN       256     /* Max length of a single token */
#define CPL_MAX_SAMPLE_VALUES   32      /* Max original values stored per variable node */
#define CPL_INITIAL_CHILDREN_CAP 4      /* Initial capacity for children array */

/* ============================================================
 * TOKEN TYPE LATTICE
 *
 * Ordering (⊂ = strict subset):
 *   #h ⊂ #n ⊂ #val ⊂ *
 *   #i ⊂ #val ⊂ *
 *   #w ⊂ #val ⊂ *
 *   #q ⊂ #qs ⊂ #val ⊂ *
 *   #f ⊂ #r ⊂ #path ⊂ *
 *   #p ⊂ #path ⊂ *
 *   #u ⊂ *
 *
 * #f and #w are incomparable (a filename is not a word, a word is not a filename).
 * Ambiguous tokens (e.g., "Makefile" could be #w or #f) require user disambiguation.
 * ============================================================ */

typedef enum {
    CPL_TYPE_LITERAL = 0,   /* Exact string match (bottom element) */
    CPL_TYPE_HEXHASH,       /* #h: 8+ hex chars (e.g., deadbeef) */
    CPL_TYPE_NUMBER,        /* #n: decimal, hex, octal integers */
    CPL_TYPE_IPV4,          /* #i: dotted decimal (192.168.1.1) */
    CPL_TYPE_WORD,          /* #w: [a-zA-Z_][a-zA-Z0-9_]* */
    CPL_TYPE_QUOTED,        /* #q: quoted string, no whitespace */
    CPL_TYPE_QUOTED_SPACE,  /* #qs: quoted string with whitespace */
    CPL_TYPE_FILENAME,      /* #f: no /, has . extension */
    CPL_TYPE_REL_PATH,      /* #r: has .. or / but not ^/ */
    CPL_TYPE_ABS_PATH,      /* #p: starts with / */
    CPL_TYPE_PATH,          /* #path: any path type (#p ∨ #r ∨ #f) */
    CPL_TYPE_URL,           /* #u: protocol://... */
    CPL_TYPE_VALUE,         /* #val: any scalar (#n ∨ #i ∨ #w ∨ #q ∨ #qs) */
    CPL_TYPE_ANY,           /* *: everything (top element) */
    CPL_TYPE_COUNT          /* number of types */
} cpl_token_type_t;

/**
 * String representation of each token type (for display and serialization).
 * Indexed by cpl_token_type_t.
 */
extern const char *cpl_type_symbol[CPL_TYPE_COUNT];

/**
 * Join table: cpl_type_join[a][b] = narrowest type covering both a and b.
 * Indexed by cpl_token_type_t.
 */
extern const cpl_token_type_t cpl_type_join[CPL_TYPE_COUNT][CPL_TYPE_COUNT];

/**
 * Compatibility table: cpl_type_compatible[cmd_type][policy_type] is true
 * if a command token of cmd_type matches a policy node of policy_type.
 * Equivalent to: cmd_type ≤ policy_type in the lattice.
 */
extern const bool cpl_type_compatible[CPL_TYPE_COUNT][CPL_TYPE_COUNT];

/**
 * Return the join of two token types (narrowest type covering both).
 */
static inline cpl_token_type_t cpl_join(cpl_token_type_t a, cpl_token_type_t b)
{
    return cpl_type_join[a][b];
}

/**
 * Check if a command token type is compatible with a policy node type.
 * Returns true if cmd_type ≤ policy_type in the lattice.
 */
static inline bool cpl_is_compatible(cpl_token_type_t cmd_type,
                                     cpl_token_type_t policy_type)
{
    return cpl_type_compatible[cmd_type][policy_type];
}

/* ============================================================
 * TYPED TOKEN
 * ============================================================ */

/**
 * A token with its classified type.
 */
typedef struct cpl_token {
    char *text;                  /* Token text (for literals) or type symbol (for wildcards) */
    cpl_token_type_t type;       /* Classified type */
} cpl_token_t;

/**
 * Array of typed tokens returned by cpl_normalize_typed().
 */
typedef struct cpl_token_array {
    cpl_token_t *tokens;
    size_t count;
} cpl_token_array_t;

/* ============================================================
 * DATA STRUCTURES (Learner Trie)
 * ============================================================ */

/**
 * A node in the Normalised Command Trie.
 * Each node represents one token in a normalised command sequence.
 */
typedef struct cpl_node {
    char *token;                     /* Normalised token text or type symbol */
    cpl_token_type_t type;           /* Token type (CPL_TYPE_LITERAL for exact match) */
    uint32_t count;                  /* Number of commands reaching this node */
    cpl_token_type_t observed_types; /* Bitmask of types observed at this position */
    char **sample_values;            /* Original token values seen (for debugging) */
    size_t num_samples;              /* Number of samples stored */
    struct cpl_node **children;      /* Array of child pointers */
    size_t num_children;
    size_t children_capacity;
} cpl_node_t;

/**
 * The trie itself – a root node and a total command counter.
 */
typedef struct cpl_trie {
    cpl_node_t *root;
    uint32_t total_commands;         /* Total number of commands fed */
} cpl_trie_t;

/**
 * A suggestion candidate generated from the trie.
 */
typedef struct cpl_suggestion {
    char *pattern;                   /* e.g., "git commit -m #n" */
    uint32_t count;                  /* Number of commands matching this pattern */
    double confidence;               /* Relative confidence (node.count / parent.count) */
} cpl_suggestion_t;

/**
 * Main learner handle.
 */
typedef struct cpl_learner {
    cpl_trie_t trie;
    uint32_t min_support;            /* Minimum count to suggest (default 5) */
    double min_confidence;           /* Minimum confidence (default 0.05) */
    size_t max_suggestions;          /* Max suggestions per query (default 20) */
    char **blacklist;                /* Patterns the user rejected */
    size_t blacklist_count;
    size_t blacklist_capacity;
} cpl_learner_t;

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

cpl_learner_t *cpl_learner_new(uint32_t min_support, double min_confidence);
void cpl_learner_free(cpl_learner_t *learner);

/* ============================================================
 * FEEDING COMMANDS
 * ============================================================ */

cpl_error_t cpl_feed(cpl_learner_t *learner, const char *raw_cmd);
cpl_error_t cpl_feed_parsed(cpl_learner_t *learner, const char *raw_cmd,
                            const void *parse);

/* ============================================================
 * SUGGESTIONS
 * ============================================================ */

cpl_suggestion_t *cpl_suggest(cpl_learner_t *learner, size_t *out_count);
void cpl_free_suggestions(cpl_suggestion_t *suggestions, size_t count);

/* ============================================================
 * BLACKLIST
 * ============================================================ */

cpl_error_t cpl_blacklist_add(cpl_learner_t *learner, const char *pattern);
bool cpl_is_blacklisted(const cpl_learner_t *learner, const char *pattern);

/* ============================================================
 * SERIALISATION
 * ============================================================ */

cpl_error_t cpl_save(const cpl_learner_t *learner, const char *path);
cpl_error_t cpl_load(cpl_learner_t *learner, const char *path);

/* ============================================================
 * NORMALISATION (public for testing)
 * ============================================================ */

/**
 * Normalise a raw command string into an array of typed tokens.
 * Each token is classified into the most specific type in the lattice.
 *
 * The caller must free the returned array with cpl_free_token_array().
 */
cpl_error_t cpl_normalize_typed(const char *raw_cmd,
                                cpl_token_array_t *out);

/**
 * Free a typed token array.
 */
void cpl_free_token_array(cpl_token_array_t *arr);

/**
 * Legacy: normalise into string tokens (backward compatible).
 * Wildcard tokens use their type symbol (e.g., "#n", "#p", "*").
 */
cpl_error_t cpl_normalize(const char *raw_cmd,
                          char ***out_tokens, size_t *out_token_count);

/**
 * Free a string token array.
 */
void cpl_free_tokens(char **tokens, size_t count);

/**
 * Classify a single token string into its most specific type.
 * Returns CPL_TYPE_LITERAL if no wildcard type matches.
 */
cpl_token_type_t cpl_classify_token(const char *token);

/* ============================================================
 * POLICY MODULE (arena-allocated, NFA-renderable)
 * ============================================================ */

/**
 * Shared policy context: arena allocator, string pool, and shared state.
 * Multiple policies can share a context to deduplicate token strings
 * across policy sets.
 */
typedef struct cpl_policy_ctx cpl_policy_ctx_t;

/**
 * Compact policy trie:
 * - Arena-allocated states and children (zero per-node mallocs)
 * - String-interned token text (shared across policies in same context)
 * - Sorted children: literals (binary search) + wildcards (type lookup)
 * - Wildcard bitmask for O(1) compatibility pre-filter
 */
typedef struct cpl_policy cpl_policy_t;

/**
 * NFA render options.
 */
typedef struct {
    uint8_t  category_mask;    /* Accepting category (0x01=safe, etc.) */
    uint32_t pattern_id_base;  /* Starting pattern_id for this policy */
    bool     include_tags;     /* Emit Tags: lines in NFA output */
    const char *identifier;    /* NFA header identifier string (NULL = default) */
} cpl_nfa_render_opts_t;

/* --- Context lifecycle --- */

cpl_policy_ctx_t *cpl_policy_ctx_new(void);
cpl_policy_ctx_t *cpl_policy_ctx_new_with_arena(size_t arena_size);
void cpl_policy_ctx_free(cpl_policy_ctx_t *ctx);
const char *cpl_policy_ctx_intern(cpl_policy_ctx_t *ctx, const char *str);

/* --- Policy lifecycle --- */

cpl_policy_t *cpl_policy_new(cpl_policy_ctx_t *ctx);
void cpl_policy_free(cpl_policy_t *policy);

/* --- Pattern management --- */

cpl_error_t cpl_policy_add(cpl_policy_t *policy, const char *pattern);
cpl_error_t cpl_policy_remove(cpl_policy_t *policy, const char *pattern);
size_t cpl_policy_count(const cpl_policy_t *policy);

/* --- Verification --- */

/**
 * A suggestion for expanding a policy to cover a new command.
 * Fixed-size buffer — no allocation, no cleanup needed.
 */
typedef struct {
    char pattern[CPL_MAX_PATTERN_LEN];
    const char *based_on;       /* Existing pattern this extends, or NULL */
    double confidence;          /* matched_prefix_tokens / total_cmd_tokens */
} cpl_expand_suggestion_t;

/**
 * Result of cpl_policy_eval. Caller passes a pointer to this struct.
 */
typedef struct {
    bool matches;
    const char *matching_pattern;     /* NULL if no match */
    size_t suggestion_count;          /* 0-2, only filled if !matches */
    cpl_expand_suggestion_t suggestions[2];
} cpl_eval_result_t;

/**
 * Unified evaluate + suggest.
 *
 * Walks the policy trie with the command. If it matches, sets
 * result->matches=true and result->matching_pattern.
 *
 * If it doesn't match and result is non-NULL, generates up to 2
 * expansion suggestions in result->suggestions[].
 *
 * Passing NULL for result disables suggestions (verify-only fast path).
 */
cpl_error_t cpl_policy_eval(const cpl_policy_t *policy,
                             const char *raw_cmd,
                             cpl_eval_result_t *result);

cpl_error_t cpl_policy_verify_all(const cpl_policy_t *policy,
                                  const char *raw_cmd,
                                  const char ***matching_patterns,
                                  size_t *match_count);

void cpl_policy_free_matches(const char **matches, size_t count);

/* --- NFA rendering --- */

cpl_error_t cpl_policy_render_nfa(const cpl_policy_t *policy,
                                  const char *path,
                                  const cpl_nfa_render_opts_t *opts);

/* --- Serialization --- */

cpl_error_t cpl_policy_save(const cpl_policy_t *policy, const char *path);
cpl_error_t cpl_policy_load(cpl_policy_t *policy, const char *path);

/* --- Diagnostics --- */

size_t cpl_policy_memory_usage(const cpl_policy_t *policy);
size_t cpl_policy_working_set(const cpl_policy_t *policy);
size_t cpl_policy_state_count(const cpl_policy_t *policy);

/* ============================================================
 * POLICY EXPANSION SUGGESTIONS (Miner)
 * ============================================================ */

/**
 * Step 2: Given a chosen pattern (as typed tokens), suggest up to 3
 * generalizations by widening one non-literal token at a time.
 * Also includes the exact-match-as-literal variant.
 *
 * Caller allocates out[3]. No cleanup needed.
 */
size_t cpl_policy_suggest_variants(const cpl_policy_t *policy,
                                    const cpl_token_t *tokens,
                                    size_t token_count,
                                    cpl_expand_suggestion_t out[3]);

#ifdef __cplusplus
}
#endif

#endif /* RBOX_POLICY_LEARNER_H */
