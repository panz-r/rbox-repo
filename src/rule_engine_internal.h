/**
 * @file rule_engine_internal.h
 * @brief Internal types shared by rule_engine.c and rule_engine_compile.c.
 *
 * NOT part of the public API.
 */

#ifndef RULE_ENGINE_INTERNAL_H
#define RULE_ENGINE_INTERNAL_H

#include "rule_engine.h"
#include <stdbool.h>

/* ------------------------------------------------------------------ */
/*  Limits                                                              */
/* ------------------------------------------------------------------ */

#define MAX_PATTERN_LEN 256
#define MAX_LINKED_LEN  8
#define MAX_LAYERS      64
#define MAX_CUSTOM_OPS  16
#define QUERY_CACHE_SIZE 256    /**< LRU query result cache entries */
#define SPECIFICITY_NO_MATCH  UINT32_MAX /**< Sentinel: no SPECIFICITY rule matched */

/* ------------------------------------------------------------------ */
/*  Layer type                                                         */
/* ------------------------------------------------------------------ */

/**
 * How a layer combines with other layers.
 *   PRECEDENCE  (default): DENY shadows lower, mode intersection.
 *   SPECIFICITY: Longest-match wins, overrides PRECEDENCE entirely.
 *                A SPECIFICITY rule that grants mode X returns X
 *                regardless of PRECEDENCE DENYs. A SPECIFICITY DENY
 *                (mode=0 or DENY) also overrides PRECEDENCE.
 */

/* ------------------------------------------------------------------ */
/*  Query result cache (LRU, round-robin eviction)                     */
/* ------------------------------------------------------------------ */

/**
 * Cache entry keyed on a single path.  Stores what was GRANTED and
 * what was EVALUATED as two independent mode bitmasks.
 *
 *   granted  — SOFT_ACCESS_* bits that were granted
 *   eval     — SOFT_ACCESS_* bits that were actually evaluated
 *
 * A mode bit in `granted` is only meaningful if the same bit is set in
 * `eval`.  If eval lacks a bit, the corresponding granted bit is
 * undefined (the evaluation never looked at rules that could produce it).
 *
 * Example:
 *   READ("/a")  →  granted=READ,  eval=READ
 *   COPY("/a")  →  granted=RWX,   eval=ALL   (COPY matches COPY+READ+WRITE rules)
 *
 *   Later, a WRITE("/a") lookup:
 *     - READ cache entry: eval&WRITE = 0  → miss, must evaluate
 *     - COPY cache entry: eval&WRITE = W  → hit, return granted&WRITE
 */
typedef struct {
    uint64_t path_hash;       /**< FNV-1a hash of path */
    uint32_t subject_hash;    /**< FNV-1a hash of subject string */
    uint32_t uid;             /**< Caller UID */
    uint32_t granted;         /**< SOFT_ACCESS_* bits granted */
    uint32_t eval;            /**< SOFT_ACCESS_* bits that were evaluated */
    int32_t  deny_layer;      /**< -1 = no deny, >=0 = denied at this layer */
    uint8_t  valid;           /**< Non-zero = entry is valid */
} query_cache_entry_t;

/* ------------------------------------------------------------------ */
/*  Internal rule structure                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    char              pattern[MAX_PATTERN_LEN]; /**< Path pattern */
    uint32_t          mode;                     /**< SOFT_ACCESS_* or DENY */
    soft_binary_op_t  op_type;                  /**< Operation this rule applies to */
    char              linked_path_var[MAX_LINKED_LEN]; /**< "SRC", "DST", or "" */
    char              subject_regex[128];       /**< Binary path regex, or "" */
    uint32_t          min_uid;                  /**< Minimum UID */
    uint32_t          flags;                    /**< Rule flags */
} rule_t;

/* ------------------------------------------------------------------ */
/*  Dynamic rule array per layer (descriptive, editable)               */
/* ------------------------------------------------------------------ */

#define LAYER_CHUNK 64

typedef struct {
    rule_t         *rules;      /**< Dynamically allocated array */
    int             count;      /**< Number of rules */
    int             capacity;   /**< Allocated capacity */
    layer_type_t    type;       /**< PRECEDENCE or SPECIFICITY */
    uint32_t        mask;       /**< Mode filter: 0 = all modes */
} layer_t;

/* ------------------------------------------------------------------ */
/*  String arena for compiled ruleset (interned strings)               */
/* ------------------------------------------------------------------ */

#define STR_ARENA_INIT  4096

typedef struct {
    char   *buf;
    size_t  used;
    size_t  capacity;
} str_arena_t;

/* ------------------------------------------------------------------ */
/*  Compiled rule (much smaller than descriptive rule_t: ~48 vs 416)   */
/* ------------------------------------------------------------------ */

typedef struct {
    const char     *pattern;       /**< Interned path pattern */
    uint32_t        mode;          /**< SOFT_ACCESS_* or DENY */
    uint32_t        min_uid;       /**< Minimum UID */
    uint32_t        flags;         /**< Rule flags (RECURSIVE, TEMPLATE) */
    uint16_t        op_type;       /**< soft_binary_op_t */
    uint16_t        pattern_len;   /**< strlen(pattern), cached */
    const char     *subject_regex;  /**< Interned, or NULL */
} compiled_rule_t;

/* ------------------------------------------------------------------ */
/*  Effective (simplified) ruleset — separated by pattern type         */
/* ------------------------------------------------------------------ */

#define EFF_CHUNK 64

typedef struct {
    /* PRECEDENCE rules (current behavior: DENY shadows, mode AND) */
    compiled_rule_t *static_rules;
    int              static_count;
    int              static_capacity;

    /* Non-static patterns (wildcards, recursive, templates) — linear scan */
    compiled_rule_t *dynamic_rules;
    int              dynamic_count;
    int              dynamic_capacity;

    /* SPECIFICITY rules (longest-match overrides PRECEDENCE) */
    compiled_rule_t *spec_static_rules;
    int              spec_static_count;
    int              spec_static_capacity;

    compiled_rule_t *spec_dynamic_rules;
    int              spec_dynamic_count;
    int              spec_dynamic_capacity;

    /* String arena for interning pattern and subject strings */
    str_arena_t      strings;
} effective_ruleset_t;

/* ------------------------------------------------------------------ */
/*  Custom operation mode table entry                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t src_required;
    uint32_t dst_required;
} custom_op_entry_t;

/* ------------------------------------------------------------------ */
/*  Full ruleset structure                                             */
/* ------------------------------------------------------------------ */

struct soft_ruleset {
    layer_t             layers[MAX_LAYERS];    /**< Descriptive (editable) */
    int                 layer_count;
    effective_ruleset_t effective;             /**< Simplified (read-only after compile) */
    bool                is_compiled;           /**< true if effective is valid */
    custom_op_entry_t   custom_ops[MAX_CUSTOM_OPS];
    query_cache_entry_t query_cache[QUERY_CACHE_SIZE]; /**< Direct-mapped query result cache */
    char                last_error[256];
};

/* ------------------------------------------------------------------ */
/*  Compilation API (rule_engine_compile.c)                            */
/* ------------------------------------------------------------------ */

int soft_ruleset_compile(soft_ruleset_t *rs);
void eff_free(effective_ruleset_t *eff);
void soft_ruleset_invalidate(soft_ruleset_t *rs);
bool soft_ruleset_is_compiled(const soft_ruleset_t *rs);

uint32_t eval_effective_path(const effective_ruleset_t *eff,
                             const char *path,
                             soft_binary_op_t op,
                             const soft_access_ctx_t *ctx,
                             const char **out_matched_pattern);

/* ------------------------------------------------------------------ */
/*  Helpers (rule_engine_compile.c)                                    */
/* ------------------------------------------------------------------ */

bool pattern_covers(const char *a, const char *b);
bool rule_constraints_equal(const rule_t *a, const rule_t *b);
bool rule_subsumes(const rule_t *general, const rule_t *specific);
bool subject_matches(const rule_t *rule, const char *subject);
bool rule_matches_path(const rule_t *rule, const char *path,
                       const soft_access_ctx_t *ctx);
bool path_matches(const char *pattern, const char *path);

#endif /* RULE_ENGINE_INTERNAL_H */
