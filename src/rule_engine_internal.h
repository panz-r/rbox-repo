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

/* ------------------------------------------------------------------ */
/*  Query result cache (round-robin LRU)                               */
/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t path_hash;       /**< FNV-1a hash of (src_path, dst_path, subject) */
    uint32_t op;              /**< soft_binary_op_t */
    uint32_t uid;             /**< Caller UID */
    int32_t  result;          /**< Cached result: SOFT_ACCESS_* or -EACCES, 0=miss */
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
    rule_t *rules;      /**< Dynamically allocated array */
    int     count;      /**< Number of rules */
    int     capacity;   /**< Allocated capacity */
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
    uint16_t        _pad;
    const char     *subject_regex;  /**< Interned, or NULL */
} compiled_rule_t;

/* ------------------------------------------------------------------ */
/*  Effective (simplified) ruleset — separated by pattern type         */
/* ------------------------------------------------------------------ */

#define EFF_CHUNK 64

typedef struct {
    /* Exact/directory static patterns — sorted by pattern for binary search */
    compiled_rule_t *static_rules;
    int              static_count;
    int              static_capacity;

    /* Non-static patterns (wildcards, recursive, templates) — linear scan */
    compiled_rule_t *dynamic_rules;
    int              dynamic_count;
    int              dynamic_capacity;

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
    query_cache_entry_t query_cache[QUERY_CACHE_SIZE]; /**< LRU query result cache */
    uint32_t            cache_cursor;          /**< Round-robin cursor for cache eviction */
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
