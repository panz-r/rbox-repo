/**
 * @file rule_engine_compile.c
 * @brief Rule simplification: descriptive layers → effective compiled ruleset.
 *
 * Compilation phases:
 *   1. Cross-layer shadow elimination (DENY shadows ALLOW)
 *   2. Mode intersection (identical patterns ANDed)
 *   3. Subsumption (general rules cover specific ones)
 *   4. Sort DENYs first, separate static vs dynamic rules
 *
 * The compiled ruleset uses interned strings (str_arena_t) and a
 * compact rule representation (compiled_rule_t, ~48 bytes vs 416)
 * for better cache locality.
 */

#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>

#include "rule_engine.h"
#include "rule_engine_internal.h"

/* ------------------------------------------------------------------ */
/*  String arena                                                        */
/* ------------------------------------------------------------------ */

static const char *arena_intern(str_arena_t *a, const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    if (a->used + len > a->capacity) {
        size_t new_cap = a->capacity ? a->capacity * 2 : STR_ARENA_INIT;
        while (new_cap < a->used + len) new_cap *= 2;
        char *new_buf = realloc(a->buf, new_cap);
        if (!new_buf) return NULL;
        a->buf = new_buf;
        a->capacity = new_cap;
    }
    char *p = a->buf + a->used;
    memcpy(p, s, len);
    a->used += len;
    return p;
}

static void arena_free(str_arena_t *a)
{
    free(a->buf);
    a->buf = NULL;
    a->used = 0;
    a->capacity = 0;
}

/* ------------------------------------------------------------------ */
/*  Effective ruleset helpers                                          */
/* ------------------------------------------------------------------ */

static int eff_add_static(effective_ruleset_t *eff, const compiled_rule_t *r)
{
    if (eff->static_count >= eff->static_capacity) {
        int new_cap = eff->static_capacity + EFF_CHUNK;
        compiled_rule_t *new_rules = realloc(eff->static_rules,
                                             (size_t)new_cap * sizeof(compiled_rule_t));
        if (!new_rules) return -1;
        eff->static_rules = new_rules;
        eff->static_capacity = new_cap;
    }
    eff->static_rules[eff->static_count++] = *r;
    return 0;
}

static int eff_add_dynamic(effective_ruleset_t *eff, const compiled_rule_t *r)
{
    if (eff->dynamic_count >= eff->dynamic_capacity) {
        int new_cap = eff->dynamic_capacity + EFF_CHUNK;
        compiled_rule_t *new_rules = realloc(eff->dynamic_rules,
                                             (size_t)new_cap * sizeof(compiled_rule_t));
        if (!new_rules) return -1;
        eff->dynamic_rules = new_rules;
        eff->dynamic_capacity = new_cap;
    }
    eff->dynamic_rules[eff->dynamic_count++] = *r;
    return 0;
}

static int eff_add_spec_static(effective_ruleset_t *eff, const compiled_rule_t *r)
{
    if (eff->spec_static_count >= eff->spec_static_capacity) {
        int new_cap = eff->spec_static_capacity + EFF_CHUNK;
        compiled_rule_t *new_rules = realloc(eff->spec_static_rules,
                                             (size_t)new_cap * sizeof(compiled_rule_t));
        if (!new_rules) return -1;
        eff->spec_static_rules = new_rules;
        eff->spec_static_capacity = new_cap;
    }
    eff->spec_static_rules[eff->spec_static_count++] = *r;
    return 0;
}

static int eff_add_spec_dynamic(effective_ruleset_t *eff, const compiled_rule_t *r)
{
    if (eff->spec_dynamic_count >= eff->spec_dynamic_capacity) {
        int new_cap = eff->spec_dynamic_capacity + EFF_CHUNK;
        compiled_rule_t *new_rules = realloc(eff->spec_dynamic_rules,
                                             (size_t)new_cap * sizeof(compiled_rule_t));
        if (!new_rules) return -1;
        eff->spec_dynamic_rules = new_rules;
        eff->spec_dynamic_capacity = new_cap;
    }
    eff->spec_dynamic_rules[eff->spec_dynamic_count++] = *r;
    return 0;
}

void eff_free(effective_ruleset_t *eff)
{
    free(eff->static_rules);
    free(eff->dynamic_rules);
    free(eff->spec_static_rules);
    free(eff->spec_dynamic_rules);
    arena_free(&eff->strings);
    eff->static_rules = NULL;
    eff->dynamic_rules = NULL;
    eff->static_count = 0;
    eff->dynamic_count = 0;
    eff->spec_static_rules = NULL;
    eff->spec_dynamic_rules = NULL;
    eff->spec_static_count = 0;
    eff->spec_dynamic_count = 0;
}

/** Convert a descriptive rule_t to a compiled_rule_t, interning strings. */
static int compile_rule(effective_ruleset_t *eff, const rule_t *r,
                        compiled_rule_t *out)
{
    const char *pat = arena_intern(&eff->strings, r->pattern);
    if (!pat) return -1;
    out->pattern = pat;
    out->mode = r->mode;
    out->min_uid = r->min_uid;
    out->flags = r->flags;
    out->op_type = (uint16_t)r->op_type;
    out->_pad = 0;
    if (r->subject_regex[0] != '\0') {
        const char *subj = arena_intern(&eff->strings, r->subject_regex);
        if (!subj) return -1;
        out->subject_regex = subj;
    } else {
        out->subject_regex = NULL;
    }
    return 0;
}

/** Check if a rule is a static (non-wildcard, non-template) pattern. */
static bool is_static_rule(const rule_t *r)
{
    if (r->flags & SOFT_RULE_TEMPLATE) return false;
    const char *p = r->pattern;
    size_t len = strlen(p);
    /* "..." recursive wildcard is not static */
    if (len >= 3 && p[len-1] == '.' && p[len-2] == '.' && p[len-3] == '.')
        return false;
    /* Any '*' means not static */
    if (strchr(p, '*') != NULL) return false;
    return true;
}

/* ------------------------------------------------------------------ */
/*  Compiled rule matching (for dynamic rules: wildcards, templates)   */
/* ------------------------------------------------------------------ */

/** Replace VAR in pattern with the actual path and match (compiled version). */
static bool compiled_match_with_var(const char *pattern, const char *var_name,
                                    const soft_access_ctx_t *ctx,
                                    const char *query_path)
{
    const char *resolved = NULL;
    if (!var_name || !ctx) return false;
    if (strcmp(var_name, "SRC") == 0) resolved = ctx->src_path;
    else if (strcmp(var_name, "DST") == 0) resolved = ctx->dst_path;
    if (!resolved) return false;

    char resolved_pattern[MAX_PATTERN_LEN];
    char placeholder[16];
    snprintf(placeholder, sizeof(placeholder), "${%s}", var_name);

    const char *var_pos = strstr(pattern, placeholder);
    if (!var_pos) return false;

    size_t prefix_len = (size_t)(var_pos - pattern);
    size_t total_len = prefix_len + strlen(resolved) + strlen(var_pos + strlen(placeholder));
    if (total_len >= MAX_PATTERN_LEN) return false;

    memcpy(resolved_pattern, pattern, prefix_len);
    memcpy(resolved_pattern + prefix_len, resolved, strlen(resolved) + 1);
    strcat(resolved_pattern, var_pos + strlen(placeholder));

    return path_matches(resolved_pattern, query_path);
}

/** Check if compiled rule matches the given path in context. */
static bool compiled_rule_matches_path(const compiled_rule_t *rule,
                                        const char *path,
                                        const soft_access_ctx_t *ctx)
{
    if (!rule || !path) return false;

    bool is_template = (rule->flags & SOFT_RULE_TEMPLATE) != 0;

    if (is_template) {
        /* Try ${SRC} first, then ${DST} */
        if (strstr(rule->pattern, "${SRC}") != NULL) {
            return compiled_match_with_var(rule->pattern, "SRC", ctx, path);
        }
        if (strstr(rule->pattern, "${DST}") != NULL) {
            return compiled_match_with_var(rule->pattern, "DST", ctx, path);
        }
    }

    return path_matches(rule->pattern, path);
}

bool pattern_covers(const char *a, const char *b)
{
    if (!a || !b) return false;
    if (strcmp(a, b) == 0) return true;

    bool a_rec = (strlen(a) >= 3 && a[strlen(a) - 3] == '.' &&
                  a[strlen(a) - 2] == '.' && a[strlen(a) - 1] == '.');
    bool b_rec = (strlen(b) >= 3 && b[strlen(b) - 3] == '.' &&
                  b[strlen(b) - 2] == '.' && b[strlen(b) - 1] == '.');
    bool a_star = (strchr(a, '*') != NULL && !a_rec);
    bool b_star = (strchr(b, '*') != NULL && !b_rec);

    if (a_rec && b_rec) {
        char base_a[MAX_PATTERN_LEN], base_b[MAX_PATTERN_LEN];
        size_t la = strlen(a) - 3;
        size_t lb = strlen(b) - 3;
        if (la > 0 && a[la - 1] == '/') la--;
        if (lb > 0 && b[lb - 1] == '/') lb--;
        if (la >= MAX_PATTERN_LEN) la = MAX_PATTERN_LEN - 1;
        if (lb >= MAX_PATTERN_LEN) lb = MAX_PATTERN_LEN - 1;
        memcpy(base_a, a, la); base_a[la] = '\0';
        memcpy(base_b, b, lb); base_b[lb] = '\0';
        if (strcmp(base_a, base_b) == 0) return true;
        return strncmp(base_b, base_a, la) == 0 &&
               (base_b[la] == '/' || base_b[la] == '\0');
    }

    if (a_rec && !b_rec) {
        char base_a[MAX_PATTERN_LEN];
        size_t la = strlen(a) - 3;
        if (la > 0 && a[la - 1] == '/') la--;
        if (la >= MAX_PATTERN_LEN) la = MAX_PATTERN_LEN - 1;
        memcpy(base_a, a, la); base_a[la] = '\0';
        if (strcmp(base_a, b) == 0) return true;
        if (b_star) {
            char base_b[MAX_PATTERN_LEN];
            const char *star = strchr(b, '*');
            size_t prefix_len = (size_t)(star - b);
            if (prefix_len >= MAX_PATTERN_LEN) prefix_len = MAX_PATTERN_LEN - 1;
            memcpy(base_b, b, prefix_len);
            base_b[prefix_len] = '\0';
            return strncmp(base_b, base_a, la) == 0 ||
                   strncmp(base_a, base_b, prefix_len) == 0;
        }
        return strncmp(b, base_a, la) == 0 &&
               (b[la] == '/' || b[la] == '\0');
    }

    if (a_rec && b_star) {
        char base_a[MAX_PATTERN_LEN];
        size_t la = strlen(a) - 3;
        if (la > 0 && a[la - 1] == '/') la--;
        if (la >= MAX_PATTERN_LEN) la = MAX_PATTERN_LEN - 1;
        memcpy(base_a, a, la); base_a[la] = '\0';
        char base_b[MAX_PATTERN_LEN];
        const char *star = strchr(b, '*');
        size_t prefix_len = (size_t)(star - b);
        if (prefix_len > 0 && b[prefix_len - 1] == '/') prefix_len--;
        if (prefix_len >= MAX_PATTERN_LEN) prefix_len = MAX_PATTERN_LEN - 1;
        memcpy(base_b, b, prefix_len); base_b[prefix_len] = '\0';
        if (strcmp(base_a, base_b) == 0) return true;
        return strncmp(base_b, base_a, la) == 0 &&
               (base_b[la] == '/' || base_b[la] == '\0');
    }

    if (b_rec) return false;
    if (!a_star && !b_star) return false;

    if (a_star || b_star) {
        const char *star_a = strchr(a, '*');
        const char *star_b = strchr(b, '*');
        bool a_double = (star_a && *(star_a + 1) == '*');
        bool b_double = (star_b && *(star_b + 1) == '*');

        if (!a_double && b_double) return false;

        size_t pre_a = (size_t)(star_a - a);
        size_t pre_b = (size_t)(star_b - b);

        if (pre_a > pre_b) return false;
        if (strncmp(a, b, pre_a) != 0) return false;

        const char *suf_a = star_a + (a_double ? 2 : 1);
        const char *suf_b = star_b + (b_double ? 2 : 1);
        if (*suf_a == '/') suf_a++;
        if (*suf_b == '/') suf_b++;

        if (a_double && !b_double) return true;

        size_t len_suf_a = strlen(suf_a);
        size_t len_suf_b = strlen(suf_b);

        if (len_suf_a == 0) return true;

        if (len_suf_b >= len_suf_a) {
            if (strcmp(suf_b + len_suf_b - len_suf_a, suf_a) == 0) return true;
        }

        if (strchr(suf_a, '*') || strchr(suf_b, '*')) {
            return path_matches(suf_a, suf_b);
        }

        return strcmp(suf_a, suf_b) == 0;
    }

    return false;
}

/* ------------------------------------------------------------------ */
/*  Constraint helpers                                                  */
/* ------------------------------------------------------------------ */

bool rule_constraints_equal(const rule_t *a, const rule_t *b)
{
    return a->op_type == b->op_type &&
           a->min_uid == b->min_uid &&
           a->flags == b->flags &&
           strcmp(a->subject_regex, b->subject_regex) == 0 &&
           strcmp(a->linked_path_var, b->linked_path_var) == 0;
}

bool rule_subsumes(const rule_t *general, const rule_t *specific)
{
    if (!rule_constraints_equal(general, specific)) return false;
    if (!pattern_covers(general->pattern, specific->pattern)) return false;
    if ((general->mode & specific->mode) != specific->mode) return false;
    return true;
}

/**
 * Check if a subject-constrained rule is redundant given an unconstrained rule
 * with the same pattern.
 *
 * In PRECEDENCE (mode intersection), a subject-constrained rule is redundant
 * if the unconstrained rule already grants a SUPERSUBSET of its modes.
 * Adding more modes via a subject rule can only further restrict (via AND),
 * never expand — so if the unconstrained rule is more permissive, the subject
 * rule is a no-op for intersection semantics.
 *
 * Example:
 *   /data/...  READ|WRITE   (no subject)      → grants to ALL subjects
 *   /data/...  READ|WRITE|EXEC (subject=admin) → grants to admin only
 *   For admin: (READ|WRITE) ∩ (READ|WRITE|EXEC) = READ|WRITE → same as without subject rule
 *   → Subject rule is REDUNDANT.
 *
 *   /data/...  READ          (no subject)      → grants to ALL subjects
 *   /data/...  WRITE         (subject=admin)   → grants to admin only
 *   For admin: READ ∩ WRITE = 0 → DENIED → Subject rule is NOT REDUNDANT.
 */
static bool subject_rule_redundant(const rule_t *unconstrained,
                                   const rule_t *subject_rule)
{
    /* Unconstrained rule must have no subject constraint */
    if (unconstrained->subject_regex[0] != '\0') return false;
    /* Subject rule must have a subject constraint */
    if (subject_rule->subject_regex[0] == '\0') return false;
    /* Same pattern, op, flags, linked_path_var, min_uid */
    if (strcmp(unconstrained->pattern, subject_rule->pattern) != 0) return false;
    if (unconstrained->op_type != subject_rule->op_type) return false;
    if (unconstrained->flags != subject_rule->flags) return false;
    if (unconstrained->min_uid != subject_rule->min_uid) return false;
    /* Subject rule mode must be a superset of unconstrained mode */
    return (subject_rule->mode & unconstrained->mode) == unconstrained->mode;
}

/* ------------------------------------------------------------------ */
/*  Compiled subject matching                                           */
/* ------------------------------------------------------------------ */

static bool compiled_subject_matches(const compiled_rule_t *rule,
                                     const char *subject)
{
    if (!rule->subject_regex) return true;
    if (!subject) return false;

    size_t rlen = strlen(rule->subject_regex);
    if (rlen >= 2 && rule->subject_regex[0] == '.' &&
        rule->subject_regex[1] == '*' && rlen > 2) {
        const char *suffix = rule->subject_regex + 2;
        size_t slen = strlen(subject);
        size_t suf_len = strlen(suffix);
        if (suf_len > 0 && suffix[suf_len - 1] == '$') suf_len--;
        if (slen >= suf_len && suf_len > 0 &&
            strncmp(subject + slen - suf_len, suffix, suf_len) == 0)
            return true;
        return false;
    }
    return strcmp(rule->subject_regex, subject) == 0;
}

/* ------------------------------------------------------------------ */
/*  Binary search for static rules (sorted by pattern string)           */
/* ------------------------------------------------------------------ */

static int compare_rule_by_pattern(const void *a, const void *b)
{
    const compiled_rule_t *ra = (const compiled_rule_t *)a;
    const compiled_rule_t *rb = (const compiled_rule_t *)b;
    return strcmp(ra->pattern, rb->pattern);
}

/**
 * Match PRECEDENCE static rules (exact or directory-prefix).
 * Uses intersection (AND) semantics: all matching rules must agree.
 * Optimized with binary search: find insertion point via binary search,
 * then scan forward for exact matches and backward for prefix matches.
 */
static uint32_t match_static_rules(const effective_ruleset_t *eff,
                                   const char *path,
                                   soft_binary_op_t op,
                                   const soft_access_ctx_t *ctx,
                                   const char **out_matched_pattern)
{
    if (!eff || !path) return 0;

    uint32_t granted = SOFT_ACCESS_ALL;
    const char *last_pattern = NULL;
    bool any_matched = false;
    size_t path_len = strlen(path);

    /* Binary search for insertion point of path in sorted static rules.
     * This finds where the path would be inserted, which is also the
     * starting point for exact matches. */
    int lo = 0, hi = eff->static_count;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        int cmp = strcmp(eff->static_rules[mid].pattern, path);
        if (cmp < 0) lo = mid + 1;
        else hi = mid;
    }

    /* Scan forward from lo to find all exact matches. */
    for (int i = lo; i < eff->static_count; i++) {
        const compiled_rule_t *r = &eff->static_rules[i];
        size_t pat_len = strlen(r->pattern);
        if (pat_len != path_len) break;  /* past exact matches */
        if (memcmp(r->pattern, path, pat_len) != 0) break;

        if (r->op_type != op && r->op_type != SOFT_OP_READ &&
            r->op_type != SOFT_OP_WRITE) continue;
        if (!compiled_subject_matches(r, ctx->subject)) continue;
        if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;

        any_matched = true;
        if (r->mode & SOFT_ACCESS_DENY) {
            if (out_matched_pattern) *out_matched_pattern = r->pattern;
            return 0; /* DENY short-circuit */
        }
        granted &= r->mode;
        last_pattern = r->pattern;
    }

    /* Scan backwards from lo-1 to find prefix matches. */
    for (int i = lo - 1; i >= 0; i--) {
        const compiled_rule_t *r = &eff->static_rules[i];
        size_t pat_len = strlen(r->pattern);
        if (pat_len >= path_len) continue;  /* can't be a prefix of shorter path */
        if (memcmp(r->pattern, path, pat_len) != 0 || path[pat_len] != '/')
            continue;

        if (r->op_type != op && r->op_type != SOFT_OP_READ &&
            r->op_type != SOFT_OP_WRITE) continue;
        if (!compiled_subject_matches(r, ctx->subject)) continue;
        if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;

        any_matched = true;
        if (r->mode & SOFT_ACCESS_DENY) {
            if (out_matched_pattern) *out_matched_pattern = r->pattern;
            return 0; /* DENY short-circuit */
        }
        granted &= r->mode;
        last_pattern = r->pattern;
    }

    if (out_matched_pattern) *out_matched_pattern = last_pattern;
    if (!any_matched) return 0;
    return granted;
}

/** Match dynamic rules (wildcards, recursive, templates).
 * Uses intersection (AND) semantics for PRECEDENCE rules. */
static uint32_t match_dynamic_rules(const effective_ruleset_t *eff,
                                    const char *path,
                                    soft_binary_op_t op,
                                    const soft_access_ctx_t *ctx,
                                    const char **out_matched_pattern)
{
    if (!eff || !path) return 0;

    uint32_t granted = SOFT_ACCESS_ALL;
    const char *last_pattern = NULL;

    for (int i = 0; i < eff->dynamic_count; i++) {
        const compiled_rule_t *r = &eff->dynamic_rules[i];
        if (r->op_type != op && r->op_type != SOFT_OP_READ &&
            r->op_type != SOFT_OP_WRITE) continue;
        if (!compiled_subject_matches(r, ctx->subject)) continue;
        if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;
        if (!compiled_rule_matches_path(r, path, ctx)) continue;

        if (r->mode & SOFT_ACCESS_DENY) {
            if (out_matched_pattern) *out_matched_pattern = r->pattern;
            return 0;
        }
        granted &= r->mode;
        last_pattern = r->pattern;
    }

    if (out_matched_pattern) *out_matched_pattern = last_pattern;
    return granted;
}

/* ------------------------------------------------------------------ */
/*  Evaluation using effective (compiled) ruleset                      */
/* ------------------------------------------------------------------ */

static uint32_t match_spec_static(const effective_ruleset_t *eff,
                                   const char *path,
                                   soft_binary_op_t op,
                                   const soft_access_ctx_t *ctx,
                                   const char **out_matched_pattern);
static uint32_t match_spec_dynamic(const effective_ruleset_t *eff,
                                    const char *path,
                                    soft_binary_op_t op,
                                    const soft_access_ctx_t *ctx,
                                    const char **out_matched_pattern);

uint32_t eval_effective_path(const effective_ruleset_t *eff,
                             const char *path,
                             soft_binary_op_t op,
                             const soft_access_ctx_t *ctx,
                             const char **out_matched_pattern)
{
    if (!path) { if (out_matched_pattern) *out_matched_pattern = NULL; return 0; }
    if (!eff) { if (out_matched_pattern) *out_matched_pattern = NULL; return 0; }

    /* Phase 1: SPECIFICITY — longest match overrides PRECEDENCE */
    const char *spec_matched = NULL;
    uint32_t spec_static = match_spec_static(eff, path, op, ctx, &spec_matched);
    if (spec_static != SPECIFICITY_NO_MATCH) {
        if (out_matched_pattern) *out_matched_pattern = spec_matched;
        return spec_static;
    }
    uint32_t spec_dynamic = match_spec_dynamic(eff, path, op, ctx, &spec_matched);
    if (spec_dynamic != SPECIFICITY_NO_MATCH) {
        if (out_matched_pattern) *out_matched_pattern = spec_matched;
        return spec_dynamic;
    }

    /* Phase 2: PRECEDENCE — current behavior (DENY shadows, mode AND) */
    const char *static_matched = NULL;
    uint32_t granted = match_static_rules(eff, path, op, ctx, &static_matched);
    if (granted == 0 && static_matched != NULL) {
        if (out_matched_pattern) *out_matched_pattern = static_matched;
        return 0; /* DENY matched in PRECEDENCE static rules */
    }

    const char *dyn_pattern = NULL;
    uint32_t dyn_granted = match_dynamic_rules(eff, path, op, ctx, &dyn_pattern);
    if (dyn_granted == 0 && dyn_pattern != NULL) {
        if (out_matched_pattern) *out_matched_pattern = dyn_pattern;
        return 0; /* DENY matched in PRECEDENCE dynamic rules */
    }

    /* Combine static and dynamic with intersection (AND semantics) */
    if (static_matched && dyn_pattern) {
        /* Both static and dynamic matched — intersect modes */
        granted &= dyn_granted;
        if (!*out_matched_pattern) *out_matched_pattern = dyn_pattern;
    } else if (static_matched) {
        /* Only static matched — result from static */
        if (out_matched_pattern) *out_matched_pattern = static_matched;
    } else if (dyn_pattern) {
        /* Only dynamic matched — result from dynamic */
        granted = dyn_granted;
        if (out_matched_pattern) *out_matched_pattern = dyn_pattern;
    }
    /* Neither matched → granted=0 (no rule matched) */

    return granted;
}

/* ------------------------------------------------------------------ */
/*  qsort: DENY rules first for fast short-circuit                     */
/* ------------------------------------------------------------------ */

static int compare_deny_first(const void *a, const void *b)
{
    const compiled_rule_t *ra = (const compiled_rule_t *)a;
    const compiled_rule_t *rb = (const compiled_rule_t *)b;
    bool a_deny = ra->mode & SOFT_ACCESS_DENY;
    bool b_deny = rb->mode & SOFT_ACCESS_DENY;
    if (a_deny && !b_deny) return -1;
    if (!a_deny && b_deny) return 1;
    return 0;
}

/** qsort comparison: longest pattern first (for SPECIFICITY) */
static int compare_rule_by_length(const void *a, const void *b)
{
    const compiled_rule_t *ra = (const compiled_rule_t *)a;
    const compiled_rule_t *rb = (const compiled_rule_t *)b;
    size_t la = strlen(ra->pattern);
    size_t lb = strlen(rb->pattern);
    if (la > lb) return -1;
    if (la < lb) return 1;
    return 0;
}

/**
 * Match SPECIFICITY static rules (longest match wins).
 * Returns SPECIFICITY_NO_MATCH if none match, otherwise the matched mode.
 */
static uint32_t match_spec_static(const effective_ruleset_t *eff,
                                   const char *path,
                                   soft_binary_op_t op,
                                   const soft_access_ctx_t *ctx,
                                   const char **out_matched_pattern)
{
    if (!eff || !path) return SPECIFICITY_NO_MATCH;
    size_t path_len = strlen(path);

    for (int i = 0; i < eff->spec_static_count; i++) {
        const compiled_rule_t *r = &eff->spec_static_rules[i];
        if (r->op_type != op && r->op_type != SOFT_OP_READ &&
            r->op_type != SOFT_OP_WRITE) continue;
        if (!compiled_subject_matches(r, ctx->subject)) continue;
        if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;

        bool match = false;
        size_t pat_len = strlen(r->pattern);
        if (pat_len == path_len && memcmp(r->pattern, path, pat_len) == 0) {
            match = true;
        } else if (pat_len < path_len &&
                   memcmp(r->pattern, path, pat_len) == 0 &&
                   path[pat_len] == '/') {
            match = true;
        }

        if (match) {
            if (out_matched_pattern) *out_matched_pattern = r->pattern;
            return r->mode & SOFT_ACCESS_DENY ? 0 : r->mode;
        }
    }
    return SPECIFICITY_NO_MATCH;
}

/**
 * Match SPECIFICITY dynamic rules (longest match wins).
 */
static uint32_t match_spec_dynamic(const effective_ruleset_t *eff,
                                    const char *path,
                                    soft_binary_op_t op,
                                    const soft_access_ctx_t *ctx,
                                    const char **out_matched_pattern)
{
    if (!eff || !path) return SPECIFICITY_NO_MATCH;

    const char *best_pattern = NULL;
    size_t best_len = 0;
    uint32_t best_mode = 0;
    bool found = false;

    for (int i = 0; i < eff->spec_dynamic_count; i++) {
        const compiled_rule_t *r = &eff->spec_dynamic_rules[i];
        if (r->op_type != op && r->op_type != SOFT_OP_READ &&
            r->op_type != SOFT_OP_WRITE) continue;
        if (!compiled_subject_matches(r, ctx->subject)) continue;
        if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;
        if (!compiled_rule_matches_path(r, path, ctx)) continue;

        size_t pat_len = strlen(r->pattern);
        if (!found || pat_len > best_len) {
            best_len = pat_len;
            best_pattern = r->pattern;
            best_mode = r->mode;
            found = true;
        }
    }

    if (!found) return SPECIFICITY_NO_MATCH;
    if (out_matched_pattern) *out_matched_pattern = best_pattern;
    return best_mode & SOFT_ACCESS_DENY ? 0 : best_mode;
}

/* ------------------------------------------------------------------ */
/*  Compilation: descriptive layers → effective compiled ruleset       */
/* ------------------------------------------------------------------ */

void soft_ruleset_invalidate(soft_ruleset_t *rs)
{
    if (!rs) return;
    if (rs->is_compiled) {
        eff_free(&rs->effective);
        rs->is_compiled = false;
    }
    /* Also invalidate the query cache */
    for (uint32_t i = 0; i < QUERY_CACHE_SIZE; i++) rs->query_cache[i].valid = 0;
}

bool soft_ruleset_is_compiled(const soft_ruleset_t *rs)
{
    if (!rs) return false;
    return rs->is_compiled;
}

int soft_ruleset_compile(soft_ruleset_t *rs)
{
    if (!rs) { errno = EINVAL; return -1; }

    /* Invalidate any previous effective */
    eff_free(&rs->effective);

    /* Count total rules */
    int max_pending = 0;
    for (int i = 0; i < rs->layer_count; i++)
        max_pending += rs->layers[i].count;
    if (max_pending == 0) {
        rs->is_compiled = true;
        return 0;
    }

    /* Phase 1: Cross-layer shadow elimination (PRECEDENCE layers only) */
    typedef struct { rule_t rule; int layer; layer_type_t type; } pending_rule_t;
    pending_rule_t *pending = calloc((size_t)max_pending, sizeof(pending_rule_t));
    if (!pending) return -1;
    int pending_count = 0;

    for (int li = 0; li < rs->layer_count; li++) {
        const layer_t *lyr = &rs->layers[li];
        for (int ri = 0; ri < lyr->count; ri++) {
            const rule_t *r = &lyr->rules[ri];

            /* SPECIFICITY layers: no shadow elimination, keep all rules */
            if (lyr->type == LAYER_SPECIFICITY) {
                pending[pending_count].rule = *r;
                pending[pending_count].layer = li;
                pending[pending_count].type = LAYER_SPECIFICITY;
                pending_count++;
                continue;
            }

            /* PRECEDENCE layers: shadow elimination */
            bool shadowed = false;
            if (r->mode & SOFT_ACCESS_DENY) {
                for (int pi = 0; pi < pending_count && !shadowed; pi++) {
                    const pending_rule_t *pr = &pending[pi];
                    if (pr->type == LAYER_PRECEDENCE &&
                        pr->rule.mode & SOFT_ACCESS_DENY &&
                        rule_constraints_equal(&pr->rule, r) &&
                        pattern_covers(pr->rule.pattern, r->pattern))
                        shadowed = true;
                }
            } else {
                for (int pi = 0; pi < pending_count && !shadowed; pi++) {
                    const pending_rule_t *pr = &pending[pi];
                    if (pr->type == LAYER_PRECEDENCE &&
                        pr->rule.mode & SOFT_ACCESS_DENY &&
                        pattern_covers(pr->rule.pattern, r->pattern))
                        shadowed = true;
                }
            }
            if (!shadowed) {
                pending[pending_count].rule = *r;
                pending[pending_count].layer = li;
                pending[pending_count].type = LAYER_PRECEDENCE;
                pending_count++;
            }
        }
    }

    /* Phase 2: Mode intersection (PRECEDENCE layers only) */
    typedef struct { uint32_t mode; bool used; } group_entry_t;
    group_entry_t *groups = calloc((size_t)pending_count, sizeof(group_entry_t));
    if (!groups) { free(pending); return -1; }
    for (int i = 0; i < pending_count; i++) {
        groups[i].mode = pending[i].rule.mode;
        groups[i].used = false;
    }
    for (int i = 0; i < pending_count; i++) {
        if (groups[i].used) continue;
        if (pending[i].type != LAYER_PRECEDENCE) continue;
        for (int j = i + 1; j < pending_count; j++) {
            if (groups[j].used) continue;
            if (pending[j].type != LAYER_PRECEDENCE) continue;
            if (strcmp(pending[i].rule.pattern, pending[j].rule.pattern) == 0 &&
                rule_constraints_equal(&pending[i].rule, &pending[j].rule)) {
                groups[i].mode &= pending[j].rule.mode;
                groups[j].used = true;
            }
        }
    }

    /* Phase 3: Separate static vs dynamic, subsumption (PRECEDENCE only),
     * classify into PRECEDENCE vs SPECIFICITY buckets */
    effective_ruleset_t eff;
    memset(&eff, 0, sizeof(eff));

    /* First pass: mark subsumed rules (PRECEDENCE only) */
    bool *removed = calloc((size_t)pending_count, sizeof(bool));
    if (pending_count > 0 && !removed) { free(groups); free(pending); return -1; }

    for (int i = 0; i < pending_count; i++) {
        if (removed[i] || groups[i].used) continue;
        if (pending[i].type != LAYER_PRECEDENCE) continue;
        if (groups[i].mode == 0) { removed[i] = true; continue; }
        for (int j = 0; j < pending_count; j++) {
            if (i == j || removed[j] || groups[j].used) continue;
            if (pending[j].type != LAYER_PRECEDENCE) continue;
            if (groups[j].mode == 0) { removed[j] = true; continue; }
            /* Standard subsumption: same constraints, broader pattern */
            if (rule_subsumes(&pending[i].rule, &pending[j].rule)) {
                removed[j] = true;
                continue;
            }
            /* Subject rule redundancy: unconstrained rule makes subject-constrained
             * rule redundant if it grants a superset of modes (PRECEDENCE only). */
            if (subject_rule_redundant(&pending[i].rule, &pending[j].rule)) {
                removed[j] = true;
            }
        }
    }

    /* SPECIFICITY subject redundancy: for SPECIFICITY layers (replacement semantics),
     * a subject-constrained rule is redundant only if its mode is EXACTLY EQUAL to
     * the unconstrained rule's mode. Since SPECIFICITY replaces rather than intersects,
     * different modes would change behavior for the constrained subjects. */
    for (int i = 0; i < pending_count; i++) {
        if (removed[i] || groups[i].used) continue;
        if (pending[i].type != LAYER_PRECEDENCE) continue;
        if (pending[i].rule.subject_regex[0] != '\0') continue;  /* only unconstrained */
        for (int j = 0; j < pending_count; j++) {
            if (i == j || removed[j] || groups[j].used) continue;
            if (pending[j].type != LAYER_SPECIFICITY) continue;
            if (pending[j].rule.subject_regex[0] == '\0') continue;  /* only subject-constrained */
            /* Same pattern and exact mode match → redundant */
            if (strcmp(pending[i].rule.pattern, pending[j].rule.pattern) != 0) continue;
            if (pending[i].rule.op_type != pending[j].rule.op_type) continue;
            if (pending[i].rule.flags != pending[j].rule.flags) continue;
            if (pending[i].rule.min_uid != pending[j].rule.min_uid) continue;
            if (groups[i].mode != groups[j].mode) continue;  /* exact mode match required */
            removed[j] = true;
        }
    }

    /* Second pass: classify and add to effective */
    for (int i = 0; i < pending_count; i++) {
        if (removed[i] || groups[i].used) continue;
        rule_t r = pending[i].rule;
        r.mode = groups[i].mode;

        compiled_rule_t cr;
        if (compile_rule(&eff, &r, &cr) < 0) {
            free(removed); free(groups); free(pending);
            eff_free(&eff);
            return -1;
        }

        if (pending[i].type == LAYER_SPECIFICITY) {
            if (is_static_rule(&r)) {
                if (eff_add_spec_static(&eff, &cr) < 0) {
                    free(removed); free(groups); free(pending);
                    eff_free(&eff);
                    return -1;
                }
            } else {
                if (eff_add_spec_dynamic(&eff, &cr) < 0) {
                    free(removed); free(groups); free(pending);
                    eff_free(&eff);
                    return -1;
                }
            }
        } else {
            if (is_static_rule(&r)) {
                if (eff_add_static(&eff, &cr) < 0) {
                    free(removed); free(groups); free(pending);
                    eff_free(&eff);
                    return -1;
                }
            } else {
                if (eff_add_dynamic(&eff, &cr) < 0) {
                    free(removed); free(groups); free(pending);
                    eff_free(&eff);
                    return -1;
                }
            }
        }
    }

    free(removed);
    free(groups);
    free(pending);

    /* Phase 4: Sort PRECEDENCE static rules by pattern */
    if (eff.static_count > 1)
        qsort(eff.static_rules, (size_t)eff.static_count,
              sizeof(compiled_rule_t), compare_rule_by_pattern);

    /* Phase 5: Sort PRECEDENCE dynamic rules — DENY first */
    if (eff.dynamic_count > 1)
        qsort(eff.dynamic_rules, (size_t)eff.dynamic_count,
              sizeof(compiled_rule_t), compare_deny_first);

    /* Phase 6: Sort SPECIFICITY static rules by pattern length DESC */
    if (eff.spec_static_count > 1)
        qsort(eff.spec_static_rules, (size_t)eff.spec_static_count,
              sizeof(compiled_rule_t), compare_rule_by_length);

    /* Phase 7: Sort SPECIFICITY dynamic rules by pattern length DESC */
    if (eff.spec_dynamic_count > 1)
        qsort(eff.spec_dynamic_rules, (size_t)eff.spec_dynamic_count,
              sizeof(compiled_rule_t), compare_rule_by_length);

    rs->effective = eff;
    rs->is_compiled = true;
    return 0;
}
