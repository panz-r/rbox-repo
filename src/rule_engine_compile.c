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
    out->pattern_len = (uint16_t)strlen(r->pattern);
    out->mode = r->mode;
    out->min_uid = r->min_uid;
    out->flags = r->flags;
    out->op_type = (uint16_t)r->op_type;
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
 *
 * Returns the granted mode (0 if no rules matched or if DENY).
 * Sets *out_deny to true only if a DENY rule was matched.
 */
static uint32_t match_static_rules(const effective_ruleset_t *eff,
                                   const char *path,
                                   soft_binary_op_t op,
                                   const soft_access_ctx_t *ctx,
                                   const char **out_matched_pattern,
                                   bool *out_deny)
{
    if (out_deny) *out_deny = false;
    if (!eff || !path) { if (out_matched_pattern) *out_matched_pattern = NULL; return 0; }

    uint32_t granted = SOFT_ACCESS_ALL;
    const char *last_pattern = NULL;
    bool any_matched = false;
    bool deny_matched = false;
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
        size_t pat_len = r->pattern_len;
        if (pat_len != path_len) break;  /* past exact matches */
        if (memcmp(r->pattern, path, pat_len) != 0) break;

        if (r->op_type != op && r->op_type != SOFT_OP_READ &&
            r->op_type != SOFT_OP_WRITE) continue;
        if (!compiled_subject_matches(r, ctx->subject)) continue;
        if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;

        any_matched = true;
        if (r->mode & SOFT_ACCESS_DENY) {
            deny_matched = true;
            if (out_matched_pattern) *out_matched_pattern = r->pattern;
            if (out_deny) *out_deny = true;
            return 0; /* DENY short-circuit */
        }
        granted &= r->mode;
        last_pattern = r->pattern;
    }

    /* Scan backwards from lo-1 to find prefix matches. */
    for (int i = lo - 1; i >= 0; i--) {
        const compiled_rule_t *r = &eff->static_rules[i];
        size_t pat_len = r->pattern_len;
        if (pat_len >= path_len) continue;  /* can't be a prefix of shorter path */
        if (memcmp(r->pattern, path, pat_len) != 0 || path[pat_len] != '/')
            continue;

        if (r->op_type != op && r->op_type != SOFT_OP_READ &&
            r->op_type != SOFT_OP_WRITE) continue;
        if (!compiled_subject_matches(r, ctx->subject)) continue;
        if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;

        any_matched = true;
        if (r->mode & SOFT_ACCESS_DENY) {
            deny_matched = true;
            if (out_matched_pattern) *out_matched_pattern = r->pattern;
            if (out_deny) *out_deny = true;
            return 0; /* DENY short-circuit */
        }
        granted &= r->mode;
        last_pattern = r->pattern;
    }

    if (out_matched_pattern) *out_matched_pattern = last_pattern;
    if (!any_matched) return 0;
    /* granted may be 0 if modes were disjoint — but that's NOT a deny */
    if (out_deny) *out_deny = deny_matched;
    return granted;
}

/** Match dynamic rules (wildcards, recursive, templates).
 * Uses intersection (AND) semantics for PRECEDENCE rules.
 * Sets *out_deny to true only if a DENY rule was matched. */
static uint32_t match_dynamic_rules(const effective_ruleset_t *eff,
                                    const char *path,
                                    soft_binary_op_t op,
                                    const soft_access_ctx_t *ctx,
                                    const char **out_matched_pattern,
                                    bool *out_deny)
{
    if (out_deny) *out_deny = false;
    if (!eff || !path) { if (out_matched_pattern) *out_matched_pattern = NULL; return 0; }

    uint32_t granted = SOFT_ACCESS_ALL;
    const char *last_pattern = NULL;
    bool deny_matched = false;

    for (int i = 0; i < eff->dynamic_count; i++) {
        const compiled_rule_t *r = &eff->dynamic_rules[i];
        if (r->op_type != op && r->op_type != SOFT_OP_READ &&
            r->op_type != SOFT_OP_WRITE) continue;
        if (!compiled_subject_matches(r, ctx->subject)) continue;
        if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;
        if (!compiled_rule_matches_path(r, path, ctx)) continue;

        if (r->mode & SOFT_ACCESS_DENY) {
            deny_matched = true;
            if (out_matched_pattern) *out_matched_pattern = r->pattern;
            if (out_deny) *out_deny = true;
            return 0;
        }
        granted &= r->mode;
        last_pattern = r->pattern;
    }

    if (out_matched_pattern) *out_matched_pattern = last_pattern;
    if (out_deny) *out_deny = deny_matched;
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
    bool static_deny = false;
    uint32_t granted = match_static_rules(eff, path, op, ctx, &static_matched, &static_deny);
    if (static_deny) {
        if (out_matched_pattern) *out_matched_pattern = static_matched;
        return 0; /* DENY matched in PRECEDENCE static rules */
    }

    const char *dyn_pattern = NULL;
    bool dyn_deny = false;
    uint32_t dyn_granted = match_dynamic_rules(eff, path, op, ctx, &dyn_pattern, &dyn_deny);
    if (dyn_deny) {
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
    if (ra->pattern_len > rb->pattern_len) return -1;
    if (ra->pattern_len < rb->pattern_len) return 1;
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
        size_t pat_len = r->pattern_len;
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

        size_t pat_len = r->pattern_len;
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

/* ------------------------------------------------------------------ */
/*  Binary serialization: save / load compiled ruleset                 */
/* ------------------------------------------------------------------ */

/* Binary format:
 *   Header:  magic(4) version(2) flags(2)
 *   Strings:  str_data_len(4) [string arena data...]
 *   Counts:  static(4) dynamic(4) spec_static(4) spec_dynamic(4)
 *   Rules:   mode(4) min_uid(4) flags(4) op_type(2) pattern_len(2)
 *            pat_off(4) subj_off(4)   [24 bytes per rule]
 *
 * String offsets are relative to the start of the string arena data.
 */

#define COMPILED_MAGIC "RBE\x01"
#define COMPILED_VERSION 1

int soft_ruleset_save_compiled(const soft_ruleset_t *rs,
                               void **out_buf,
                               size_t *out_len)
{
    if (!rs || !rs->is_compiled || !out_buf || !out_len) {
        if (out_buf) *out_buf = NULL;
        if (out_len) *out_len = 0;
        errno = EINVAL;
        return -1;
    }

    const effective_ruleset_t *eff = &rs->effective;
    const str_arena_t *sa = &eff->strings;

    size_t hdr_sz = 4 + 2 + 2;
    size_t str_len_field = 4;
    size_t str_data_sz = sa->used;
    size_t rule_sz = 24;
    size_t rule_count = (size_t)(eff->static_count + eff->dynamic_count +
                                  eff->spec_static_count + eff->spec_dynamic_count);
    size_t counts_sz = 16;
    size_t total = hdr_sz + str_len_field + str_data_sz + counts_sz + rule_count * rule_sz;

    char *buf = malloc(total);
    if (!buf) { errno = ENOMEM; return -1; }

    char *p = buf;

    /* Header */
    memcpy(p, COMPILED_MAGIC, 4); p += 4;
    uint16_t ver = COMPILED_VERSION;
    memcpy(p, &ver, 2); p += 2;
    uint16_t flags = 0;
    memcpy(p, &flags, 2); p += 2;

    /* Strings: length then raw arena data */
    uint32_t sdl = (uint32_t)sa->used;
    memcpy(p, &sdl, 4); p += 4;
    memcpy(p, sa->buf, sa->used); p += sa->used;

    /* Rule counts */
    uint32_t cnt[4];
    cnt[0] = (uint32_t)eff->static_count;
    cnt[1] = (uint32_t)eff->dynamic_count;
    cnt[2] = (uint32_t)eff->spec_static_count;
    cnt[3] = (uint32_t)eff->spec_dynamic_count;
    memcpy(p, cnt, sizeof(cnt)); p += sizeof(cnt);

    /* Write rules */
    int arr;
    for (arr = 0; arr < 4; arr++) {
        const compiled_rule_t *rules;
        int count;
        if (arr == 0) { rules = eff->static_rules; count = eff->static_count; }
        else if (arr == 1) { rules = eff->dynamic_rules; count = eff->dynamic_count; }
        else if (arr == 2) { rules = eff->spec_static_rules; count = eff->spec_static_count; }
        else { rules = eff->spec_dynamic_rules; count = eff->spec_dynamic_count; }

        int i;
        for (i = 0; i < count; i++) {
            const compiled_rule_t *r = &rules[i];
            uint32_t mode = r->mode;
            uint32_t min_uid = r->min_uid;
            uint32_t flags_r = r->flags;
            uint16_t op_type = r->op_type;
            uint16_t pat_len = r->pattern_len;
            uint32_t pat_off = (uint32_t)(r->pattern - sa->buf);
            uint32_t subj_off = r->subject_regex ? (uint32_t)(r->subject_regex - sa->buf) : 0;
            memcpy(p, &mode, 4); p += 4;
            memcpy(p, &min_uid, 4); p += 4;
            memcpy(p, &flags_r, 4); p += 4;
            memcpy(p, &op_type, 2); p += 2;
            memcpy(p, &pat_len, 2); p += 2;
            memcpy(p, &pat_off, 4); p += 4;
            memcpy(p, &subj_off, 4); p += 4;
        }
    }

    *out_buf = buf;
    *out_len = (size_t)(p - buf);
    return 0;
}

soft_ruleset_t *soft_ruleset_load_compiled(const void *buf, size_t len)
{
    if (!buf || len < 28) { errno = EINVAL; return NULL; }

    const char *p = (const char *)buf;
    const char *end = p + len;

    /* Header */
    if (memcmp(p, COMPILED_MAGIC, 4) != 0) { errno = EINVAL; return NULL; }
    p += 4;
    uint16_t ver;
    memcpy(&ver, p, 2); p += 2;
    if (ver != COMPILED_VERSION) { errno = EINVAL; return NULL; }
    p += 2;  /* flags */

    /* Strings */
    if (p + 4 > end) { errno = EINVAL; return NULL; }
    uint32_t str_data_len;
    memcpy(&str_data_len, p, 4); p += 4;
    if (str_data_len == 0 || p + str_data_len > end) { errno = EINVAL; return NULL; }
    const char *str_data = p;
    p += str_data_len;

    /* Rule counts */
    if (p + 16 > end) { errno = EINVAL; return NULL; }
    uint32_t cnt[4];
    memcpy(cnt, p, 16); p += 16;

    /* Create ruleset */
    soft_ruleset_t *rs = soft_ruleset_new();
    if (!rs) return NULL;

    /* Allocate string arena */
    str_arena_t *sa = &rs->effective.strings;
    sa->buf = malloc(str_data_len);
    if (!sa->buf) { soft_ruleset_free(rs); return NULL; }
    memcpy(sa->buf, str_data, str_data_len);
    sa->used = str_data_len;
    sa->capacity = str_data_len;

    /* Helper macro to read one rule field */
    #define READ_U32(v) do { if (p + 4 > end) goto fail; memcpy(&(v), p, 4); p += 4; } while (0)
    #define READ_U16(v) do { if (p + 2 > end) goto fail; memcpy(&(v), p, 2); p += 2; } while (0)

    /* Read rules for each array */
    int arr;
    compiled_rule_t **targets[4];
    int *counts[4];
    int *capacities[4];
    effective_ruleset_t *eff = &rs->effective;
    targets[0] = &eff->static_rules; counts[0] = &eff->static_count; capacities[0] = &eff->static_capacity;
    targets[1] = &eff->dynamic_rules; counts[1] = &eff->dynamic_count; capacities[1] = &eff->dynamic_capacity;
    targets[2] = &eff->spec_static_rules; counts[2] = &eff->spec_static_count; capacities[2] = &eff->spec_static_capacity;
    targets[3] = &eff->spec_dynamic_rules; counts[3] = &eff->spec_dynamic_count; capacities[3] = &eff->spec_dynamic_capacity;

    for (arr = 0; arr < 4; arr++) {
        int c = (int)cnt[arr];
        *counts[arr] = c;
        *capacities[arr] = c;
        if (c > 0) {
            *targets[arr] = calloc((size_t)c, sizeof(compiled_rule_t));
            if (!*targets[arr]) goto fail;
            int i;
            for (i = 0; i < c; i++) {
                compiled_rule_t *r = &(*targets[arr])[i];
                uint32_t mode, min_uid, flags_r, pat_off, subj_off;
                uint16_t op_type, pat_len;
                READ_U32(mode);
                READ_U32(min_uid);
                READ_U32(flags_r);
                READ_U16(op_type);
                READ_U16(pat_len);
                READ_U32(pat_off);
                READ_U32(subj_off);
                if (pat_off >= str_data_len || (subj_off > 0 && subj_off >= str_data_len))
                    goto fail;
                r->mode = mode;
                r->min_uid = min_uid;
                r->flags = flags_r;
                r->op_type = op_type;
                r->pattern_len = pat_len;
                r->pattern = sa->buf + pat_off;
                r->subject_regex = subj_off > 0 ? sa->buf + subj_off : NULL;
            }
        } else {
            *targets[arr] = NULL;
        }
    }

    #undef READ_U32
    #undef READ_U16

    rs->is_compiled = true;
    return rs;

fail:
    soft_ruleset_free(rs);
    return NULL;
}
