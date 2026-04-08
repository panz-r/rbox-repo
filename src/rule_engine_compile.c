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

void eff_free(effective_ruleset_t *eff)
{
    free(eff->static_rules);
    free(eff->dynamic_rules);
    arena_free(&eff->strings);
    eff->static_rules = NULL;
    eff->dynamic_rules = NULL;
    eff->static_count = 0;
    eff->dynamic_count = 0;
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
                                    const soft_access_ctx_t *ctx)
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

    return path_matches(resolved_pattern, resolved);
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
            return compiled_match_with_var(rule->pattern, "SRC", ctx);
        }
        if (strstr(rule->pattern, "${DST}") != NULL) {
            return compiled_match_with_var(rule->pattern, "DST", ctx);
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
 * Find all static rules that match the given path.
 * Static rules are exact or directory-prefix patterns (no wildcards).
 * Returns the accumulated mode from all matching rules.
 */
static uint32_t match_static_rules(const effective_ruleset_t *eff,
                                   const char *path,
                                   soft_binary_op_t op,
                                   const soft_access_ctx_t *ctx,
                                   const char **out_matched_pattern)
{
    if (!eff || !path) return 0;

    uint32_t granted = 0;
    const char *last_pattern = NULL;
    size_t path_len = strlen(path);

    for (int i = 0; i < eff->static_count; i++) {
        const compiled_rule_t *r = &eff->static_rules[i];
        if (r->op_type != op && r->op_type != SOFT_OP_READ &&
            r->op_type != SOFT_OP_WRITE) continue;
        if (!compiled_subject_matches(r, ctx->subject)) continue;
        if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;

        /* Exact match or directory prefix */
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
            if (r->mode & SOFT_ACCESS_DENY) {
                if (out_matched_pattern) *out_matched_pattern = r->pattern;
                return 0; /* DENY short-circuit */
            }
            granted |= r->mode;
            last_pattern = r->pattern;
        }
    }

    if (out_matched_pattern) *out_matched_pattern = last_pattern;
    return granted;
}

/** Match dynamic rules (wildcards, recursive, templates). */
static uint32_t match_dynamic_rules(const effective_ruleset_t *eff,
                                    const char *path,
                                    soft_binary_op_t op,
                                    const soft_access_ctx_t *ctx,
                                    const char **out_matched_pattern)
{
    if (!eff || !path) return 0;

    uint32_t granted = 0;
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
        granted |= r->mode;
        last_pattern = r->pattern;
    }

    if (out_matched_pattern) *out_matched_pattern = last_pattern;
    return granted;
}

/* ------------------------------------------------------------------ */
/*  Evaluation using effective (compiled) ruleset                      */
/* ------------------------------------------------------------------ */

uint32_t eval_effective_path(const effective_ruleset_t *eff,
                             const char *path,
                             soft_binary_op_t op,
                             const soft_access_ctx_t *ctx,
                             const char **out_matched_pattern)
{
    if (!path) { if (out_matched_pattern) *out_matched_pattern = NULL; return 0; }
    if (!eff) { if (out_matched_pattern) *out_matched_pattern = NULL; return 0; }

    /* Phase 1: Static rules — sorted, can use binary search optimization */
    uint32_t granted = match_static_rules(eff, path, op, ctx, out_matched_pattern);
    if (granted == 0 && out_matched_pattern != NULL && *out_matched_pattern != NULL)
        return 0; /* DENY matched in static rules */

    /* Phase 2: Dynamic rules — wildcards, recursive, templates */
    const char *dyn_pattern = NULL;
    uint32_t dyn_granted = match_dynamic_rules(eff, path, op, ctx, &dyn_pattern);
    if (dyn_granted == 0 && dyn_pattern != NULL) {
        if (out_matched_pattern) *out_matched_pattern = dyn_pattern;
        return 0; /* DENY matched in dynamic rules */
    }

    if (dyn_pattern) {
        granted |= dyn_granted;
        if (!*out_matched_pattern) *out_matched_pattern = dyn_pattern;
    }

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
    rs->cache_cursor = 0;
    memset(rs->query_cache, 0, sizeof(rs->query_cache));
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

    /* Phase 1: Cross-layer shadow elimination */
    typedef struct { rule_t rule; int layer; } pending_rule_t;
    pending_rule_t *pending = calloc((size_t)max_pending, sizeof(pending_rule_t));
    if (!pending) return -1;
    int pending_count = 0;

    for (int li = 0; li < rs->layer_count; li++) {
        const layer_t *lyr = &rs->layers[li];
        for (int ri = 0; ri < lyr->count; ri++) {
            const rule_t *r = &lyr->rules[ri];
            bool shadowed = false;
            if (r->mode & SOFT_ACCESS_DENY) {
                for (int pi = 0; pi < pending_count && !shadowed; pi++) {
                    const pending_rule_t *pr = &pending[pi];
                    if (pr->rule.mode & SOFT_ACCESS_DENY &&
                        rule_constraints_equal(&pr->rule, r) &&
                        pattern_covers(pr->rule.pattern, r->pattern))
                        shadowed = true;
                }
            } else {
                for (int pi = 0; pi < pending_count && !shadowed; pi++) {
                    const pending_rule_t *pr = &pending[pi];
                    if (pr->rule.mode & SOFT_ACCESS_DENY &&
                        pattern_covers(pr->rule.pattern, r->pattern))
                        shadowed = true;
                }
            }
            if (!shadowed) {
                pending[pending_count].rule = *r;
                pending[pending_count].layer = li;
                pending_count++;
            }
        }
    }

    /* Phase 2: Mode intersection for identical constraint tuples */
    typedef struct { uint32_t mode; bool used; } group_entry_t;
    group_entry_t *groups = calloc((size_t)pending_count, sizeof(group_entry_t));
    if (!groups) { free(pending); return -1; }
    for (int i = 0; i < pending_count; i++) {
        groups[i].mode = pending[i].rule.mode;
        groups[i].used = false;
    }
    for (int i = 0; i < pending_count; i++) {
        if (groups[i].used) continue;
        for (int j = i + 1; j < pending_count; j++) {
            if (groups[j].used) continue;
            if (strcmp(pending[i].rule.pattern, pending[j].rule.pattern) == 0 &&
                rule_constraints_equal(&pending[i].rule, &pending[j].rule)) {
                groups[i].mode &= pending[j].rule.mode;
                groups[j].used = true;
            }
        }
    }

    /* Phase 3: Separate static vs dynamic, subsumption, build effective */
    effective_ruleset_t eff;
    memset(&eff, 0, sizeof(eff));

    /* First pass: mark subsumed rules */
    bool *removed = calloc((size_t)pending_count, sizeof(bool));
    if (pending_count > 0 && !removed) { free(groups); free(pending); return -1; }

    for (int i = 0; i < pending_count; i++) {
        if (removed[i] || groups[i].used) continue;
        if (groups[i].mode == 0) { removed[i] = true; continue; }
        for (int j = 0; j < pending_count; j++) {
            if (i == j || removed[j] || groups[j].used) continue;
            if (groups[j].mode == 0) { removed[j] = true; continue; }
            if (rule_subsumes(&pending[i].rule, &pending[j].rule))
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

    free(removed);
    free(groups);
    free(pending);

    /* Phase 4: Sort static rules by pattern (for potential binary search) */
    if (eff.static_count > 1)
        qsort(eff.static_rules, (size_t)eff.static_count,
              sizeof(compiled_rule_t), compare_rule_by_pattern);

    /* Phase 5: Sort dynamic rules — DENY first for fast short-circuit */
    if (eff.dynamic_count > 1)
        qsort(eff.dynamic_rules, (size_t)eff.dynamic_count,
              sizeof(compiled_rule_t), compare_deny_first);

    rs->effective = eff;
    rs->is_compiled = true;
    return 0;
}
