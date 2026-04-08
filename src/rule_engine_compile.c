/**
 * @file rule_engine_compile.c
 * @brief Rule simplification: descriptive layers → effective flat ruleset.
 *
 * See RuleEngineSpec.md §10 for the design rationale.
 */

#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "rule_engine.h"
#include "rule_engine_internal.h"

/* ------------------------------------------------------------------ */
/*  Pattern containment                                                 */
/* ------------------------------------------------------------------ */

/**
 * Return true if pattern A matches every path that pattern B matches.
 */
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

    /* Static/wildcard never covers recursive */
    if (b_rec) return false;

    /* Both static: only exact match (handled above) */
    if (!a_star && !b_star) return false;

    /* Both wildcards: check that a is at least as broad as b.
     *
     * Strategy: split each pattern at its first star, compare prefix
     * and suffix separately.
     *
     *   /etc/STAR covers /etc/STAR.c  -> pre "/etc/" == "/etc/", suf "" covers ".c"
     *   /usr/local/STAR/STAR.so covers /usr/local/bin/STAR.so
     *     -> pre "/usr/local/" is prefix of "/usr/local/bin/"
     *        suf "/STAR.so" is suffix of "/STAR.so"
     *   /usr/local/STAR/STAR.so does NOT cover /usr/local/STAR.so
     *     -> pre "/usr/local/" == "/usr/local/", but suf "/STAR.so" NOT suffix of "STAR.so"
     *   /usr/DOUBLE/lib covers /usr/local/lib
     *     -> pre "/usr/", suf "/lib"
     *   /usr/STAR/lib covers /usr/local/lib (where STAR is single-star)
     *     -> pre "/usr/", suf "/lib"
     */
    if (a_star || b_star) {
        /* Find first * or ** in each pattern */
        const char *star_a = strchr(a, '*');
        const char *star_b = strchr(b, '*');
        bool a_double = (star_a && *(star_a + 1) == '*');
        bool b_double = (star_b && *(star_b + 1) == '*');

        /* ** is strictly more permissive than *: if a has * and b has **,
         * a cannot cover b (unless the rest of the pattern compensates,
         * which we conservatively say no). */
        if (!a_double && b_double) return false;

        size_t pre_a = (size_t)(star_a - a);
        size_t pre_b = (size_t)(star_b - b);

        /* Prefix check: a's prefix must be a prefix of b's prefix */
        if (pre_a > pre_b) return false;
        if (strncmp(a, b, pre_a) != 0) return false;

        /* Suffix check: compare everything after the first star.
         * ** covers * and more, so if a has ** and b has *, the suffix
         * check is relaxed. */
        const char *suf_a = star_a + (a_double ? 2 : 1);
        const char *suf_b = star_b + (b_double ? 2 : 1);
        if (*suf_a == '/') suf_a++;
        if (*suf_b == '/') suf_b++;

        /* If a has ** and b has *, a's suffix covers b's */
        if (a_double && !b_double) return true;

        /* Both single-star: check if a's suffix is a suffix of b's suffix,
         * or if a's suffix matches b's suffix literally. */
        size_t len_suf_a = strlen(suf_a);
        size_t len_suf_b = strlen(suf_b);

        if (len_suf_a == 0) return true;  /* a ends with *, covers anything */

        /* Check if suf_b ends with suf_a (suffix containment) */
        if (len_suf_b >= len_suf_a) {
            if (strcmp(suf_b + len_suf_b - len_suf_a, suf_a) == 0) return true;
        }

        /* Check if a's suffix matches b's suffix as a pattern */
        /* This handles cases like /etc/STAR vs /etc/STAR.conf
         * where suf_a="" and suf_b=".conf" -> already handled above */
        /* For multi-star suffixes like /STAR/STAR.so, do a glob match */
        if (strchr(suf_a, '*') || strchr(suf_b, '*')) {
            return path_matches(suf_a, suf_b);
        }

        /* Static suffix: suf_a must equal suf_b or be empty */
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
    /* General must grant at least the same bits as specific */
    if ((general->mode & specific->mode) != specific->mode) return false;
    return true;
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
    if (!eff || eff->count == 0) { if (out_matched_pattern) *out_matched_pattern = NULL; return 0; }

    uint32_t granted = 0;
    const char *last_pattern = NULL;

    for (int i = 0; i < eff->count; i++) {
        const rule_t *r = &eff->rules[i];

        if (r->op_type != op && r->op_type != SOFT_OP_READ &&
            r->op_type != SOFT_OP_WRITE) continue;
        if (!subject_matches(r, ctx->subject)) continue;
        if (r->min_uid > 0 && ctx->uid < r->min_uid) continue;
        if (!rule_matches_path(r, path, ctx)) continue;

        if (r->mode & SOFT_ACCESS_DENY) {
            if (out_matched_pattern) *out_matched_pattern = r->pattern;
            return 0;  /* DENY short-circuit */
        }
        granted |= r->mode;
        last_pattern = r->pattern;
    }

    if (out_matched_pattern) *out_matched_pattern = last_pattern;
    return granted;
}

/* ------------------------------------------------------------------ */
/*  Compilation: descriptive layers → effective flat ruleset           */
/* ------------------------------------------------------------------ */

void soft_ruleset_invalidate(soft_ruleset_t *rs)
{
    if (!rs) return;
    if (rs->is_compiled) {
        free(rs->effective.rules);
        rs->effective.rules = NULL;
        rs->effective.count = 0;
        rs->effective.capacity = 0;
        rs->is_compiled = false;
    }
}

bool soft_ruleset_is_compiled(const soft_ruleset_t *rs)
{
    if (!rs) return false;
    return rs->is_compiled;
}

static int eff_add(effective_ruleset_t *eff, const rule_t *r)
{
    if (eff->count >= eff->capacity) {
        int new_cap = eff->capacity + EFF_CHUNK;
        if (new_cap < 0) return -1;
        rule_t *new_rules = realloc(eff->rules, (size_t)new_cap * sizeof(rule_t));
        if (!new_rules) return -1;
        eff->rules = new_rules;
        eff->capacity = new_cap;
    }
    eff->rules[eff->count++] = *r;
    return 0;
}

int soft_ruleset_compile(soft_ruleset_t *rs)
{
    if (!rs) { errno = EINVAL; return -1; }

    /* Invalidate any previous effective */
    free(rs->effective.rules);
    rs->effective.rules = NULL;
    rs->effective.count = 0;
    rs->effective.capacity = 0;

    /* Count total rules */
    int max_pending = 0;
    for (int i = 0; i < rs->layer_count; i++) {
        max_pending += rs->layers[i].count;
    }
    if (max_pending == 0) {
        rs->is_compiled = true;
        return 0;
    }

    /* Phase 1: Cross-layer shadow elimination */
    typedef struct {
        rule_t rule;
        int layer;
    } pending_rule_t;

    pending_rule_t *pending = calloc((size_t)max_pending, sizeof(pending_rule_t));
    if (!pending) return -1;
    int pending_count = 0;

    for (int li = 0; li < rs->layer_count; li++) {
        const layer_t *lyr = &rs->layers[li];
        for (int ri = 0; ri < lyr->count; ri++) {
            const rule_t *r = &lyr->rules[ri];

            /* Check if shadowed by higher-layer DENY */
            bool shadowed = false;
            if (r->mode & SOFT_ACCESS_DENY) {
                for (int pi = 0; pi < pending_count && !shadowed; pi++) {
                    const pending_rule_t *pr = &pending[pi];
                    if (pr->rule.mode & SOFT_ACCESS_DENY &&
                        rule_constraints_equal(&pr->rule, r) &&
                        pattern_covers(pr->rule.pattern, r->pattern)) {
                        shadowed = true;
                    }
                }
            } else {
                for (int pi = 0; pi < pending_count && !shadowed; pi++) {
                    const pending_rule_t *pr = &pending[pi];
                    if (pr->rule.mode & SOFT_ACCESS_DENY &&
                        pattern_covers(pr->rule.pattern, r->pattern)) {
                        shadowed = true;
                    }
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
    typedef struct {
        uint32_t intersected_mode;
        bool used;
    } group_entry_t;

    group_entry_t *groups = calloc((size_t)pending_count, sizeof(group_entry_t));
    if (!groups) { free(pending); return -1; }

    for (int i = 0; i < pending_count; i++) {
        groups[i].intersected_mode = pending[i].rule.mode;
        groups[i].used = false;
    }

    for (int i = 0; i < pending_count; i++) {
        if (groups[i].used) continue;
        for (int j = i + 1; j < pending_count; j++) {
            if (groups[j].used) continue;
            if (strcmp(pending[i].rule.pattern, pending[j].rule.pattern) == 0 &&
                rule_constraints_equal(&pending[i].rule, &pending[j].rule)) {
                groups[i].intersected_mode &= pending[j].rule.mode;
                groups[j].used = true;
            }
        }
    }

    /* Build effective ruleset */
    effective_ruleset_t eff;
    memset(&eff, 0, sizeof(eff));

    for (int i = 0; i < pending_count; i++) {
        if (groups[i].used) continue;
        rule_t r = pending[i].rule;
        r.mode = groups[i].intersected_mode;
        /* Skip zero-mode rules (intersection eliminated all bits) */
        if (r.mode == 0) continue;
        eff_add(&eff, &r);
    }

    free(groups);

    /* Phase 3: Subsumption within effective */
    bool *removed = calloc((size_t)eff.count, sizeof(bool));
    if (eff.count > 0 && !removed) { free(eff.rules); free(pending); return -1; }

    for (int i = 0; i < eff.count; i++) {
        if (removed[i]) continue;
        for (int j = 0; j < eff.count; j++) {
            if (i == j || removed[j]) continue;
            if (rule_subsumes(&eff.rules[i], &eff.rules[j])) {
                removed[j] = true;
            }
        }
    }

    effective_ruleset_t compact;
    memset(&compact, 0, sizeof(compact));
    for (int i = 0; i < eff.count; i++) {
        if (!removed[i]) {
            eff_add(&compact, &eff.rules[i]);
        }
    }
    free(eff.rules);
    free(removed);

    /* Phase 4: Sort DENYs first for fast short-circuit */
    for (int i = 0; i < compact.count - 1; i++) {
        for (int j = i + 1; j < compact.count; j++) {
            bool i_deny = compact.rules[i].mode & SOFT_ACCESS_DENY;
            bool j_deny = compact.rules[j].mode & SOFT_ACCESS_DENY;
            if (!i_deny && j_deny) {
                rule_t tmp = compact.rules[i];
                compact.rules[i] = compact.rules[j];
                compact.rules[j] = tmp;
            }
        }
    }

    rs->effective = compact;
    rs->is_compiled = true;

    free(pending);
    return 0;
}
