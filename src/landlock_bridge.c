/**
 * @file landlock_bridge.c
 * @brief Translation bridge: soft_ruleset_t → landlock_builder_t.
 *
 * Converts a compiled rule engine ruleset into a Landlock BPF policy,
 * with validation for Landlock-inexpressible features.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "rule_engine.h"
#include "rule_engine_internal.h"
#include "landlock_builder.h"
#include "landlock_bridge.h"

/* ------------------------------------------------------------------ */
/*  Access flag mapping                                                 */
/* ------------------------------------------------------------------ */

uint64_t soft_access_to_ll_fs(uint32_t soft_mask)
{
    uint64_t ll = 0;

    if (soft_mask & SOFT_ACCESS_DENY)
        return 0;  /* deny is handled separately */

    if (soft_mask & SOFT_ACCESS_READ) {
        ll |= LL_FS_READ_FILE | LL_FS_READ_DIR;
    }
    if (soft_mask & SOFT_ACCESS_WRITE) {
        ll |= LL_FS_WRITE_FILE;
    }
    if (soft_mask & SOFT_ACCESS_EXEC) {
        ll |= LL_FS_EXECUTE;
    }
    if (soft_mask & SOFT_ACCESS_CREATE) {
        ll |= LL_FS_WRITE_FILE;  /* create implies write to parent */
    }
    if (soft_mask & SOFT_ACCESS_UNLINK) {
        ll |= LL_FS_REMOVE_FILE | LL_FS_REMOVE_DIR;
    }
    if (soft_mask & SOFT_ACCESS_LINK) {
        /* Hard link creation */
        ll |= LL_FS_WRITE_FILE;
    }
    if (soft_mask & SOFT_ACCESS_MKDIR) {
        ll |= LL_FS_WRITE_FILE;  /* mkdir writes to parent dir */
    }

    return ll;
}

/* ------------------------------------------------------------------ */
/*  Pattern classification                                              */
/* ------------------------------------------------------------------ */

pattern_class_t soft_pattern_classify(const char *pattern)
{
    if (!pattern || !*pattern)
        return PATTERN_EXACT;

    size_t len = strlen(pattern);

    /* Check for double-star suffix (recursive wildcard) */
    if (len >= 3 && pattern[len - 3] == '/' &&
        pattern[len - 2] == '*' && pattern[len - 1] == '*')
        return PATTERN_PREFIX;

    /* Check for triple-dot suffix (recursive wildcard) */
    if (len >= 4 && pattern[len - 4] == '/' &&
        pattern[len - 3] == '.' && pattern[len - 2] == '.' &&
        pattern[len - 1] == '.')
        return PATTERN_PREFIX;

    /* Check for single-star suffix (one-level wildcard, still a prefix for Landlock) */
    if (len >= 2 && pattern[len - 2] == '/' && pattern[len - 1] == '*')
        return PATTERN_WILDCARD;  /* over-permissive for Landlock */

    /* Check for * anywhere in the middle */
    if (memchr(pattern, '*', len) != NULL)
        return PATTERN_WILDCARD;

    return PATTERN_EXACT;
}

/* ------------------------------------------------------------------ */
/*  Strip trailing wildcards to get the prefix path                   */
/* ------------------------------------------------------------------ */

/**
 * Extract the base path from a pattern, stripping trailing wildcards.
 * Returns a static buffer (caller should copy if needed long-term).
 */
static const char *pattern_to_prefix(const char *pattern)
{
    static char buf[MAX_PATTERN_LEN];
    size_t len = strlen(pattern);

    if (len == 0) {
        buf[0] = '\0';
        return buf;
    }

    /* /path/** → /path */
    if (len >= 3 && pattern[len - 3] == '/' &&
        pattern[len - 2] == '*' && pattern[len - 1] == '*') {
        size_t base = len - 3;
        memcpy(buf, pattern, base);
        buf[base] = '\0';
        return buf;
    }

    /* /path/... → /path */
    if (len >= 4 && pattern[len - 4] == '/' &&
        pattern[len - 3] == '.' && pattern[len - 2] == '.' &&
        pattern[len - 1] == '.') {
        size_t base = len - 4;
        memcpy(buf, pattern, base);
        buf[base] = '\0';
        return buf;
    }

    /* /path/* → /path (over-permissive) */
    if (len >= 2 && pattern[len - 2] == '/' && pattern[len - 1] == '*') {
        size_t base = len - 2;
        memcpy(buf, pattern, base);
        buf[base] = '\0';
        return buf;
    }

    /* Exact path */
    strncpy(buf, pattern, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    return buf;
}

/* ------------------------------------------------------------------ */
/*  Landlock compatibility validation                                 */
/* ------------------------------------------------------------------ */

/**
 * Check a single rule for Landlock compatibility.
 * Returns 0 if compatible, -1 if not (with error_msg set).
 */
static int validate_rule(const rule_t *r, int rule_idx,
                         const char **error_msg, int *error_line)
{
    /* Subject constraints cannot be expressed in Landlock */
    if (r->subject_regex[0] != '\0') {
        *error_msg = "subject constraint not supported by Landlock";
        if (error_line) *error_line = rule_idx;
        return -1;
    }

    /* UID constraints cannot be expressed in Landlock */
    if (r->min_uid > 0) {
        *error_msg = "UID constraint not supported by Landlock";
        if (error_line) *error_line = rule_idx;
        return -1;
    }

    /* Binary operations (COPY, MOVE, etc.) with ${SRC}/${DST} templates
     * cannot be expressed as single-path Landlock rules */
    if (r->linked_path_var[0] != '\0') {
        *error_msg = "dual-path operation (COPY/MOVE/LINK/MOUNT) not supported by Landlock";
        if (error_line) *error_line = rule_idx;
        return -1;
    }

    /* Non-trivial operation types: Landlock only knows file access rights,
     * not syscall intent. Rules with specific op types other than READ/WRITE/EXEC
     * may not map correctly. We warn but don't reject. */

    /* Wildcards in the middle of patterns cannot be prefix-matched */
    pattern_class_t pc = soft_pattern_classify(r->pattern);
    if (pc == PATTERN_WILDCARD) {
        *error_msg = "mid-path wildcard (*) cannot be expressed in Landlock";
        if (error_line) *error_line = rule_idx;
        return -1;
    }

    return 0;
}

int soft_ruleset_validate_for_landlock(const soft_ruleset_t *rs,
                                       const char **error_msg,
                                       int *error_line)
{
    if (!rs) {
        if (error_msg) *error_msg = "NULL ruleset";
        return -1;
    }

    static const char *static_msgs[] = {
        "subject constraint not supported by Landlock",
        "UID constraint not supported by Landlock",
        "dual-path operation (COPY/MOVE/LINK/MOUNT) not supported by Landlock",
        "mid-path wildcard (*) cannot be expressed in Landlock",
    };

    /* If compiled, check the effective ruleset */
    if (rs->is_compiled) {
        const effective_ruleset_t *eff = &rs->effective;
        int idx = 0;

        /* SPECIFICITY rules have different semantics (longest-match-wins)
         * compared to Landlock's flat allow-list. Reject them. */
        if (eff->spec_static_count > 0 || eff->spec_dynamic_count > 0) {
            if (error_msg) *error_msg = "SPECIFICITY layer rules not supported by Landlock (longest-match semantics)";
            if (error_line) *error_line = 0;
            return -1;
        }

        /* Check static rules */
        for (int i = 0; i < eff->static_count; i++) {
            const compiled_rule_t *cr = &eff->static_rules[i];
            /* Recompute from the rule fields */
            if (cr->subject_regex && cr->subject_regex[0] != '\0') {
                if (error_msg) *error_msg = static_msgs[0];
                if (error_line) *error_line = idx;
                return -1;
            }
            if (cr->min_uid > 0) {
                if (error_msg) *error_msg = static_msgs[1];
                if (error_line) *error_line = idx;
                return -1;
            }
            if (cr->flags & SOFT_RULE_TEMPLATE) {
                if (error_msg) *error_msg = static_msgs[2];
                if (error_line) *error_line = idx;
                return -1;
            }
            pattern_class_t pc = soft_pattern_classify(cr->pattern);
            if (pc == PATTERN_WILDCARD) {
                if (error_msg) *error_msg = static_msgs[3];
                if (error_line) *error_line = idx;
                return -1;
            }
            idx++;
        }

        /* Check dynamic rules */
        for (int i = 0; i < eff->dynamic_count; i++) {
            const compiled_rule_t *cr = &eff->dynamic_rules[i];
            if (cr->subject_regex && cr->subject_regex[0] != '\0') {
                if (error_msg) *error_msg = static_msgs[0];
                if (error_line) *error_line = idx;
                return -1;
            }
            if (cr->min_uid > 0) {
                if (error_msg) *error_msg = static_msgs[1];
                if (error_line) *error_line = idx;
                return -1;
            }
            if (cr->flags & SOFT_RULE_TEMPLATE) {
                if (error_msg) *error_msg = static_msgs[2];
                if (error_line) *error_line = idx;
                return -1;
            }
            pattern_class_t pc = soft_pattern_classify(cr->pattern);
            if (pc == PATTERN_WILDCARD) {
                if (error_msg) *error_msg = static_msgs[3];
                if (error_line) *error_line = idx;
                return -1;
            }
            idx++;
        }

        /* Check SPECIFICITY rules */
        for (int i = 0; i < eff->spec_static_count; i++) {
            const compiled_rule_t *cr = &eff->spec_static_rules[i];
            if (cr->subject_regex && cr->subject_regex[0] != '\0') {
                if (error_msg) *error_msg = static_msgs[0];
                if (error_line) *error_line = idx;
                return -1;
            }
            if (cr->min_uid > 0) {
                if (error_msg) *error_msg = static_msgs[1];
                if (error_line) *error_line = idx;
                return -1;
            }
            if (cr->flags & SOFT_RULE_TEMPLATE) {
                if (error_msg) *error_msg = static_msgs[2];
                if (error_line) *error_line = idx;
                return -1;
            }
            pattern_class_t pc = soft_pattern_classify(cr->pattern);
            if (pc == PATTERN_WILDCARD) {
                if (error_msg) *error_msg = static_msgs[3];
                if (error_line) *error_line = idx;
                return -1;
            }
            idx++;
        }

        for (int i = 0; i < eff->spec_dynamic_count; i++) {
            const compiled_rule_t *cr = &eff->spec_dynamic_rules[i];
            if (cr->subject_regex && cr->subject_regex[0] != '\0') {
                if (error_msg) *error_msg = static_msgs[0];
                if (error_line) *error_line = idx;
                return -1;
            }
            if (cr->min_uid > 0) {
                if (error_msg) *error_msg = static_msgs[1];
                if (error_line) *error_line = idx;
                return -1;
            }
            if (cr->flags & SOFT_RULE_TEMPLATE) {
                if (error_msg) *error_msg = static_msgs[2];
                if (error_line) *error_line = idx;
                return -1;
            }
            pattern_class_t pc = soft_pattern_classify(cr->pattern);
            if (pc == PATTERN_WILDCARD) {
                if (error_msg) *error_msg = static_msgs[3];
                if (error_line) *error_line = idx;
                return -1;
            }
            idx++;
        }

        return 0;
    }

    /* Not compiled: check descriptive layers */
    int rule_idx = 0;
    for (int l = 0; l < rs->layer_count; l++) {
        const layer_t *lyr = &rs->layers[l];

        /* Layer masks cannot be expressed in Landlock */
        if (lyr->mask != 0) {
            if (error_msg) *error_msg = "layer mode mask not supported by Landlock";
            if (error_line) *error_line = rule_idx;
            return -1;
        }

        /* SPECIFICITY layer semantics differ from Landlock's flat model */
        if (lyr->type == LAYER_SPECIFICITY && lyr->count > 0) {
            /* Not a hard rejection, but worth noting */
        }

        for (int r = 0; r < lyr->count; r++) {
            if (validate_rule(&lyr->rules[r], rule_idx, error_msg, error_line) != 0)
                return -1;
            rule_idx++;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Translation: soft_ruleset_t → landlock_builder_t                  */
/* ------------------------------------------------------------------ */

void soft_landlock_deny_prefixes_free(const char **prefixes)
{
    if (!prefixes) return;
    for (int i = 0; prefixes[i] != NULL; i++)
        free((char *)prefixes[i]);
    free(prefixes);
}

landlock_builder_t *soft_ruleset_to_landlock(const soft_ruleset_t *rs,
                                             const char ***deny_prefixes_out)
{
    if (!rs) return NULL;

    /* Compile if not already compiled */
    soft_ruleset_t *mutable_rs = (soft_ruleset_t *)rs;
    if (!rs->is_compiled) {
        if (soft_ruleset_compile(mutable_rs) != 0)
            return NULL;
    }

    landlock_builder_t *b = landlock_builder_new();
    if (!b) return NULL;

    const effective_ruleset_t *eff = &rs->effective;

    /* Collect deny prefixes for the caller (only if requested) */
    const char **deny_prefixes = NULL;
    int deny_cap = 0;
    int deny_idx = 0;

    /* Process all compiled rule arrays */
    const compiled_rule_t *all_rules[4];
    int all_counts[4];
    all_rules[0] = eff->static_rules;
    all_counts[0] = eff->static_count;
    all_rules[1] = eff->dynamic_rules;
    all_counts[1] = eff->dynamic_count;
    all_rules[2] = eff->spec_static_rules;
    all_counts[2] = eff->spec_static_count;
    all_rules[3] = eff->spec_dynamic_rules;
    all_counts[3] = eff->spec_dynamic_count;

    for (int arr = 0; arr < 4; arr++) {
        for (int i = 0; i < all_counts[arr]; i++) {
            const compiled_rule_t *cr = &all_rules[arr][i];

            /* Skip rules with constraints Landlock can't express */
            if ((cr->subject_regex && cr->subject_regex[0] != '\0') ||
                cr->min_uid > 0 ||
                (cr->flags & SOFT_RULE_TEMPLATE)) {
                continue;  /* skip inexpressible rules */
            }

            /* Classify pattern */
            pattern_class_t pc = soft_pattern_classify(cr->pattern);
            if (pc == PATTERN_WILDCARD) {
                continue;  /* skip mid-path wildcards */
            }

            /* Convert pattern to Landlock-compatible prefix */
            const char *prefix = pattern_to_prefix(cr->pattern);
            if (!prefix || !*prefix) {
                continue;
            }

            /* Check if this is a deny rule */
            if ((cr->mode & SOFT_ACCESS_DENY) || soft_access_to_ll_fs(cr->mode) == 0) {
                /* Add deny to builder so overlap removal subtracts it from allows */
                landlock_builder_deny(b, prefix);

                /* Also track for caller */
                if (deny_prefixes_out) {
                    if (deny_idx >= deny_cap) {
                        deny_cap = deny_cap == 0 ? 16 : deny_cap * 2;
                        deny_prefixes = realloc(deny_prefixes,
                                                (deny_cap + 1) * sizeof(char *));
                        if (!deny_prefixes) {
                            landlock_builder_free(b);
                            soft_landlock_deny_prefixes_free(deny_prefixes);
                            return NULL;
                        }
                    }
                    deny_prefixes[deny_idx] = strdup(prefix);
                    if (deny_prefixes[deny_idx]) deny_idx++;
                }
                continue;
            }

            /* Allow rule */
            uint64_t access = soft_access_to_ll_fs(cr->mode);
            if (access == 0) continue;

            if (landlock_builder_allow(b, prefix, access) != 0) {
                landlock_builder_free(b);
                soft_landlock_deny_prefixes_free(deny_prefixes);
                return NULL;
            }
        }
    }

    /* NULL-terminate the deny prefix array */
    if (deny_prefixes) {
        deny_prefixes[deny_idx] = NULL;
    }

    if (deny_prefixes_out) {
        *deny_prefixes_out = deny_prefixes;
    } else {
        soft_landlock_deny_prefixes_free(deny_prefixes);
    }

    return b;
}
