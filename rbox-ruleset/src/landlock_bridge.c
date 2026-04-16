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

/* Forward declarations for helper functions */
static inline const char *get_pattern(const effective_ruleset_t *eff, const compiled_rule_t *r);
static inline const char *get_subject(const effective_ruleset_t *eff, const compiled_rule_t *r);
#include "landlock_builder.h"
#include "landlock_bridge.h"

/* ------------------------------------------------------------------ */
/*  Per-rule Landlock compatibility pre-check                           */
/* ------------------------------------------------------------------ */

/** Check if pattern ends with / (single-star suffix). */
static bool is_single_star_suffix(const char *pattern)
{
    if (!pattern) return false;
    size_t len = strlen(pattern);
    return len >= 2 && pattern[len - 2] == '/' && pattern[len - 1] == '*';
}

int soft_rule_is_landlock_compatible(const char *pattern,
                                     const char *subject_regex,
                                     const char *linked_path_var,
                                     const char **error_msg)
{
    if (subject_regex && subject_regex[0] != '\0') {
        if (error_msg) *error_msg = landlock_compat_error_msgs[-LANDLOCK_COMPAT_SUBJECT];
        return -1;
    }
    if (linked_path_var && linked_path_var[0] != '\0') {
        if (error_msg) *error_msg = landlock_compat_error_msgs[-LANDLOCK_COMPAT_TEMPLATE];
        return -1;
    }
    if (is_single_star_suffix(pattern)) {
        if (error_msg) *error_msg = landlock_compat_error_msgs[-LANDLOCK_COMPAT_SINGLE_STAR];
        return -1;
    }
    pattern_class_t pc = soft_pattern_classify(pattern);
    if (pc == PATTERN_WILDCARD) {
        if (error_msg) *error_msg = landlock_compat_error_msgs[-LANDLOCK_COMPAT_WILDCARD];
        return -1;
    }
    return 0;
}

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

    /* /path/... → /path */
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

    /* /path/star → /path (over-permissive) */
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

/** Human-readable messages indexed by negating the enum value. */
const char *const landlock_compat_error_msgs[] = {
    [-LANDLOCK_COMPAT_OK]           = "Compatible with Landlock",
    [-LANDLOCK_COMPAT_SUBJECT]      = "Subject constraint not supported by Landlock",

    [-LANDLOCK_COMPAT_TEMPLATE]     = "Dual-path operation (COPY/MOVE/LINK/MOUNT) not supported by Landlock",
    [-LANDLOCK_COMPAT_WILDCARD]     = "Mid-path wildcard (*) cannot be expressed in Landlock",
    [-LANDLOCK_COMPAT_SPECIFICITY]  = "SPECIFICITY layer rules not supported by Landlock (longest-match semantics)",
    [-LANDLOCK_COMPAT_LAYER_MASK]   = "Layer mode mask not supported by Landlock",
    [-LANDLOCK_COMPAT_SINGLE_STAR]  = "Single-star suffix (/*) cannot be expressed in Landlock",
    [-LANDLOCK_COMPAT_NULL_RULESET] = "NULL ruleset",
    [-LANDLOCK_COMPAT_COMPILE_FAIL] = "Compilation failed during validation",
};

/* ------------------------------------------------------------------ */
/*  Internal: validate a single compiled rule, return error enum      */
/* ------------------------------------------------------------------ */

static landlock_compat_error_t validate_compiled_rule(const effective_ruleset_t *eff,
                                                       const compiled_rule_t *cr,
                                                       int *error_line)
{
    const char *subject = get_subject(eff, cr);
    if (subject && subject[0] != '\0')
        return LANDLOCK_COMPAT_SUBJECT;

    if (cr->flags & SOFT_RULE_TEMPLATE)
        return LANDLOCK_COMPAT_TEMPLATE;
    
    const char *pattern = get_pattern(eff, cr);
    if (is_single_star_suffix(pattern))
        return LANDLOCK_COMPAT_SINGLE_STAR;
    pattern_class_t pc = soft_pattern_classify(pattern);
    if (pc == PATTERN_WILDCARD)
        return LANDLOCK_COMPAT_WILDCARD;
    (void)error_line;  /* caller sets the rule index */
    return LANDLOCK_COMPAT_OK;
}

/**
 * Check a single descriptive rule for Landlock compatibility.
 * Returns LANDLOCK_COMPAT_OK if compatible, or a negative error code.
 */
static landlock_compat_error_t validate_descriptive_rule(const rule_t *r,
                                                          int *error_line)
{
    if (r->subject_regex[0] != '\0')
        return LANDLOCK_COMPAT_SUBJECT;

    if (r->linked_path_var[0] != '\0')
        return LANDLOCK_COMPAT_TEMPLATE;
    if (is_single_star_suffix(r->pattern))
        return LANDLOCK_COMPAT_SINGLE_STAR;
    pattern_class_t pc = soft_pattern_classify(r->pattern);
    if (pc == PATTERN_WILDCARD)
        return LANDLOCK_COMPAT_WILDCARD;
    (void)error_line;
    return LANDLOCK_COMPAT_OK;
}

landlock_compat_error_t soft_ruleset_validate_for_landlock_ex(
        const soft_ruleset_t *rs, int *error_line)
{
    if (!rs) {
        if (error_line) *error_line = 0;
        return LANDLOCK_COMPAT_NULL_RULESET;
    }

    /* If compiled, check the effective ruleset */
    if (rs->is_compiled) {
        const effective_ruleset_t *eff = &rs->effective;
        int idx = 0;

        /* SPECIFICITY rules have different semantics (longest-match-wins) */
        if (eff->spec_static_count > 0 || eff->spec_dynamic_count > 0) {
            if (error_line) *error_line = 0;
            return LANDLOCK_COMPAT_SPECIFICITY;
        }

        /* Check static rules */
        for (int i = 0; i < eff->static_count; i++) {
            landlock_compat_error_t e = validate_compiled_rule(eff, &eff->static_rules[i], error_line);
            if (e != LANDLOCK_COMPAT_OK) { if (error_line) *error_line = idx; return e; }
            idx++;
        }

        /* Check dynamic rules */
        for (int i = 0; i < eff->dynamic_count; i++) {
            landlock_compat_error_t e = validate_compiled_rule(eff, &eff->dynamic_rules[i], error_line);
            if (e != LANDLOCK_COMPAT_OK) { if (error_line) *error_line = idx; return e; }
            idx++;
        }

        /* Check SPECIFICITY static rules (already rejected above, but check for completeness) */
        for (int i = 0; i < eff->spec_static_count; i++) {
            landlock_compat_error_t e = validate_compiled_rule(eff, &eff->spec_static_rules[i], error_line);
            if (e != LANDLOCK_COMPAT_OK) { if (error_line) *error_line = idx; return e; }
            idx++;
        }

        /* Check SPECIFICITY dynamic rules */
        for (int i = 0; i < eff->spec_dynamic_count; i++) {
            landlock_compat_error_t e = validate_compiled_rule(eff, &eff->spec_dynamic_rules[i], error_line);
            if (e != LANDLOCK_COMPAT_OK) { if (error_line) *error_line = idx; return e; }
            idx++;
        }

        return LANDLOCK_COMPAT_OK;
    }

    /* Not compiled: check descriptive layers */
    int rule_idx = 0;
    for (int l = 0; l < rs->layer_count; l++) {
        const layer_t *lyr = &rs->layers[l];

        /* Layer masks cannot be expressed in Landlock */
        if (lyr->mask != 0) {
            if (error_line) *error_line = rule_idx;
            return LANDLOCK_COMPAT_LAYER_MASK;
        }

        /* SPECIFICITY layer semantics differ from Landlock's flat model */
        if (lyr->type == LAYER_SPECIFICITY && lyr->count > 0) {
            if (error_line) *error_line = rule_idx;
            return LANDLOCK_COMPAT_SPECIFICITY;
        }

        for (int r = 0; r < lyr->count; r++) {
            landlock_compat_error_t e = validate_descriptive_rule(&lyr->rules[r], error_line);
            if (e != LANDLOCK_COMPAT_OK) {
                if (error_line) *error_line = rule_idx;
                return e;
            }
            rule_idx++;
        }
    }

    return LANDLOCK_COMPAT_OK;
}

int soft_ruleset_validate_for_landlock(const soft_ruleset_t *rs,
                                       landlock_compat_error_t *error_code,
                                       const char **error_msg,
                                       int *error_line)
{
    landlock_compat_error_t e = soft_ruleset_validate_for_landlock_ex(rs, error_line);
    if (error_code) *error_code = e;
    if (error_msg) {
        if (e == LANDLOCK_COMPAT_OK) {
            *error_msg = NULL;
        } else {
            int idx = -e;
            *error_msg = (idx >= 0 && idx < (int)(sizeof(landlock_compat_error_msgs) / sizeof(landlock_compat_error_msgs[0])))
                         ? landlock_compat_error_msgs[idx]
                         : "Unknown Landlock incompatibility";
        }
    }
    return (e == LANDLOCK_COMPAT_OK) ? 0 : -1;
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
            const char *subject = get_subject(eff, cr);
            if ((subject && subject[0] != '\0') ||

                (cr->flags & SOFT_RULE_TEMPLATE)) {
                continue;  /* skip inexpressible rules */
            }

            /* Classify pattern */
            const char *pattern = get_pattern(eff, cr);
            if (!pattern || !*pattern) {
                continue;  /* skip empty/null patterns */
            }
            pattern_class_t pc = soft_pattern_classify(pattern);
            if (pc == PATTERN_WILDCARD) {
                continue;  /* skip mid-path wildcards */
            }

            /* Convert pattern to Landlock-compatible prefix */
            const char *prefix = pattern_to_prefix(pattern);
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

/* ------------------------------------------------------------------ */
/*  Validation report (collects ALL errors)                           */
/* ------------------------------------------------------------------ */

int soft_ruleset_validate_for_landlock_report(
        const soft_ruleset_t *rs,
        landlock_validation_entry_t report[LANDLOCK_VALIDATION_REPORT_MAX])
{
    if (!rs) return 0;

    int count = 0;

    /* If compiled, check effective ruleset */
    if (rs->is_compiled) {
        const effective_ruleset_t *eff = &rs->effective;
        int idx = 0;

        /* SPECIFICITY rules: reject all at once */
        if (eff->spec_static_count > 0 || eff->spec_dynamic_count > 0) {
            if (count < LANDLOCK_VALIDATION_REPORT_MAX) {
                report[count].error = LANDLOCK_COMPAT_SPECIFICITY;
                report[count].line = 0;
            }
            count++;
        }

        /* Check all four compiled rule arrays */
        const compiled_rule_t *all_rules[4];
        int all_counts[4];
        all_rules[0] = eff->static_rules;     all_counts[0] = eff->static_count;
        all_rules[1] = eff->dynamic_rules;    all_counts[1] = eff->dynamic_count;
        all_rules[2] = eff->spec_static_rules; all_counts[2] = eff->spec_static_count;
        all_rules[3] = eff->spec_dynamic_rules; all_counts[3] = eff->spec_dynamic_count;

        for (int arr = 0; arr < 4; arr++) {
            for (int i = 0; i < all_counts[arr]; i++) {
                landlock_compat_error_t e = validate_compiled_rule(eff, &all_rules[arr][i], NULL);
                if (e != LANDLOCK_COMPAT_OK) {
                    if (count < LANDLOCK_VALIDATION_REPORT_MAX) {
                        report[count].error = e;
                        report[count].line = idx;
                    }
                    count++;
                }
                idx++;
            }
        }

        return count;
    }

    /* Not compiled: check descriptive layers */
    int rule_idx = 0;
    for (int l = 0; l < rs->layer_count; l++) {
        const layer_t *lyr = &rs->layers[l];

        if (lyr->mask != 0) {
            if (count < LANDLOCK_VALIDATION_REPORT_MAX) {
                report[count].error = LANDLOCK_COMPAT_LAYER_MASK;
                report[count].line = rule_idx;
            }
            count++;
        }

        if (lyr->type == LAYER_SPECIFICITY && lyr->count > 0) {
            if (count < LANDLOCK_VALIDATION_REPORT_MAX) {
                report[count].error = LANDLOCK_COMPAT_SPECIFICITY;
                report[count].line = rule_idx;
            }
            count++;
        }

        for (int r = 0; r < lyr->count; r++) {
            landlock_compat_error_t e = validate_descriptive_rule(&lyr->rules[r], NULL);
            if (e != LANDLOCK_COMPAT_OK) {
                if (count < LANDLOCK_VALIDATION_REPORT_MAX) {
                    report[count].error = e;
                    report[count].line = rule_idx;
                }
                count++;
            }
            rule_idx++;
        }
    }

    return count;
}

/* ------------------------------------------------------------------ */
/*  Translation with report                                           */
/* ------------------------------------------------------------------ */

landlock_builder_t *soft_ruleset_to_landlock_with_report(
        const soft_ruleset_t *rs,
        const char ***deny_prefixes_out,
        landlock_translation_report_t *report)
{
    if (!rs) return NULL;

    /* Compile if not already compiled */
    soft_ruleset_t *mutable_rs = (soft_ruleset_t *)rs;
    if (!rs->is_compiled) {
        if (soft_ruleset_compile(mutable_rs) != 0)
            return NULL;
    }

    /* Initialize report */
    landlock_translation_report_t rep;
    memset(&rep, 0, sizeof(rep));

    const effective_ruleset_t *eff = &rs->effective;
    rep.total_rules = eff->static_count + eff->dynamic_count +
                      eff->spec_static_count + eff->spec_dynamic_count;

    landlock_builder_t *b = landlock_builder_new();
    if (!b) return NULL;

    /* Collect deny prefixes */
    const char **deny_prefixes = NULL;
    int deny_cap = 0;
    int deny_idx = 0;

    /* Process all compiled rule arrays */
    const compiled_rule_t *all_rules[4];
    int all_counts[4];
    all_rules[0] = eff->static_rules;     all_counts[0] = eff->static_count;
    all_rules[1] = eff->dynamic_rules;    all_counts[1] = eff->dynamic_count;
    all_rules[2] = eff->spec_static_rules; all_counts[2] = eff->spec_static_count;
    all_rules[3] = eff->spec_dynamic_rules; all_counts[3] = eff->spec_dynamic_count;

    for (int arr = 0; arr < 4; arr++) {
        for (int i = 0; i < all_counts[arr]; i++) {
            const compiled_rule_t *cr = &all_rules[arr][i];

            /* Track skip reasons */
            const char *subject = get_subject(eff, cr);
            if (subject && subject[0] != '\0') {
                rep.skipped_rules++; rep.skipped_subject++; continue;
            }

            if (cr->flags & SOFT_RULE_TEMPLATE) {
                rep.skipped_rules++; rep.skipped_template++; continue;
            }

            /* Classify pattern */
            const char *pattern = get_pattern(eff, cr);
            if (!pattern || !*pattern) {
                rep.skipped_rules++; continue;  /* skip empty/null patterns */
            }
            pattern_class_t pc = soft_pattern_classify(pattern);
            if (pc == PATTERN_WILDCARD) {
                rep.skipped_rules++; rep.skipped_wildcard++; continue;
            }

            /* Convert pattern to Landlock-compatible prefix */
            const char *prefix = pattern_to_prefix(pattern);
            if (!prefix || !*prefix) continue;

            /* Check if this is a deny rule */
            if ((cr->mode & SOFT_ACCESS_DENY) || soft_access_to_ll_fs(cr->mode) == 0) {
                landlock_builder_deny(b, prefix);
                rep.denied_rules++;

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
            rep.allowed_rules++;
        }
    }

    /* Finalize deny prefix array */
    if (deny_prefixes) {
        deny_prefixes[deny_idx] = NULL;
        rep.deny_prefixes = deny_idx;
    }

    if (deny_prefixes_out) {
        *deny_prefixes_out = deny_prefixes;
    } else {
        soft_landlock_deny_prefixes_free(deny_prefixes);
    }

    if (report) *report = rep;
    return b;
}

/* ------------------------------------------------------------------ */
/*  Convenience: validate → translate → save in one call              */
/* ------------------------------------------------------------------ */

int soft_ruleset_save_landlock_policy(const soft_ruleset_t *rs,
                                      const char *filename,
                                      int abi_version,
                                      const char **error_msg,
                                      landlock_compat_error_t *error_code)
{
    if (!rs || !filename) return -1;

    /* Step 1: Validate */
    landlock_compat_error_t e = soft_ruleset_validate_for_landlock_ex(rs, NULL);
    if (error_code) *error_code = e;
    if (e != LANDLOCK_COMPAT_OK) {
        if (error_msg) {
            int idx = -e;
            *error_msg = (idx >= 0 && idx < (int)(sizeof(landlock_compat_error_msgs) / sizeof(landlock_compat_error_msgs[0])))
                         ? landlock_compat_error_msgs[idx]
                         : "Unknown Landlock incompatibility";
        }
        return -1;
    }

    /* Step 2: Translate */
    landlock_builder_t *b = soft_ruleset_to_landlock(rs, NULL);
    if (!b) {
        if (error_msg) *error_msg = "Translation to Landlock failed";
        if (error_code) *error_code = LANDLOCK_COMPAT_COMPILE_FAIL;
        return -1;
    }

    /* Step 3: Prepare for ABI version */
    if (landlock_builder_prepare(b, abi_version, false) != 0) {
        landlock_builder_free(b);
        if (error_msg) *error_msg = "Landlock prepare failed";
        if (error_code) *error_code = LANDLOCK_COMPAT_COMPILE_FAIL;
        return -1;
    }

    /* Step 4: Save to file */
    int ret = landlock_builder_save(b, filename);
    landlock_builder_free(b);

    if (ret != 0) {
        if (error_msg) *error_msg = "Failed to save Landlock policy";
        if (error_code) *error_code = LANDLOCK_COMPAT_COMPILE_FAIL;
        return -1;
    }

    if (error_msg) *error_msg = NULL;
    return 0;
}

/* Helper function implementations */
static inline const char *get_pattern(const effective_ruleset_t *eff, const compiled_rule_t *r)
{
    if (r->pattern_offset == UINT32_MAX) return NULL;
    return eff->strings.buf + r->pattern_offset;
}

static inline const char *get_subject(const effective_ruleset_t *eff, const compiled_rule_t *r)
{
    if (r->subject_offset == UINT32_MAX) return NULL;
    return eff->strings.buf + r->subject_offset;
}
