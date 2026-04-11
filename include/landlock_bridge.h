/**
 * @file landlock_bridge.h
 * @brief Bridge between the Rule Engine text-policy format and Landlock BPF.
 *
 * Provides translation from `soft_ruleset_t` (text-policy parsed ruleset)
 * to `landlock_builder_t` (Landlock BPF policy), with validation that
 * detects rules which cannot be expressed in Landlock.
 */

#ifndef LANDLOCK_BRIDGE_H
#define LANDLOCK_BRIDGE_H

#include "rule_engine.h"
#include "landlock_builder.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Access flag mapping                                                 */
/* ------------------------------------------------------------------ */

/**
 * Translate a SOFT_ACCESS_* bitmask to a LL_FS_* bitmask.
 *
 * Mapping:
 *   SOFT_ACCESS_READ   → LL_FS_READ_FILE | LL_FS_READ_DIR
 *   SOFT_ACCESS_WRITE  → LL_FS_WRITE_FILE
 *   SOFT_ACCESS_EXEC   → LL_FS_EXECUTE
 *   SOFT_ACCESS_CREATE → LL_FS_WRITE_FILE
 *   SOFT_ACCESS_UNLINK → LL_FS_REMOVE_FILE
 *   SOFT_ACCESS_DENY   → (deny rule, not a mask)
 *
 * @param soft_mask  SOFT_ACCESS_* bitmask.
 * @return           LL_FS_* bitmask.
 */
uint64_t soft_access_to_ll_fs(uint32_t soft_mask);

/* ------------------------------------------------------------------ */
/*  Landlock compatibility validation                                 */
/* ------------------------------------------------------------------ */

/**
 * Check whether a ruleset can be faithfully translated to Landlock.
 *
 * Landlock cannot express:
 *   - Subject constraints (subject_regex)
 *   - UID constraints (min_uid > 0)
 *   - Binary operations with distinct SRC/DST patterns (COPY, MOVE, etc.)
 *   - Non-prefix wildcards (`*` in the middle of a path)
 *   - Layer masks (SPECIFICITY:R, PRECEDENCE:RW)
 *
 * @param rs          Ruleset handle (compiled or uncompiled).
 * @param error_msg   If non-NULL and the ruleset is incompatible,
 *                    receives a static string describing the issue.
 * @param error_line  If non-NULL, receives the approximate rule index
 *                    that caused the incompatibility.
 * @return 0 if the ruleset can be translated, -1 if not.
 */
int soft_ruleset_validate_for_landlock(const soft_ruleset_t *rs,
                                       const char **error_msg,
                                       int *error_line);

/* ------------------------------------------------------------------ */
/*  Translation                                                       */
/* ------------------------------------------------------------------ */

/**
 * Translate a rule engine ruleset to a Landlock builder.
 *
 * The caller must call landlock_builder_prepare() on the returned builder
 * before calling landlock_builder_get_rules().
 *
 * @param rs            Ruleset handle (must be compiled via soft_ruleset_compile).
 * @param deny_prefixes If non-NULL, receives an array of path prefixes
 *                      that were DENY-only and cannot be expressed as
 *                      Landlock allow rules. The array is NULL-terminated
 *                      and owned by the caller (must be freed).
 * @return New landlock_builder_t handle, or NULL on failure.
 *         The caller must call landlock_builder_free() when done.
 */
landlock_builder_t *soft_ruleset_to_landlock(const soft_ruleset_t *rs,
                                             const char ***deny_prefixes);

/**
 * Free an array of deny prefix strings returned by soft_ruleset_to_landlock.
 * @param prefixes  NULL-terminated array of strings, or NULL.
 */
void soft_landlock_deny_prefixes_free(const char **prefixes);

/* ------------------------------------------------------------------ */
/*  Pattern expansion helpers                                         */
/* ------------------------------------------------------------------ */

/**
 * Determine how a rule engine pattern maps to Landlock semantics.
 *
 * Pattern types:
 *   PATTERN_EXACT    - exact path match, no wildcards
 *   PATTERN_PREFIX   - ends with ** or ... suffix, matches prefix
 *   PATTERN_WILDCARD - contains * in the middle (cannot be prefix-matched)
 *
 * @param pattern  Rule engine pattern string.
 * @return         Pattern classification.
 */
typedef enum {
    PATTERN_EXACT,
    PATTERN_PREFIX,
    PATTERN_WILDCARD,
} pattern_class_t;

pattern_class_t soft_pattern_classify(const char *pattern);

#ifdef __cplusplus
}
#endif

#endif /* LANDLOCK_BRIDGE_H */
