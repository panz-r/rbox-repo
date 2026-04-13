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
/*  Per-rule Landlock compatibility pre-check                           */
/* ------------------------------------------------------------------ */

/**
 * Check if a single rule can be expressed in Landlock.
 *
 * This is useful for interactive policy building: reject a rule before
 * inserting it into the ruleset, rather than validating the entire
 * ruleset after each insertion.
 *
 * Incompatible conditions:
 *   - Subject constraint (subject_regex non-NULL and non-empty)
 *   - UID constraint (min_uid > 0)
 *   - Template variable (linked_path_var non-NULL and non-empty)
 *   - Mid-path wildcard (* not at suffix /** or ...)
 *   - Single-star suffix (/*) — over-permissive, not expressible
 *
 * @param pattern        Path pattern string.
 * @param subject_regex  Subject regex constraint (NULL or "" = none).
 * @param min_uid        Minimum UID (0 = any).
 * @param linked_path_var Template variable ("SRC", "DST", or NULL/"" = none).
 * @param error_msg      If non-NULL and incompatible, receives a static
 *                       error string describing the issue.
 * @return 0 if compatible with Landlock, -1 if not.
 */
int soft_rule_is_landlock_compatible(const char *pattern,
                                     const char *subject_regex,
                                     uint32_t min_uid,
                                     const char *linked_path_var,
                                     const char **error_msg);

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
 * Structured error codes for Landlock compatibility validation.
 *
 * Each value identifies a specific reason why a ruleset cannot be
 * translated to Landlock.  Callers can use these codes to produce
 * user-friendly error messages or to automatically fix the policy.
 */
typedef enum {
    LANDLOCK_COMPAT_OK            =  0,  /**< Compatible with Landlock. */
    LANDLOCK_COMPAT_SUBJECT       = -1,  /**< Rule has subject_regex constraint. */
    LANDLOCK_COMPAT_UID           = -2,  /**< Rule has min_uid > 0 constraint. */
    LANDLOCK_COMPAT_TEMPLATE      = -3,  /**< Rule uses ${SRC}/${DST} template. */
    LANDLOCK_COMPAT_WILDCARD      = -4,  /**< Pattern has mid-path * wildcard. */
    LANDLOCK_COMPAT_SPECIFICITY   = -5,  /**< Layer uses SPECIFICITY type. */
    LANDLOCK_COMPAT_LAYER_MASK    = -6,  /**< Layer has a mode mask (e.g. PRECEDENCE:RW). */
    LANDLOCK_COMPAT_SINGLE_STAR   = -7,  /**< Pattern ends with /* (single-star suffix). */
    LANDLOCK_COMPAT_NULL_RULESET  = -8,  /**< NULL ruleset passed. */
    LANDLOCK_COMPAT_COMPILE_FAIL  = -9,  /**< Compilation failed during validation. */
} landlock_compat_error_t;

/**
 * Human-readable description for each landlock_compat_error_t value.
 * Indexed by negating the enum value (e.g. [-LANDLOCK_COMPAT_SUBJECT]).
 */
extern const char *const landlock_compat_error_msgs[];

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
 * @param error_code  If non-NULL, receives a landlock_compat_error_t value
 *                    (LANDLOCK_COMPAT_OK on success, negative on failure).
 * @param error_msg   If non-NULL and the ruleset is incompatible,
 *                    receives a static string describing the FIRST issue.
 * @param error_line  If non-NULL, receives the approximate rule index
 *                    that caused the FIRST incompatibility.
 * @return 0 if the ruleset can be translated, -1 if not.
 *
 * @see soft_ruleset_validate_for_landlock_ex() for the enum-returning variant.
 * @see soft_ruleset_validate_for_landlock_report() for a full error report.
 */
int soft_ruleset_validate_for_landlock(const soft_ruleset_t *rs,
                                       landlock_compat_error_t *error_code,
                                       const char **error_msg,
                                       int *error_line);

/**
 * Extended validation that returns a structured error code.
 *
 * This is the preferred API for new code.  The legacy
 * soft_ruleset_validate_for_landlock() is a thin wrapper around this.
 *
 * @param rs          Ruleset handle (compiled or uncompiled).
 * @param error_line  If non-NULL, receives the approximate rule index
 *                    that caused the incompatibility.
 * @return LANDLOCK_COMPAT_OK on success, or a negative error code.
 */
landlock_compat_error_t soft_ruleset_validate_for_landlock_ex(
        const soft_ruleset_t *rs, int *error_line);

/* ------------------------------------------------------------------ */
/*  Validation report (collects ALL errors, not just first)            */
/* ------------------------------------------------------------------ */

/** Maximum number of validation errors collected in a single report. */
#define LANDLOCK_VALIDATION_REPORT_MAX 32

/**
 * A single entry in a validation report.
 */
typedef struct {
    landlock_compat_error_t error;   /**< Error code. */
    int                     line;    /**< Rule index (0-based). */
} landlock_validation_entry_t;

/**
 * Full validation report collecting ALL incompatibilities.
 *
 * Unlike soft_ruleset_validate_for_landlock() which stops at the first
 * error, this function scans the entire ruleset and records every
 * rule that cannot be translated to Landlock.
 *
 * @param rs       Ruleset handle (compiled or uncompiled).
 * @param report   Caller-allocated array of at least LANDLOCK_VALIDATION_REPORT_MAX entries.
 * @return Number of entries written to report (0 if fully compatible).
 */
int soft_ruleset_validate_for_landlock_report(
        const soft_ruleset_t *rs,
        landlock_validation_entry_t report[LANDLOCK_VALIDATION_REPORT_MAX]);

/* ------------------------------------------------------------------ */
/*  Translation report                                                */
/* ------------------------------------------------------------------ */

/**
 * Statistics returned by soft_ruleset_to_landlock_with_report().
 */
typedef struct {
    int total_rules;          /**< Total rules in source ruleset. */
    int allowed_rules;        /**< Rules translated to Landlock allow. */
    int denied_rules;         /**< Rules translated to Landlock deny. */
    int skipped_rules;        /**< Rules skipped (inexpressible in Landlock). */
    int skipped_subject;      /**< Skipped due to subject constraint. */
    int skipped_uid;          /**< Skipped due to UID constraint. */
    int skipped_template;     /**< Skipped due to template. */
    int skipped_wildcard;     /**< Skipped due to wildcard pattern. */
    int deny_prefixes;        /**< Number of deny path prefixes reported. */
} landlock_translation_report_t;

/**
 * Translate a ruleset to Landlock with a detailed report.
 *
 * Like soft_ruleset_to_landlock() but also populates a report
 * with counts of allowed, denied, and skipped rules broken down
 * by skip reason.
 *
 * @param rs            Ruleset handle (must be compiled).
 * @param deny_prefixes If non-NULL, receives deny prefix array.
 * @param report        If non-NULL, receives translation statistics.
 * @return Landlock builder, or NULL on failure.
 */
landlock_builder_t *soft_ruleset_to_landlock_with_report(
        const soft_ruleset_t *rs,
        const char ***deny_prefixes,
        landlock_translation_report_t *report);

/* ------------------------------------------------------------------ */
/*  Convenience: validate → translate → save in one call              */
/* ------------------------------------------------------------------ */

/**
 * Validate, translate, and save a ruleset as a Landlock binary policy.
 *
 * This is the recommended high-level API for the Landlock workflow:
 *   1. Validates the ruleset (returns error if incompatible)
 *   2. Translates to Landlock
 *   3. Prepares for the given ABI version
 *   4. Saves the binary policy to the specified file
 *
 * @param rs           Ruleset handle (compiled or uncompiled).
 * @param filename     Output file path for the Landlock binary policy.
 * @param abi_version  Target Landlock ABI version (1..LANDLOCK_ABI_MAX).
 * @param error_msg    If non-NULL and validation fails, receives error string.
 * @param error_code   If non-NULL, receives validation error code.
 * @return 0 on success, -1 on validation or translation failure.
 */
int soft_ruleset_save_landlock_policy(const soft_ruleset_t *rs,
                                      const char *filename,
                                      int abi_version,
                                      const char **error_msg,
                                      landlock_compat_error_t *error_code);

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
