/**
 * @file rule_engine.h
 * @brief ReadOnlyBox Rule Engine public API (spec v3.0).
 *
 * Supports binary operations (COPY, MOVE, LINK, MOUNT, etc.), path
 * variables (${SRC}, ${DST}), subject constraints, and batched
 * dual-path evaluation.
 */

#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Operation types                                                    */
/* ------------------------------------------------------------------ */

/** Binary / unary operation types for access transactions. */
typedef enum {
    SOFT_OP_READ,           /**< Single path (fallback) */
    SOFT_OP_WRITE,          /**< Single path (fallback) */
    SOFT_OP_EXEC,           /**< Single path (fallback) */
    SOFT_OP_COPY,           /**< Requires SRC (Read) and DST (Write/Create) */
    SOFT_OP_MOVE,           /**< Requires SRC (Write/Unlink) and DST (Write/Create) */
    SOFT_OP_LINK,           /**< Requires SRC (Read/Link) and DST (Write/Create) */
    SOFT_OP_MOUNT,          /**< Requires SRC (Read) and DST (Mount point) */
    SOFT_OP_CHMOD_CHOWN,    /**< Requires Target (Write) */
    SOFT_OP_CUSTOM          /**< User-defined operation */
} soft_binary_op_t;

/* ------------------------------------------------------------------ */
/*  Access flags                                                       */
/* ------------------------------------------------------------------ */

#define SOFT_ACCESS_READ    (1U << 0)
#define SOFT_ACCESS_WRITE   (1U << 1)
#define SOFT_ACCESS_EXEC    (1U << 2)
#define SOFT_ACCESS_CREATE  (1U << 3)
#define SOFT_ACCESS_UNLINK  (1U << 4)
#define SOFT_ACCESS_LINK    (1U << 5)
#define SOFT_ACCESS_MKDIR   (1U << 6)
#define SOFT_ACCESS_LINK_SRC 0x1000  /**< Read source to create a link */
#define SOFT_ACCESS_MOUNT_SRC 0x2000 /**< Read source for mounting */
#define SOFT_ACCESS_DENY    (1U << 31)

/* ------------------------------------------------------------------ */
/*  Rule flags                                                         */
/* ------------------------------------------------------------------ */

#define SOFT_RULE_RECURSIVE  (1U << 0)
#define SOFT_RULE_STRICT     (1U << 1)
#define SOFT_RULE_TEMPLATE   (1U << 2)  /* Contains ${SRC} or ${DST} */

/* ------------------------------------------------------------------ */
/*  Access context                                                     */
/* ------------------------------------------------------------------ */

/**
 * Transaction context passed to evaluation functions.
 * For unary operations, dst_path is NULL and op is one of READ/WRITE/EXEC.
 * For binary operations, both src_path and dst_path are set.
 */
typedef struct {
    soft_binary_op_t op;
    const char *src_path;   /**< Source path (NULL for unary ops) */
    const char *dst_path;   /**< Destination path (NULL for unary ops) */
    const char *subject;    /**< Calling binary path (for subject_regex) */
    uid_t       uid;        /**< Caller UID (for min_uid matching) */
} soft_access_ctx_t;

/* ------------------------------------------------------------------ */
/*  Audit log entry                                                    */
/* ------------------------------------------------------------------ */

/**
 * Optional audit log output from check functions.
 * Set to NULL if audit logging is not needed.
 */
typedef struct {
    int         result;         /**< Final decision: SOFT_ACCESS_* or -EACCES */
    const char *deny_reason;    /**< Human-readable deny reason (if denied) */
    const char *matched_rule;   /**< Pattern of the rule that decided the result */
} soft_audit_log_t;

/* ------------------------------------------------------------------ */
/*  Ruleset (opaque)                                                   */
/* ------------------------------------------------------------------ */

typedef struct soft_ruleset soft_ruleset_t;

/* ------------------------------------------------------------------ */
/*  Ruleset management                                                 */
/* ------------------------------------------------------------------ */

/**
 * Create an empty ruleset.
 * @return New ruleset handle, or NULL on failure.
 */
soft_ruleset_t *soft_ruleset_new(void);

/**
 * Free a ruleset and all associated memory.
 * @param rs Ruleset handle (NULL is safe).
 */
void soft_ruleset_free(soft_ruleset_t *rs);

/* ------------------------------------------------------------------ */
/*  Rule insertion (programmatic API)                                  */
/* ------------------------------------------------------------------ */

/**
 * Add a rule to the ruleset programmatically.
 *
 * @param rs              Ruleset handle.
 * @param pattern         Path pattern (may contain ${SRC}, ${DST}, or
 *                        "..." for recursive wildcards).
 * @param mode            Access mode (SOFT_ACCESS_READ, etc., or
 *                        SOFT_ACCESS_DENY).
 * @param op_type         Operation this rule applies to
 *                        (SOFT_OP_COPY, SOFT_OP_READ, etc.).
 *                        Use SOFT_OP_READ for unary rules.
 * @param linked_path_var If non-NULL, the path variable this rule
 *                        references for dual-path evaluation (e.g. "DST"
 *                        means: when matching SRC, also check DST).
 * @param subject_regex   Optional regex to match the calling binary.
 *                        NULL matches any subject.
 * @param min_uid         Minimum UID for this rule to apply (0 = any).
 * @param flags           Rule flags (SOFT_RULE_RECURSIVE, etc.).
 * @return 0 on success, -1 on failure (errno set).
 */
int soft_ruleset_add_rule(soft_ruleset_t *rs,
                          const char *pattern,
                          uint32_t mode,
                          soft_binary_op_t op_type,
                          const char *linked_path_var,
                          const char *subject_regex,
                          uint32_t min_uid,
                          uint32_t flags);

/* ------------------------------------------------------------------ */
/*  Rule insertion (expression parser)                                 */
/* ------------------------------------------------------------------ */

/**
 * Parse and add a rule from an expression string.
 *
 * Format:  op:subject:src_pattern:dst_pattern -> mode
 *
 * Examples:
 *   "cp::/etc/*:/tmp/ -> RW"
 *   "cp:/usr/bin/cp:${SRC}:${DST} -> RO"
 *   "mount::/dev/sd*:/mnt/usb -> RWX"
 *   "read::/home/user/... -> RO"
 *
 * @param rs            Ruleset handle.
 * @param rule_str      Expression string.
 * @param source_file   Optional source file name for error reporting.
 * @return 0 on success, -1 on parse error (errno set, message in
 *         soft_ruleset_error()).
 */
int soft_ruleset_add_rule_str(soft_ruleset_t *rs,
                              const char *rule_str,
                              const char *source_file);

/**
 * Return the last error message from parsing or rule insertion.
 * @param rs Ruleset handle.
 * @return Error string, or NULL if no error.
 */
const char *soft_ruleset_error(const soft_ruleset_t *rs);

/* ------------------------------------------------------------------ */
/*  Evaluation                                                         */
/* ------------------------------------------------------------------ */

/**
 * Evaluate a single access transaction.
 *
 * For unary operations (READ, WRITE, EXEC), ctx->src_path is the
 * target path and ctx->dst_path should be NULL.
 *
 * For binary operations (COPY, MOVE, LINK, MOUNT), both src_path and
 * dst_path are evaluated:
 *   - src_path is checked against rules matching the operation or READ
 *   - dst_path is checked against rules matching the operation or WRITE
 *   - Results are intersected; DENY on either side means DENY overall
 *
 * @param rs        Ruleset handle.
 * @param ctx       Access context (operation, paths, subject, UID).
 * @param out_log   Optional audit log output.
 * @return SOFT_ACCESS_* granted, or -EACCES if denied.
 */
int soft_ruleset_check_ctx(const soft_ruleset_t *rs,
                           const soft_access_ctx_t *ctx,
                           soft_audit_log_t *out_log);

/**
 * Evaluate a batch of access transactions efficiently.
 *
 * Reuses parent-directory evaluation results across transactions.
 * If 100 files are copied from /a to /b, the rules for /a and /b
 * are evaluated once and cached for all children.
 *
 * @param rs        Ruleset handle.
 * @param ctxs      Array of access contexts (count entries).
 * @param results   Output array of results (count entries).
 *                  Each entry is SOFT_ACCESS_* or -EACCES.
 * @param count     Number of transactions.
 * @return 0 on success, -1 on failure (e.g., memory).
 */
int soft_ruleset_check_batch_ctx(const soft_ruleset_t *rs,
                                 const soft_access_ctx_t *ctxs[],
                                 int *results,
                                 int count);

/* ------------------------------------------------------------------ */
/*  Backward compatibility wrapper                                     */
/* ------------------------------------------------------------------ */

/**
 * Legacy unary check wrapper.
 * Equivalent to calling soft_ruleset_check_ctx with a READ operation
 * on the given path.
 *
 * @param rs    Ruleset handle.
 * @param path  Target path.
 * @param mask  Requested access mask (ignored, kept for API compat).
 * @return SOFT_ACCESS_* granted, or -EACCES if denied.
 */
int soft_ruleset_check(const soft_ruleset_t *rs,
                       const char *path,
                       uint32_t mask);

#ifdef __cplusplus
}
#endif

#endif /* RULE_ENGINE_H */
