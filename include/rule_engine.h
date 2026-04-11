/**
 * @file rule_engine.h
 * @brief ReadOnlyBox Rule Engine public API (spec v3.0).
 *
 * Supports binary operations (COPY, MOVE, LINK, MOUNT, etc.), path
 * variables (${SRC}, ${DST}), layered rulesets with precedence,
 * subject constraints, and batched dual-path evaluation.
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
#define SOFT_ACCESS_ALL     (SOFT_ACCESS_READ | SOFT_ACCESS_WRITE | \
                             SOFT_ACCESS_EXEC | SOFT_ACCESS_CREATE | \
                             SOFT_ACCESS_UNLINK | SOFT_ACCESS_LINK | \
                             SOFT_ACCESS_MKDIR | SOFT_ACCESS_LINK_SRC | \
                             SOFT_ACCESS_MOUNT_SRC)

/* ------------------------------------------------------------------ */
/*  Rule flags                                                         */
/* ------------------------------------------------------------------ */

#define SOFT_RULE_RECURSIVE  (1U << 0)
#define SOFT_RULE_STRICT     (1U << 1)
#define SOFT_RULE_TEMPLATE   (1U << 2)  /* Contains ${SRC} or ${DST} */

/* ------------------------------------------------------------------ */
/*  Layer type                                                         */
/* ------------------------------------------------------------------ */

/**
 * How a layer combines with other layers.
 *   LAYER_PRECEDENCE (default): DENY shadows lower, mode intersection.
 *   LAYER_SPECIFICITY: Longest-match wins, overrides PRECEDENCE.
 */
typedef enum {
    LAYER_PRECEDENCE,
    LAYER_SPECIFICITY,
} layer_type_t;

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
    int         deny_layer;     /**< Layer index that caused denial (-1 if allowed) */
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

/**
 * Return the number of rules across all layers.
 */
size_t soft_ruleset_rule_count(const soft_ruleset_t *rs);

/**
 * Return the number of layers currently in the ruleset.
 */
int soft_ruleset_layer_count(const soft_ruleset_t *rs);

/* ------------------------------------------------------------------ */
/*  Compilation / simplification                                       */
/* ------------------------------------------------------------------ */

/**
 * Compile the descriptive layered ruleset into a single simplified
 * effective ruleset.
 *
 * Simplification steps:
 *   1. Cross-layer shadow elimination: rules in lower layers that are
 *      covered by DENY rules in higher layers are removed.
 *   2. Mode intersection: identical patterns across layers are merged
 *      with their modes ANDed together.
 *   3. Subsumption: rules covered by more general rules with the same
 *      effective mode are removed.
 *   4. Sort: DENY rules placed first for fast short-circuit.
 *
 * After compilation, soft_ruleset_check_ctx and
 * soft_ruleset_check_batch_ctx use the simplified effective ruleset
 * for faster single-pass evaluation.
 *
 * Any subsequent call to soft_ruleset_add_rule*() invalidates the
 * compiled state, falling back to layered evaluation until the next
 * compile() call.
 *
 * @param rs Ruleset handle.
 * @return 0 on success, -1 on failure.
 */
int soft_ruleset_compile(soft_ruleset_t *rs);

/**
 * Check if the ruleset has a valid compiled effective ruleset.
 */
bool soft_ruleset_is_compiled(const soft_ruleset_t *rs);

/* ------------------------------------------------------------------ */
/*  Rule insertion                                                      */
/* ------------------------------------------------------------------ */

/**
 * Add a rule to the ruleset (default layer 0).
 *
 * @param rs              Ruleset handle.
 * @param pattern         Path pattern (may contain ${SRC}, ${DST}, or
 *                        "..." for recursive wildcards).
 * @param mode            Access mode (SOFT_ACCESS_READ, etc., or
 *                        SOFT_ACCESS_DENY).
 * @param op_type         Operation this rule applies to.
 * @param linked_path_var If non-NULL and non-empty, the path variable
 *                        this rule references for template resolution.
 *                        Only valid with patterns containing ${SRC} or
 *                        ${DST}; rejected with EINVAL otherwise.
 * @param subject_regex   Optional regex to match the calling binary.
 *                        NULL or "" matches any subject.
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

/**
 * Add a rule to a specific layer in the ruleset.
 *
 * Layer 0 has the highest precedence. Rules in layer N are only
 * consulted if all layers 0..N-1 did not produce a DENY. The final
 * allowed mode is the bitwise AND of all matching rules across
 * all non-denying layers.
 *
 * @param rs              Ruleset handle.
 * @param layer           Layer index (0 = highest precedence).
 * @param pattern         Path pattern.
 * @param mode            Access mode.
 * @param op_type         Operation type.
 * @param linked_path_var Linked path variable ("SRC", "DST", or NULL).
 * @param subject_regex   Subject regex constraint (NULL = any).
 * @param min_uid         Minimum UID (0 = any).
 * @param flags           Rule flags.
 * @return 0 on success, -1 on failure.
 */
int soft_ruleset_add_rule_at_layer(soft_ruleset_t *rs,
                                   int layer,
                                   const char *pattern,
                                   uint32_t mode,
                                   soft_binary_op_t op_type,
                                   const char *linked_path_var,
                                   const char *subject_regex,
                                   uint32_t min_uid,
                                   uint32_t flags);

/* ------------------------------------------------------------------ */
/*  Custom operation mode registration                                 */
/* ------------------------------------------------------------------ */

/**
 * Set the type and mode mask for a specific layer.
 *
 * @param rs    Ruleset handle.
 * @param layer Layer index.
 * @param type  Layer type: LAYER_PRECEDENCE (default) or LAYER_SPECIFICITY.
 *              SPECIFICITY layers use longest-match semantics: the most
 *              specific rule overrides PRECEDENCE layers.
 * @param mask  Bitmask of SOFT_ACCESS_* modes this layer applies.
 *              0 means "all modes" (default, backward compatible).
 * @return 0 on success, -1 on invalid index.
 */
int soft_ruleset_set_layer_type(soft_ruleset_t *rs,
                                int layer,
                                layer_type_t type,
                                uint32_t mask);

/**
 * Register required SRC and DST modes for a SOFT_OP_CUSTOM operation.
 *
 * By default, SOFT_OP_CUSTOM requires READ for SRC and WRITE for DST.
 * Call this to override those defaults for a specific custom operation
 * index (custom_op_index must be >= SOFT_OP_CUSTOM).
 *
 * @param rs               Ruleset handle.
 * @param custom_op_index  The custom operation index to configure.
 * @param required_src     Required mode bits for SRC path.
 * @param required_dst     Required mode bits for DST path.
 * @return 0 on success, -1 on invalid index.
 */
int soft_ruleset_set_custom_op_modes(soft_ruleset_t *rs,
                                     int custom_op_index,
                                     uint32_t required_src,
                                     uint32_t required_dst);

/* ------------------------------------------------------------------ */
/*  Expression parser                                                  */
/* ------------------------------------------------------------------ */

/**
 * Parse and add a rule from an expression string.
 *
 * Format:  [@layer:]op:subject:src_pattern:dst_pattern -> mode
 *
 * Examples:
 *   "cp::/etc/\\*:/tmp/ -> RW"
 *   "@1:cp:/usr/bin/cp:${SRC}:${DST} -> RO"
 *   "mount::/dev/sd*:/mnt/usb -> RWX"
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
 * Layers are evaluated from 0 (highest precedence) downward:
 *   1. If any layer produces DENY, return DENY immediately.
 *   2. Otherwise, the granted mode is the bitwise AND of all layers.
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
 * Within each layer, static (non-template) rules are evaluated before
 * template rules, so a static DENY for /etc/shadow will shadow a
 * template ${SRC}: RO rule.
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
 * Uses a parent-directory cache to avoid re-evaluating the same
 * directory rules thousands of times. If 100 files are copied from
 * /a to /b, the rules for /a and /b are evaluated once and reused
 * for all children.
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

/* ------------------------------------------------------------------ */
/*  Binary serialization of compiled ruleset                            */
/* ------------------------------------------------------------------ */

/**
 * Serialize the compiled effective ruleset to a binary buffer.
 *
 * The output can be loaded back with soft_ruleset_load_compiled()
 * to skip recompilation from text.  Only valid after compile().
 *
 * @param rs       Ruleset handle (must be compiled).
 * @param out_buf  Rece pointer to allocated buffer (caller must free).
 * @param out_len  Receives buffer size in bytes.
 * @return 0 on success, -1 on failure (errno set).
 */
int soft_ruleset_save_compiled(const soft_ruleset_t *rs,
                               void **out_buf,
                               size_t *out_len);

/**
 * Load a previously serialized compiled ruleset.
 *
 * Bypasses text parsing and compilation.  The loaded ruleset
 * behaves as if compile() had been called.
 *
 * @param buf   Binary buffer from soft_ruleset_save_compiled().
 * @param len   Buffer size in bytes.
 * @return New ruleset handle, or NULL on failure (errno set).
 */
soft_ruleset_t *soft_ruleset_load_compiled(const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* RULE_ENGINE_H */
