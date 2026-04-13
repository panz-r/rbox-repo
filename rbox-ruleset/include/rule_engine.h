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
 * Compile with error detail.
 *
 * Like soft_ruleset_compile(), but on failure writes a human-readable
 * description of what went wrong into errbuf.
 *
 * @param rs           Ruleset handle.
 * @param errbuf       Buffer to receive error message, or NULL to discard.
 * @param errbuf_size  Size of errbuf in bytes (ignored if errbuf is NULL).
 * @return 0 on success, -1 on failure (errno set, errbuf filled).
 */
int soft_ruleset_compile_err(soft_ruleset_t *rs,
                             char *errbuf, size_t errbuf_size);

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
 * Parse a compact comma-separated rule list (CLI shorthand syntax).
 *
 * Format:  /path1:rwx,/path2:ro,/path3:rx,...
 *
 * Mode chars (case-insensitive):
 *   r  →  SOFT_ACCESS_READ
 *   w  →  SOFT_ACCESS_WRITE
 *   x  →  SOFT_ACCESS_EXEC
 *   ro →  SOFT_ACCESS_READ (read-only alias)
 *   D  →  SOFT_ACCESS_DENY
 *
 * Path conventions:
 *   Trailing /... or /**  →  SOFT_RULE_RECURSIVE
 *   Trailing /*           →  single-level wildcard
 *   Exact path            →  static rule
 *
 * All rules are added to layer 0 with SOFT_OP_READ operation.
 * For binary operations (COPY/MOVE) use soft_ruleset_add_rule_str().
 *
 * @param rs          Ruleset handle.
 * @param rules_str   Comma-separated rule string (e.g. "/usr:rx,/tmp:rw").
 * @param source_name Optional name for error messages (e.g. "--hard-allow").
 * @return 0 on success, -1 on parse error (errno set, message in
 *         soft_ruleset_error()).
 */
int soft_ruleset_parse_compact_rules(soft_ruleset_t *rs,
                                     const char *rules_str,
                                     const char *source_name);

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
/*  Evaluation statistics                                               */
/* ------------------------------------------------------------------ */

/**
 * Evaluation statistics collected from check_ctx() calls.
 *
 * These counters are NOT thread-safe.  In a multi-threaded syscall
 * intercept, the caller must synchronize access or accept approximate
 * counts.
 */
typedef struct {
    uint64_t cache_hits;     /**< Query cache hits */
    uint64_t cache_misses;   /**< Query cache misses */
    uint64_t eval_calls;     /**< Total soft_ruleset_check_ctx() calls */
} soft_eval_stats_t;

/**
 * Read and optionally reset evaluation statistics.
 *
 * @param rs     Ruleset handle.
 * @param out    Receives current statistics.
 * @param reset  If true, reset all counters to zero after reading.
 */
void soft_ruleset_get_stats(const soft_ruleset_t *rs,
                            soft_eval_stats_t *out,
                            bool reset);

/* ------------------------------------------------------------------ */
/*  Compiled footprint estimate                                       */
/* ------------------------------------------------------------------ */

/**
 * Estimate the memory footprint of the compiled ruleset without
 * actually compiling.
 *
 * Useful for enforcing memory budgets or warning about oversized
 * rulesets before committing to the (potentially expensive) compile.
 *
 * @param rs               Ruleset handle.
 * @param out_rule_bytes   Estimated bytes for compiled rule arrays
 *                         (all 4 buckets combined).  May be NULL.
 * @param out_str_bytes    Estimated bytes for the string arena
 *                         (interned pattern/subject strings). May be NULL.
 * @return 0 on success, -1 if rs is NULL.
 */
int soft_ruleset_estimate_compiled(const soft_ruleset_t *rs,
                                   size_t *out_rule_bytes,
                                   size_t *out_str_bytes);

/* ------------------------------------------------------------------ */
/*  Library version and features                                       */
/* ------------------------------------------------------------------ */

/**
 * Library version string, e.g. "0.2.0".
 */
const char *soft_ruleset_version(void);

/** Feature flags returned by soft_ruleset_features(). */
#define SOFT_FEATURE_LANDLOCK_BRIDGE      (1U << 0)
#define SOFT_FEATURE_BINARY_SERIALIZATION (1U << 1)
#define SOFT_FEATURE_RULE_MELD            (1U << 2)
#define SOFT_FEATURE_RULE_DIFF            (1U << 3)

/**
 * Query which features are compiled into this build.
 *
 * Returns a bitmask of SOFT_FEATURE_* flags.  All features defined
 * above are always present in a standard build.  Stripped-down builds
 * may omit some flags.
 */
uint32_t soft_ruleset_features(void);

/* ------------------------------------------------------------------ */
/*  Rule info (enumeration / inspection)                               */
/* ------------------------------------------------------------------ */

/**
 * Snapshot of a single rule's attributes for inspection.
 * Returned by soft_ruleset_get_rule_info().
 * Strings are borrowed from the ruleset (do not free).
 */
typedef struct {
    const char         *pattern;           /**< Path pattern (borrowed) */
    uint32_t            mode;              /**< SOFT_ACCESS_* or DENY */
    soft_binary_op_t    op_type;           /**< Operation type */
    const char         *linked_path_var;   /**< "SRC", "DST", or NULL */
    const char         *subject_regex;     /**< Subject regex, or NULL */
    uint32_t            min_uid;           /**< Minimum UID */
    uint32_t            flags;             /**< SOFT_RULE_* flags */
    int                 layer;             /**< Layer index */
} soft_rule_info_t;

/**
 * Metadata about a layer.
 */
typedef struct {
    layer_type_t    type;      /**< LAYER_PRECEDENCE or LAYER_SPECIFICITY */
    uint32_t        mask;      /**< Mode filter (0 = all modes) */
    int             count;     /**< Number of rules in this layer */
} soft_layer_info_t;

/**
 * Get information about a rule at a linear index.
 *
 * Rules are indexed linearly across all layers (layer 0 first, then
 * layer 1, etc.).  Use soft_ruleset_rule_count() for the total.
 *
 * @param rs    Ruleset handle.
 * @param index Linear index (0..rule_count-1).
 * @param out   Receives rule info.  Strings are borrowed (do not free).
 * @return 0 on success, -1 on invalid index.
 */
int soft_ruleset_get_rule_info(const soft_ruleset_t *rs, int index,
                               soft_rule_info_t *out);

/**
 * Get metadata about a specific layer.
 *
 * @param rs     Ruleset handle.
 * @param layer  Layer index.
 * @param out    Receives layer info.
 * @return 0 on success, -1 on invalid index.
 */
int soft_ruleset_get_layer_info(const soft_ruleset_t *rs, int layer,
                                soft_layer_info_t *out);

/* ------------------------------------------------------------------ */
/*  Rule removal                                                       */
/* ------------------------------------------------------------------ */

/**
 * Remove a rule matching the given attributes from the specified layer.
 *
 * Searches for the first rule in the layer that matches pattern, mode,
 * and op_type exactly.  If multiple identical rules exist, only the
 * first is removed.
 *
 * Invalidates compiled state.
 *
 * @param rs        Ruleset handle.
 * @param layer     Layer index.
 * @param pattern   Exact pattern to match.
 * @param mode      Exact mode to match.
 * @param op_type   Exact operation type to match.
 * @return 0 on success, -1 if no matching rule found.
 */
int soft_ruleset_remove_rule(soft_ruleset_t *rs,
                             int layer,
                             const char *pattern,
                             uint32_t mode,
                             soft_binary_op_t op_type);

/**
 * Remove a rule by its position within a layer.
 *
 * Invalidates compiled state.
 *
 * @param rs     Ruleset handle.
 * @param layer  Layer index.
 * @param index  Rule index within the layer (0..count-1).
 * @return 0 on success, -1 on invalid layer or index.
 */
int soft_ruleset_remove_rule_at_index(soft_ruleset_t *rs,
                                      int layer,
                                      int index);

/* ------------------------------------------------------------------ */
/*  Ruleset merging and insertion                                      */
/* ------------------------------------------------------------------ */

/**
 * Clone a ruleset (deep copy).
 *
 * Creates a new ruleset with all layers and rules copied from the
 * source.  The cloned ruleset is NOT compiled (starts in descriptive
 * mode) even if the source was compiled.
 *
 * @param rs Source ruleset handle.
 * @return New ruleset handle, or NULL on failure (errno set).
 *         Caller must free with soft_ruleset_free().
 */
soft_ruleset_t *soft_ruleset_clone(const soft_ruleset_t *rs);

/**
 * Merge all rules from src into dest, preserving layer indices.
 *
 * Rules from src at layer N are appended to dest's layer N.  If dest
 * doesn't have that layer yet, it is created.  Layer types and masks
 * from src override dest for overlapping layers.
 *
 * Invalidates dest compiled state.
 *
 * @param dest Destination ruleset handle.
 * @param src  Source ruleset handle (unchanged).
 * @return 0 on success, -1 on failure (errno set).
 */
int soft_ruleset_merge(soft_ruleset_t *dest, const soft_ruleset_t *src);

/**
 * Insert all rules from src into dest, shifted by depth layers.
 *
 * Rules from src at layer N are inserted into dest at layer N+depth.
 * Existing dest rules keep their original layer numbers (no shift).
 * This is useful for nesting a ruleset at a specific precedence depth.
 *
 * Invalidates dest compiled state.
 *
 * @param dest   Destination ruleset handle.
 * @param src    Source ruleset handle (unchanged).
 * @param depth  Number of layers to shift src rules by.
 * @return 0 on success, -1 on failure (e.g., depth would exceed MAX_LAYERS).
 */
int soft_ruleset_insert_ruleset(soft_ruleset_t *dest,
                                const soft_ruleset_t *src,
                                int depth);

/**
 * Merge src into dest so that src's layer 0 becomes target_layer.
 *
 * All rules from src are re-layered: src layer N → dest layer
 * target_layer+N.  This is useful for inserting a complete ruleset
 * at a specific precedence point in dest.
 *
 * Invalidates dest compiled state.
 *
 * @param dest         Destination ruleset handle.
 * @param src          Source ruleset handle (unchanged).
 * @param target_layer Layer in dest where src's layer 0 should land.
 * @return 0 on success, -1 on failure (e.g., would exceed MAX_LAYERS).
 */
int soft_ruleset_merge_at_layer(soft_ruleset_t *dest,
                                const soft_ruleset_t *src,
                                int target_layer);

/**
 * Move all layers from src into dest, merging at corresponding indices
 * (ownership transfer, no deep copy).
 *
 * Like soft_ruleset_merge(), but instead of copying src's rules, the
 * rule arrays are transferred.  After this call, src is left in a
 * valid but empty state.
 *
 * @param dest Destination ruleset handle.
 * @param src  Source ruleset handle (consumed — left empty).
 * @return 0 on success, -1 on failure (errno set).
 */
int soft_ruleset_meld(soft_ruleset_t *dest, soft_ruleset_t *src);

/**
 * Move all layers from src into dest, shifted by depth (ownership transfer).
 *
 * Like soft_ruleset_insert_ruleset(), but transfers ownership of src's
 * rule arrays instead of copying them.
 *
 * @param dest   Destination ruleset handle.
 * @param src    Source ruleset handle (consumed — left empty).
 * @param depth  Number of layers to shift src rules by.
 * @return 0 on success, -1 on failure.
 */
int soft_ruleset_meld_ruleset(soft_ruleset_t *dest,
                              soft_ruleset_t *src,
                              int depth);

/**
 * Move all layers from src into dest at target_layer (ownership transfer).
 *
 * Like soft_ruleset_merge_at_layer(), but transfers ownership of src's
 * rule arrays instead of copying them.
 *
 * @param dest         Destination ruleset handle.
 * @param src          Source ruleset handle (consumed — left empty).
 * @param target_layer Layer in dest where src's layer 0 should land.
 * @return 0 on success, -1 on failure.
 */
int soft_ruleset_meld_at_layer(soft_ruleset_t *dest,
                               soft_ruleset_t *src,
                               int target_layer);

/**
 * Insert all rules from src into dest at target_layer, shifting
 * existing dest layers upward.
 *
 * All dest layers at index ≥ target_layer are shifted up by
 * src->layer_count positions.  Src's layers are then copied in:
 *   src layer 0  → dest layer target_layer
 *   src layer 1  → dest layer target_layer + 1
 *   ...
 *
 * Example: dest has layers [0, 1, 2], src has 3 layers, insert at 1.
 *   Result: [dest0, src0, src1, src2, dest1→4, dest2→5]
 *
 * Src is not modified.  For an ownership-taking variant, see
 * soft_ruleset_meld_into().
 *
 * Invalidates dest compiled state.
 *
 * @param dest          Destination ruleset handle.
 * @param src           Source ruleset handle (unchanged).
 * @param target_layer  Layer index in dest where src's layer 0 lands.
 * @return 0 on success, -1 on failure (e.g., would exceed MAX_LAYERS).
 */
int soft_ruleset_insert_at_layer(soft_ruleset_t *dest,
                                 const soft_ruleset_t *src,
                                 int target_layer);

/**
 * Move all layers from src into dest at target_layer, taking ownership
 * of src's internal rule arrays (no deep copy).
 *
 * Like soft_ruleset_insert_at_layer(), but instead of cloning src's
 * rules, the rule arrays are transferred to dest.  After this call,
 * src is left in a valid but empty state (safe to free, but its rules
 * now belong to dest).
 *
 * This is useful when loading or building a temporary ruleset that will
 * be combined into a larger one — avoids malloc overhead.
 *
 * Example: dest has layers [0, 1, 2], src has 3 layers, meld at 1.
 *   Result: [dest0, src0, src1, src2, dest1→4, dest2→5]
 *   src is left with 0 layers.
 *
 * Invalidates dest compiled state.
 *
 * @param dest          Destination ruleset handle.
 * @param src           Source ruleset handle (consumed — left empty).
 * @param target_layer  Layer index in dest where src's layer 0 lands.
 * @return 0 on success, -1 on failure (e.g., would exceed MAX_LAYERS).
 */
int soft_ruleset_meld_into(soft_ruleset_t *dest,
                           soft_ruleset_t *src,
                           int target_layer);

/* ------------------------------------------------------------------ */
/*  Ruleset diff                                                       */
/* ------------------------------------------------------------------ */

/** Type of change detected in a ruleset diff. */
typedef enum {
    DIFF_RULE_ADDED,     /**< Rule exists in B but not A */
    DIFF_RULE_REMOVED,   /**< Rule exists in A but not B */
    DIFF_RULE_MODIFIED,  /**< Rule exists in both but attributes differ */
    DIFF_RULE_UNCHANGED, /**< Rule is identical in both */
} soft_diff_type_t;

/**
 * Description of a single rule difference.
 *
 * rule_a and rule_b point to internal rule data in the respective
 * rulesets.  They are valid only until the ruleset is modified or freed.
 */
typedef struct {
    soft_diff_type_t      type;
    int                   layer_a;   /**< Layer in A (-1 if added) */
    int                   layer_b;   /**< Layer in B (-1 if removed) */
    const soft_rule_info_t *rule_a;  /**< NULL if added */
    const soft_rule_info_t *rule_b;  /**< NULL if removed */
} soft_rule_diff_t;

/**
 * Summary of a ruleset diff operation.
 */
typedef struct {
    soft_rule_diff_t *changes;  /**< Array of all differences (caller must not free) */
    int               count;    /**< Number of entries in changes[] */
    int               capacity; /**< Allocated capacity of changes[] */
    int               added;    /**< Count of DIFF_RULE_ADDED */
    int               removed;  /**< Count of DIFF_RULE_REMOVED */
    int               modified; /**< Count of DIFF_RULE_MODIFIED */
    int               unchanged;/**< Count of DIFF_RULE_UNCHANGED */
} soft_ruleset_diff_t;

/**
 * Compare two rulesets and produce a diff report.
 *
 * Rules are compared layer by layer, then by (pattern, mode, op_type,
 * subject_regex, min_uid, flags).  A rule is considered MODIFIED if
 * the same pattern+op exists in both rulesets but with different
 * attributes.
 *
 * @param a     First ruleset (may be NULL — treated as empty).
 * @param b     Second ruleset (may be NULL — treated as empty).
 * @param out   Receives the diff report.  The changes[] array points
 *              to internally allocated memory; free with
 *              soft_ruleset_diff_free().
 * @return 0 on success, -1 on failure (errno set).
 */
int soft_ruleset_diff(const soft_ruleset_t *a,
                      const soft_ruleset_t *b,
                      soft_ruleset_diff_t *out);

/**
 * Free a diff report produced by soft_ruleset_diff().
 *
 * @param diff  Diff report to free (NULL is safe).
 */
void soft_ruleset_diff_free(soft_ruleset_diff_t *diff);

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
