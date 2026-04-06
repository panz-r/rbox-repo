/*
 * soft_policy.h - Soft filesystem access policy via syscall interception
 *
 * The soft policy provides runtime filesystem access control that can be
 * dynamically updated. Unlike Landlock (hard policy), soft policy uses
 * syscall interception to make allow/deny decisions.
 *
 * Access modes:
 *   DENY  - Block all access
 *   RO    - Read-only (read file, read dir)
 *   RX    - Read + execute (read file, read dir, execute)
 *   RW    - Read + write (no create of special files)
 *   RWX   - Full access (including create special files, symlinks, etc.)
 *
 * Path requirements:
 *   This module does NOT resolve symlinks or ".." components. The caller
 *   must provide canonical, absolute paths (e.g., from realpath(3)).
 *
 * Thread-safety: This module is NOT thread-safe. The global policy
 * (soft_policy_get_global) must not be modified while other threads
 * are calling soft_policy_check(). Callers must ensure proper synchronization.
 *
 * The global policy returned by soft_policy_get_global() must NOT be freed
 * using soft_policy_free() or cleared using soft_policy_clear(). It is
 * managed internally and re-initialized on subsequent calls to
 * soft_policy_load_from_env().
 */

#ifndef SOFT_POLICY_H
#define SOFT_POLICY_H

#include <stdbool.h>
#include <stdint.h>

#define MAX_SOFT_RULES 256
#define MAX_PATH_LENGTH 4096

/* Access types (bitmask) - maps to syscall types */
#define SOFT_ACCESS_READ     0x01  /* Read file content */
#define SOFT_ACCESS_WRITE    0x02  /* Write file content, create files */
#define SOFT_ACCESS_EXEC     0x04  /* Execute file */
#define SOFT_ACCESS_MKDIR    0x08  /* Create directories */
#define SOFT_ACCESS_RMDIR    0x10  /* Remove directories */
#define SOFT_ACCESS_UNLINK   0x20  /* Remove files */
#define SOFT_ACCESS_RENAME  0x40  /* Rename files/dirs */
#define SOFT_ACCESS_CHMOD    0x80  /* Change permissions */
#define SOFT_ACCESS_CHOWN    0x100 /* Change owner/group */
#define SOFT_ACCESS_TRUNCATE 0x200 /* Truncate files */
#define SOFT_ACCESS_SYMLINK  0x400 /* Create symlinks */
#define SOFT_ACCESS_LINK     0x800 /* Create hard links */

typedef enum {
    SOFT_MODE_DENY = 0,    /* Block all access */
    SOFT_MODE_RO,          /* Read-only */
    SOFT_MODE_RX,          /* Read + execute */
    SOFT_MODE_RW,          /* Read + write (no special file creation) */
    SOFT_MODE_RWX          /* Full access */
} soft_mode_t;

/* Input: path + requested access mask */
typedef struct {
    const char *path;
    uint32_t access_mask;
} soft_path_mode_t;

/* Rule structure */
typedef struct {
    char *path;
    soft_mode_t mode;
} soft_rule_t;

/* soft_policy_t definition */
struct soft_policy {
    soft_rule_t *rules;
    int count;
    int capacity;
    soft_mode_t default_mode;
};
typedef struct soft_policy soft_policy_t;

uint32_t soft_mode_to_access_mask(soft_mode_t mode);
soft_mode_t soft_parse_mode(const char *mode_str);

void soft_policy_init(soft_policy_t *policy);
int soft_policy_add_rule(soft_policy_t *policy, const char *path, soft_mode_t mode);
int soft_policy_prepend_rule(soft_policy_t *policy, const char *path, soft_mode_t mode);
void soft_policy_free(soft_policy_t *policy);

/* Clear all rules from a policy (does not free the policy itself).
 * Note: Must NOT be called on the global policy returned by
 * soft_policy_get_global(). Use soft_policy_load_from_env() to reload
 * the global policy instead. */
void soft_policy_clear(soft_policy_t *policy);

/* Check access for multiple paths at once.
 * 
 * Args:
 *   policy     - The policy to check against
 *   inputs     - Array of path+access_mask pairs to evaluate
 *   results    - Pre-allocated array for results (0=denied, 1=allowed), same length as inputs
 *   count      - Number of entries in inputs/results
 *
 * Returns 0 on success, -1 on error. */
int soft_policy_check(const soft_policy_t *policy, const soft_path_mode_t *inputs, int *results, int count);

int soft_policy_load_from_env(soft_policy_t *policy);
int soft_policy_validate_from_env(void);
void soft_policy_load_builtin(soft_policy_t *policy);
void soft_policy_set_default(soft_policy_t *policy, soft_mode_t mode);
bool soft_policy_is_active(const soft_policy_t *policy);
soft_policy_t *soft_policy_get_global(void);

extern bool g_soft_debug;

#endif /* SOFT_POLICY_H */
