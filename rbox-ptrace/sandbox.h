/*
 * sandbox.h - Sandboxing functionality for rbox-ptrace
 *
 * Provides:
 * - Landlock filesystem restrictions
 * - Seccomp network blocking
 * - Memory limits via setrlimit
 *
 * Configuration is read from environment variables:
 * - READONLYBOX_MEMORY_LIMIT: memory limit (e.g., "256M", "1G")
 * - READONLYBOX_NO_NETWORK: if set, block network access
 * - READONLYBOX_HARD_ALLOW: colon-separated allowed paths with modes
 * - READONLYBOX_HARD_DENY: colon-separated denied paths
 *
 * Policy: When both HARD_ALLOW and HARD_DENY are set, deny takes precedence
 * for overlapping paths. Only directories are accepted.
 */

#ifndef SANDBOX_H
#define SANDBOX_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct allowed_entry {
    char *original;
    char *resolved;
    uint64_t access;
};

struct denied_entry {
    char *original;
    char *resolved;
};

typedef bool (*sandbox_path_validator_t)(const char *path, void *ctx);

uint64_t sandbox_parse_access_mode(const char *mode);

struct allowed_entry *sandbox_parse_allow_list(const char *env_value, int *out_count,
                                              sandbox_path_validator_t validator, void *ctx);

struct denied_entry *sandbox_parse_deny_list(const char *env_value, int *out_count,
                                             sandbox_path_validator_t validator, void *ctx);

void sandbox_simplify_allow_list(struct allowed_entry **entries, int *count);

void sandbox_simplify_deny_list(struct denied_entry **entries, int *count);

int sandbox_remove_overlaps(struct allowed_entry *allow, int allow_count,
                           struct denied_entry *deny, int deny_count);

uint64_t sandbox_calc_handled_access(const struct allowed_entry *allow, int allow_count);

void sandbox_free_allow_entries(struct allowed_entry *entries, int count);

void sandbox_free_deny_entries(struct denied_entry *entries, int count);

bool sandbox_is_path_prefix(const char *parent, const char *child);

bool sandbox_is_under_deny(const char *path, size_t path_len,
                           struct denied_entry *deny, int deny_count);

bool sandbox_has_deny_under(const char *path, size_t path_len,
                           struct denied_entry *deny, int deny_count);

/* Apply all sandbox restrictions as defined by environment variables.
 * Must be called after the child has been traced (PTRACE_TRACEME)
 * but before dropping privileges. */
void apply_sandboxing(void);

/* Validate Landlock paths early (before pkexec auth prompt).
 * Returns 0 on success.
 * Prints error message and exits on invalid paths. */
int validate_landlock_paths(void);

/* Test interface for expansion logic */
int sandbox_expand_paths(struct allowed_entry *allow, int allow_count,
                          struct denied_entry *deny, int deny_count);

int sandbox_get_expanded_count(void);
const char *sandbox_get_expanded_path(int index);
uint64_t sandbox_get_expanded_access(int index);
void sandbox_expansion_cleanup(void);

#endif /* SANDBOX_H */
