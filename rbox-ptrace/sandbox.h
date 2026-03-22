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
 * - READONLYBOX_LANDLOCK_PATHS: colon-separated allowed paths
 */

#ifndef SANDBOX_H
#define SANDBOX_H

/* Apply all sandbox restrictions as defined by environment variables.
 * Must be called after the child has been traced (PTRACE_TRACEME)
 * but before dropping privileges. */
void apply_sandboxing(void);

#endif /* SANDBOX_H */
