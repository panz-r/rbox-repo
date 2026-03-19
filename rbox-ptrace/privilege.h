/*
 * privilege.h - Privilege management for readonlybox-ptrace
 */

#ifndef PRIVILEGE_H
#define PRIVILEGE_H

#include <stdbool.h>
#include <sys/types.h>

/* Initialize privilege state with provided UID and CWD */
void privilege_init(uid_t provided_uid, const char *provided_cwd);

/* Drop privileges to the original user */
void privilege_drop(void);

/* Check if we have ptrace capability */
bool privilege_has_ptrace_capability(void);

/* Set clean environment mode */
void privilege_set_clean_env(bool clean);

#endif /* PRIVILEGE_H */
