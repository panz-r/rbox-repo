/*
 * validation.h - Command validation and server communication
 */

#ifndef READONLYBOX_PTRACE_VALIDATION_H
#define READONLYBOX_PTRACE_VALIDATION_H

#include <stdint.h>
#include <stddef.h>

/* Validation result codes */
#define VALIDATION_ALLOW    0   /* Command is allowed (DFA match) */
#define VALIDATION_DENY     1   /* Command is denied (DFA reject) */
#define VALIDATION_ASK      2   /* Need to ask server */

/* Initialize DFA - must be called before argument parsing */
int dfa_init(void);

/* Initialize validation subsystem (DFA, server connection) */
int validation_init(void);

/* Shutdown validation subsystem */
void validation_shutdown(void);

/* Check if command is allowed using DFA fast-path */
int validation_check_dfa(const char *command);

/* Get socket path - follows priority: --socket > --system-socket/--user-socket > env > XDG > default */
const char *validation_get_socket_path(void);

/* Set socket path explicitly (from --socket PATH) - highest priority */
void validation_set_socket_path(const char *path);

/* Set system socket mode - forces /run/readonlybox/readonlybox.sock */
void validation_set_system_mode(void);

/* Set user socket mode - uses $XDG_RUNTIME_DIR/readonlybox.sock if set, else falls back to system */
void validation_set_user_mode(void);

/* Get wrap binary path - resolved once at startup */
const char *validation_get_wrap_path(void);

#endif /* READONLYBOX_PTRACE_VALIDATION_H */
