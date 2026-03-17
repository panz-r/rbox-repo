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

/* Initialize validation subsystem (DFA, server connection) */
int validation_init(void);

/* Shutdown validation subsystem */
void validation_shutdown(void);

/* Check if command is allowed using DFA fast-path */
int validation_check_dfa(const char *command);

/* Get socket path from environment */
const char *validation_get_socket_path(void);

#endif /* READONLYBOX_PTRACE_VALIDATION_H */
