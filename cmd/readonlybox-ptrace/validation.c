/*
 * validation.c - DFA-based command validation for ptrace client
 *
 * This module handles DFA fast-path validation only.
 * Server communication is handled by readonlybox --run, not this ptrace client.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "validation.h"
#include "protocol.h"

/* External DFA function from the linked library */
extern int dfa_should_allow(const char *cmd);

/* Socket path (kept for API compatibility) */
static char g_socket_path[1024] = ROBO_DEFAULT_SOCKET;

/* Initialize validation subsystem */
int validation_init(void) {
    /* Get socket path from environment (kept for compatibility) */
    const char *env_path = getenv(ROBO_ENV_SOCKET);
    if (env_path && env_path[0]) {
        strncpy(g_socket_path, env_path, sizeof(g_socket_path) - 1);
        g_socket_path[sizeof(g_socket_path) - 1] = '\0';
    }

    return 0;
}

/* Shutdown validation subsystem */
void validation_shutdown(void) {
    /* Nothing to clean up for DFA-only validation */
}

/* Get socket path */
const char *validation_get_socket_path(void) {
    return g_socket_path;
}

/* Check if command is allowed using DFA */
int validation_check_dfa(const char *command) {
    if (!command || !command[0]) return VALIDATION_DENY;

    /* Call the DFA function from the linked library */
    if (dfa_should_allow(command)) {
        return VALIDATION_ALLOW;
    }

    return VALIDATION_ASK;
}
