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
#include <stdint.h>
#include <time.h>
#include <sys/fcntl.h>

#include "validation.h"
#include "protocol.h"
#include "debug.h"

/* External DFA functions from the linked library */
extern int dfa_should_allow(const char *cmd);
extern int dfa_get_category_mask(const char *cmd, uint8_t *out_mask);

/* Category bits for decision making */
#define CAT_MASK_AUTOALLOW  0x01  /* Auto-allow: execute without server query */
#define CAT_MASK_AUTODENY  0x02  /* Auto-deny: block without server query */
#define CAT_MASK_ALWAYSASK 0x04  /* Always ask: query server even if autoallow matches */

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

    uint8_t category_mask = 0;
    int matched = dfa_get_category_mask(command, &category_mask);

    if (!matched) {
        /* No DFA match - need to ask server */
        return VALIDATION_ASK;
    }

    /* Priority logic: alwaysask > autodeny > autoallow > ask */
    if (category_mask & CAT_MASK_ALWAYSASK) {
        return VALIDATION_ASK;
    }
    if (category_mask & CAT_MASK_AUTODENY) {
        return VALIDATION_DENY;
    }
    if (category_mask & CAT_MASK_AUTOALLOW) {
        return VALIDATION_ALLOW;
    }

    /* No explicit category - ask server by default */
    return VALIDATION_ASK;
}
