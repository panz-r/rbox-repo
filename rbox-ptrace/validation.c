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

/* Socket path selection flags */
static char g_socket_path[1024] = "";
static int g_socket_explicitly_set = 0;  /* --socket PATH provided */
static int g_force_system = 0;            /* --system-socket flag */
static int g_force_user = 0;              /* --user-socket flag */

/* Set socket path explicitly (from --socket PATH) - highest priority */
void validation_set_socket_path(const char *path) {
    if (path && path[0]) {
        strncpy(g_socket_path, path, sizeof(g_socket_path) - 1);
        g_socket_path[sizeof(g_socket_path) - 1] = '\0';
        g_socket_explicitly_set = 1;
    }
}

/* Set system socket mode - forces /run/readonlybox/readonlybox.sock */
void validation_set_system_mode(void) {
    g_force_system = 1;
}

/* Set user socket mode - uses $XDG_RUNTIME_DIR/readonlybox.sock if set, else system */
void validation_set_user_mode(void) {
    g_force_user = 1;
}

/* Initialize validation subsystem */
int validation_init(void) {
    /* Socket path resolution order:
     * 1. --socket PATH (explicit)
     * 2. --system-socket → /run/readonlybox/readonlybox.sock
     * 3. --user-socket → $XDG_RUNTIME_DIR/readonlybox.sock (or system if unset)
     * 4. READONLYBOX_SOCKET env variable
     * 5. XDG_RUNTIME_DIR/readonlybox.sock
     * 6. /run/readonlybox/readonlybox.sock (default)
     */

    /* 1. --socket PATH (highest priority) */
    if (g_socket_explicitly_set) {
        return 0;
    }

    /* 2. --system-socket forces system path */
    if (g_force_system) {
        strncpy(g_socket_path, "/run/readonlybox/readonlybox.sock", sizeof(g_socket_path) - 1);
        g_socket_path[sizeof(g_socket_path) - 1] = '\0';
        return 0;
    }

    /* 3. --user-socket uses XDG if set, else system */
    if (g_force_user) {
        const char *xdg_dir = getenv("XDG_RUNTIME_DIR");
        if (xdg_dir && xdg_dir[0]) {
            snprintf(g_socket_path, sizeof(g_socket_path), "%s/readonlybox.sock", xdg_dir);
        } else {
            strncpy(g_socket_path, "/run/readonlybox/readonlybox.sock", sizeof(g_socket_path) - 1);
            g_socket_path[sizeof(g_socket_path) - 1] = '\0';
        }
        return 0;
    }

    /* 4. READONLYBOX_SOCKET environment variable */
    const char *env_path = getenv(ROBO_ENV_SOCKET);
    if (env_path && env_path[0]) {
        strncpy(g_socket_path, env_path, sizeof(g_socket_path) - 1);
        g_socket_path[sizeof(g_socket_path) - 1] = '\0';
        return 0;
    }

    /* 5. XDG_RUNTIME_DIR */
    const char *xdg_dir = getenv("XDG_RUNTIME_DIR");
    if (xdg_dir && xdg_dir[0]) {
        snprintf(g_socket_path, sizeof(g_socket_path), "%s/readonlybox.sock", xdg_dir);
        return 0;
    }

    /* 6. Default system path */
    strncpy(g_socket_path, "/run/readonlybox/readonlybox.sock", sizeof(g_socket_path) - 1);
    g_socket_path[sizeof(g_socket_path) - 1] = '\0';

    return 0;
}

/* Shutdown validation subsystem */
void validation_shutdown(void) {
    /* Reset global state for clean re-initialization */
    g_socket_path[0] = '\0';
    g_socket_explicitly_set = 0;
    g_force_system = 0;
    g_force_user = 0;
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
