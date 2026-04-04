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
#include <limits.h>
#include <libgen.h>
#include <string.h>

#include "validation.h"
#include "protocol.h"
#include "debug.h"

/* External DFA functions from the linked library */
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

/* Wrap binary path - resolved once at startup */
static char g_wrap_path[PATH_MAX] = "";

/* Set socket path explicitly (from --socket PATH) - highest priority */
void validation_set_socket_path(const char *path) {
    if (path && path[0]) {
        strlcpy(g_socket_path, path, sizeof(g_socket_path));
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
    /* Resolve wrap path FIRST (before any socket path early returns) */
    if (g_wrap_path[0] == '\0') {
        const char *env_path = getenv("READONLYBOX_WRAP_PATH");
        if (env_path && env_path[0] && access(env_path, X_OK) == 0) {
            strlcpy(g_wrap_path, env_path, sizeof(g_wrap_path));
            g_wrap_path[sizeof(g_wrap_path) - 1] = '\0';
        } else {
            char self_path[PATH_MAX];
            ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
            if (len > 0) {
                self_path[len] = '\0';
                char *dir = strdup(self_path);
                if (dir) {
                    char *d = dirname(dir);
                    char candidate[PATH_MAX];

                    snprintf(candidate, sizeof(candidate), "%s/rbox-wrap", d);
                    if (access(candidate, X_OK) == 0) {
                        strlcpy(g_wrap_path, candidate, sizeof(g_wrap_path));
                        free(dir);
                    } else {
                        snprintf(candidate, sizeof(candidate), "%s/../rbox-wrap/rbox-wrap", d);
                        if (access(candidate, X_OK) == 0) {
                            strlcpy(g_wrap_path, candidate, sizeof(g_wrap_path));
                            free(dir);
                        } else {
                            snprintf(candidate, sizeof(candidate), "%s/../../rbox-wrap/rbox-wrap", d);
                            if (access(candidate, X_OK) == 0) {
                                strlcpy(g_wrap_path, candidate, sizeof(g_wrap_path));
                                free(dir);
                            } else {
                                free(dir);
                            }
                        }
                    }
                }
            }

            if (g_wrap_path[0] == '\0' && access("./rbox-wrap/rbox-wrap", X_OK) == 0) {
                strlcpy(g_wrap_path, "./rbox-wrap/rbox-wrap", sizeof(g_wrap_path));
            }

            if (g_wrap_path[0] == '\0') {
                char *path_env = getenv("PATH");
                if (path_env) {
                    char *path_copy = strdup(path_env);
                    if (path_copy) {
                        char *token = strtok(path_copy, ":");
                        while (token && g_wrap_path[0] == '\0') {
                            char candidate[PATH_MAX];
                            snprintf(candidate, sizeof(candidate), "%s/rbox-wrap", token);
                            if (access(candidate, X_OK) == 0) {
                                strlcpy(g_wrap_path, candidate, sizeof(g_wrap_path));
                            }
                            token = strtok(NULL, ":");
                        }
                        free(path_copy);
                    }
                }
            }
        }
    }

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
        DEBUG_PRINT("VALIDATION_INIT: socket path explicitly set, using '%s'\n", g_socket_path);
        return 0;
    }

    /* 2. --system-socket forces system path */
    if (g_force_system) {
        strlcpy(g_socket_path, "/run/readonlybox/readonlybox.sock", sizeof(g_socket_path));
        g_socket_path[sizeof(g_socket_path) - 1] = '\0';
        DEBUG_PRINT("VALIDATION_INIT: --system-socket, using '%s'\n", g_socket_path);
        return 0;
    }

    /* 3. --user-socket uses XDG if set, else system */
    if (g_force_user) {
        const char *xdg_dir = getenv("XDG_RUNTIME_DIR");
        if (xdg_dir && xdg_dir[0]) {
            snprintf(g_socket_path, sizeof(g_socket_path), "%s/readonlybox.sock", xdg_dir);
            DEBUG_PRINT("VALIDATION_INIT: --user-socket XDG=%s, using '%s'\n", xdg_dir, g_socket_path);
        } else {
            strlcpy(g_socket_path, "/run/readonlybox/readonlybox.sock", sizeof(g_socket_path));
            g_socket_path[sizeof(g_socket_path) - 1] = '\0';
            DEBUG_PRINT("VALIDATION_INIT: --user-socket no XDG, using '%s'\n", g_socket_path);
        }
        return 0;
    }

    /* 4. READONLYBOX_SOCKET environment variable */
    const char *env_path = getenv(ROBO_ENV_SOCKET);
    if (env_path && env_path[0]) {
        strlcpy(g_socket_path, env_path, sizeof(g_socket_path));
        g_socket_path[sizeof(g_socket_path) - 1] = '\0';
        DEBUG_PRINT("VALIDATION_INIT: READONLYBOX_SOCKET env, using '%s'\n", g_socket_path);
        return 0;
    }

    /* 5. XDG_RUNTIME_DIR */
    const char *xdg_dir = getenv("XDG_RUNTIME_DIR");
    if (xdg_dir && xdg_dir[0]) {
        snprintf(g_socket_path, sizeof(g_socket_path), "%s/readonlybox.sock", xdg_dir);
        DEBUG_PRINT("VALIDATION_INIT: XDG_RUNTIME_DIR=%s, using '%s'\n", xdg_dir, g_socket_path);
        return 0;
    }

    /* 6. Default system path */
    strlcpy(g_socket_path, "/run/readonlybox/readonlybox.sock", sizeof(g_socket_path));
    g_socket_path[sizeof(g_socket_path) - 1] = '\0';
    DEBUG_PRINT("VALIDATION_INIT: default, using '%s'\n", g_socket_path);

    return 0;
}

/* Shutdown validation subsystem */
void validation_shutdown(void) {
    /* Reset global state for clean re-initialization */
    g_socket_path[0] = '\0';
    g_socket_explicitly_set = 0;
    g_force_system = 0;
    g_force_user = 0;
    g_wrap_path[0] = '\0';
}

/* Get socket path */
const char *validation_get_socket_path(void) {
    DEBUG_PRINT("SOCKET: returning socket path '%s'\n", g_socket_path);
    return g_socket_path;
}

/* Get wrap binary path */
const char *validation_get_wrap_path(void) {
    DEBUG_PRINT("WRAP: returning wrap path '%s'\n", g_wrap_path[0] ? g_wrap_path : "(null)");
    return g_wrap_path[0] ? g_wrap_path : NULL;
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

