/*
 * log.c - Centralized logging implementation
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <pthread.h>

#include "rbox_log.h"

/* ============================================================
 * GLOBAL STATE
 * ============================================================ */

static _Atomic int g_log_level = RBOX_LOG_ERROR;
static _Atomic rbox_log_callback_t g_log_callback = NULL;

/* Thread-local buffer for formatting */
static __thread char g_log_buf[4096];

/* ============================================================
 * DEFAULT STDERR LOGGER
 * ============================================================ */

static void default_stderr_logger(rbox_log_level_t level,
                                  const char *file,
                                  int line,
                                  const char *msg) {
    const char *level_str;
    switch (level) {
        case RBOX_LOG_ERROR: level_str = "ERROR"; break;
        case RBOX_LOG_WARN:  level_str = "WARN";  break;
        case RBOX_LOG_INFO:  level_str = "INFO";  break;
        case RBOX_LOG_DEBUG: level_str = "DEBUG"; break;
        default:             level_str = "UNKNOWN"; break;
    }

    flockfile(stderr);
    fprintf(stderr, "[%s] %s:%d: %s\n", level_str, file, line, msg);
    funlockfile(stderr);
}

/* ============================================================
 * API IMPLEMENTATION
 * ============================================================ */

__attribute__((visibility("default")))
void rbox_log_set_level(rbox_log_level_t level) {
    atomic_store_explicit(&g_log_level, level, memory_order_relaxed);
}

__attribute__((visibility("default")))
void rbox_log_set_callback(rbox_log_callback_t cb) {
    atomic_store_explicit(&g_log_callback, cb, memory_order_relaxed);
}

__attribute__((visibility("default")))
void rbox_log(rbox_log_level_t level, const char *file, int line, const char *fmt, ...) {
    if (level > atomic_load_explicit(&g_log_level, memory_order_relaxed)) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_log_buf, sizeof(g_log_buf), fmt, ap);
    va_end(ap);

    rbox_log_callback_t cb = atomic_load_explicit(&g_log_callback, memory_order_relaxed);
    if (cb) {
        cb(level, file, line, g_log_buf);
    } else {
        default_stderr_logger(level, file, line, g_log_buf);
    }
}

/* ============================================================
 * ENVIRONMENT PARSING
 * ============================================================ */

static int parse_log_level(const char *env_val) {
    if (strcmp(env_val, "error") == 0) return RBOX_LOG_ERROR;
    if (strcmp(env_val, "warn") == 0)  return RBOX_LOG_WARN;
    if (strcmp(env_val, "info") == 0)  return RBOX_LOG_INFO;
    if (strcmp(env_val, "debug") == 0) return RBOX_LOG_DEBUG;
    return -1;
}

/* Called from runtime constructor to init log level from environment */
__attribute__((visibility("default")))
void rbox_log_init_from_env(void) {
    const char *env_val = getenv("RBOX_LOG_LEVEL");
    if (env_val) {
        int level = parse_log_level(env_val);
        if (level >= 0) {
            atomic_store_explicit(&g_log_level, level, memory_order_relaxed);
        }
    }
}
