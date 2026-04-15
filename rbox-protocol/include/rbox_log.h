/*
 * rbox_log.h - Centralized logging for rbox-protocol
 *
 * Provides a unified logging system with severity levels, user-supplied callbacks,
 * and runtime configuration.
 *
 * Usage:
 *   RBOX_LOG_ERROR("connection failed: %s", strerror(errno));
 *   RBOX_LOG_DEBUG("request completed in %lu ms", elapsed_ms);
 *
 * Compile-time debug control:
 *   -DDEBUG_PRINTS=1 (default) includes debug logging in the build
 *   -DDEBUG_PRINTS=0 excludes debug logging (RBOX_LOG_DEBUG becomes no-op)
 *
 * Runtime control:
 *   RBOX_LOG_LEVEL=error|warn|info|debug ./program
 *
 * Custom callback:
 *   rbox_log_set_callback(my_log_handler);
 */

#ifndef RBOX_LOG_H
#define RBOX_LOG_H

#include <stdint.h>

/* ============================================================
 * LOG LEVELS
 * ============================================================ */

typedef enum {
    RBOX_LOG_ERROR = 1,
    RBOX_LOG_WARN  = 2,
    RBOX_LOG_INFO  = 3,
    RBOX_LOG_DEBUG = 4
} rbox_log_level_t;

/* ============================================================
 * CALLBACK TYPE
 * ============================================================ */

typedef void (*rbox_log_callback_t)(rbox_log_level_t level,
                                    const char *file,
                                    int line,
                                    const char *msg);

/* ============================================================
 * API FUNCTIONS
 * ============================================================ */

/* Set minimum log level (messages below this level are discarded) */
void rbox_log_set_level(rbox_log_level_t level);

/* Set custom log callback (default: stderr logger) */
void rbox_log_set_callback(rbox_log_callback_t cb);

/* Initialize log level from RBOX_LOG_LEVEL environment variable.
 * Called automatically by runtime constructor, but can be called manually. */
void rbox_log_init_from_env(void);

/* Core logging function */
void rbox_log(rbox_log_level_t level, const char *file, int line, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

/* ============================================================
 * LOG MACROS
 * ============================================================ */

/* Base log macros - always compiled */
#define RBOX_LOG_ERROR(...) rbox_log(RBOX_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define RBOX_LOG_WARN(...)  rbox_log(RBOX_LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define RBOX_LOG_INFO(...)  rbox_log(RBOX_LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)

/* Debug macro - conditional on DEBUG_PRINTS compile flag */
#if DEBUG_PRINTS
#define RBOX_LOG_DEBUG(...) rbox_log(RBOX_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#else
#define RBOX_LOG_DEBUG(...) ((void)0)
#endif

/* Legacy macro remapping for easy migration */
#define CDBG(...) RBOX_LOG_DEBUG(__VA_ARGS__)
#define DBG(...)  RBOX_LOG_DEBUG(__VA_ARGS__)

#endif /* RBOX_LOG_H */
