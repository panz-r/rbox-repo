/*
 * debug.h - Shared debug utilities for readonlybox-ptrace
 */

#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>

/* Program name - set by main.c from argv[0] */
extern const char *g_progname;

#define LOG_ERROR(fmt, ...) do { \
        fprintf(stderr, "%s: ERROR: " fmt "\n", g_progname, ##__VA_ARGS__); \
    } while(0)

#define LOG_WARN(fmt, ...) do { \
        fprintf(stderr, "%s: Warning: " fmt "\n", g_progname, ##__VA_ARGS__); \
    } while(0)

#define LOG_FATAL(fmt, ...) do { \
        fprintf(stderr, "%s: FATAL: " fmt "\n", g_progname, ##__VA_ARGS__); \
        exit(1); \
    } while(0)

#define LOG_ERRNO(msg) do { \
        fprintf(stderr, "%s: ERROR: %s: %s\n", g_progname, msg, strerror(errno)); \
    } while(0)

#define LOG_FATAL_ERRNO(msg) do { \
        fprintf(stderr, "%s: FATAL: %s: %s\n", g_progname, msg, strerror(errno)); \
        exit(1); \
    } while(0)

/* Runtime verbose level - set by -v flags */
extern int g_verbose_level;

/* Debug file pointer - defined in main.c */
extern FILE *g_debug_file;

/* Debug initialization - defined in main.c */
void debug_init(void);

/* DEBUG_PRINT - outputs if g_verbose_level >= 1 */
#define DEBUG_PRINT(...) do { \
        if (g_verbose_level >= 1) { \
            if (!g_debug_file) debug_init(); \
            time_t now = time(NULL); \
            struct tm *tm = localtime(&now); \
            fprintf(g_debug_file, "[%02d:%02d:%02d] ", tm->tm_hour, tm->tm_min, tm->tm_sec); \
            fprintf(g_debug_file, __VA_ARGS__); \
            fflush(g_debug_file); \
        } \
    } while(0)

#endif /* DEBUG_H */
