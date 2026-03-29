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

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "readonlybox-ptrace"
#endif

#define LOG_ERROR(fmt, ...) do { \
        fprintf(stderr, "%s: ERROR: " fmt "\n", PROGRAM_NAME, ##__VA_ARGS__); \
    } while(0)

#define LOG_WARN(fmt, ...) do { \
        fprintf(stderr, "%s: Warning: " fmt "\n", PROGRAM_NAME, ##__VA_ARGS__); \
    } while(0)

#define LOG_FATAL(fmt, ...) do { \
        fprintf(stderr, "%s: FATAL: " fmt "\n", PROGRAM_NAME, ##__VA_ARGS__); \
        exit(1); \
    } while(0)

#define LOG_ERRNO(msg) do { \
        fprintf(stderr, "%s: ERROR: %s: %s\n", PROGRAM_NAME, msg, strerror(errno)); \
    } while(0)

#define LOG_FATAL_ERRNO(msg) do { \
        fprintf(stderr, "%s: FATAL: %s: %s\n", PROGRAM_NAME, msg, strerror(errno)); \
        exit(1); \
    } while(0)

#ifdef DEBUG
/* Debug file pointer - defined in main.c */
extern FILE *g_debug_file;

/* Debug initialization - defined in main.c */
void debug_init(void);

#define DEBUG_PRINT(fmt, ...) do { \
        if (!g_debug_file) debug_init(); \
        time_t now = time(NULL); \
        struct tm *tm = localtime(&now); \
        fprintf(g_debug_file, "[%02d:%02d:%02d] ", tm->tm_hour, tm->tm_min, tm->tm_sec); \
        fprintf(g_debug_file, fmt, ##__VA_ARGS__); \
        fflush(g_debug_file); \
    } while(0)
#else
#define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

#endif /* DEBUG_H */
