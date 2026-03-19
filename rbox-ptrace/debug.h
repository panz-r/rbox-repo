/*
 * debug.h - Shared debug utilities for readonlybox-ptrace
 */

#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <time.h>
#include <stdbool.h>

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
