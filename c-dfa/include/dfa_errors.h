#ifndef DFA_ERRORS_H
#define DFA_ERRORS_H

/**
 * Unified Error Reporting for C-DFA Tools
 * 
 * Usage:
 *   FATAL("Cannot open file %s: %s", filename, strerror(errno));
 *   ERROR("Invalid state index %d", state);
 *   WARNING("Pattern '%s' not found, skipping", name);
 *
 * Format: [program] LEVEL: message
 * Example: [nfa_builder] ERROR: Cannot open file 'patterns.txt': No such file
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>

/* Program name must be defined before including this header in each tool */
#ifndef DFA_ERROR_PROGRAM
#define DFA_ERROR_PROGRAM "c-dfa"
#endif

/* Suppress pedantic warning for ##__VA_ARGS__ (GNU extension) */
#pragma GCC system_header

/* Core error macros */
#define FATAL(fmt, ...) \
    fprintf(stderr, "[%s] FATAL: " fmt "\n", DFA_ERROR_PROGRAM, ##__VA_ARGS__)

#define ERROR(fmt, ...) \
    fprintf(stderr, "[%s] ERROR: " fmt "\n", DFA_ERROR_PROGRAM, ##__VA_ARGS__)

#define WARNING(fmt, ...) \
    fprintf(stderr, "[%s] WARNING: " fmt "\n", DFA_ERROR_PROGRAM, ##__VA_ARGS__)

/* Convenience macro for system errors with errno */
#define FATAL_SYS(fmt, ...) \
    FATAL(fmt ": %s", ##__VA_ARGS__, strerror(errno))

#define ERROR_SYS(fmt, ...) \
    ERROR(fmt ": %s", ##__VA_ARGS__, strerror(errno))

#endif /* DFA_ERRORS_H */
