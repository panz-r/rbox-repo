#ifndef TRAMPOLINE_ALLOWANCE_H
#define TRAMPOLINE_ALLOWANCE_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define ALLOWSET_MAX_ENTRIES 256
#define ALLOWSET_ERR_NOMEM -1
#define ALLOWSET_ERR_TOOLARGE -2
#define ALLOWSET_ERR_TOODEEP -3
#define MAX_RECURSION_DEPTH 128
#define ALLOWANCE_TIMEOUT_SECONDS 600

/* holds a set of allowances with constraints */

/* Example:
 * GRANT timeout 1 sh -c 'noop ; sh noop'
 * Then:
 * CONSUME sh -c 'noop ; sh noop'
 * CONSUME noop
 * CONSUME sh noop
 */

struct Allowance {
    /* allowance entry, the command and constraint */
    char * command;
    int after; // -1 for no order constraint
};

/* Per‑process (-tree) allowance set */
typedef struct {
    struct Allowance *vecv; /* allowance vector: when consumed, the vecv[i] is cleared */
    int vecc;               /* count of entries */
    int veca;               /* allocated capacity */
    struct timespec expiration;
} AllowSet;

void allowset_init(AllowSet * restrict a);
void allowset_deinit(AllowSet * restrict a);
int allowset_grant(AllowSet * restrict a, const char *full_command);
int allowset_consume_argv(AllowSet * restrict a, const char *const argv[]);
int allowset_expire(AllowSet * restrict a, const struct timespec * restrict now);

/* For unit testing - get command continuation after splitting first chain.
 * Returns pointer to continuation in dst, or NULL if no chain found. */
const char *get_command_continuation(const char *full_cmd, char *dst, size_t dst_size);

#endif
