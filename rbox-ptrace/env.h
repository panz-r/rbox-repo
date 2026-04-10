/*
 * env.h - Environment screening for readonlybox-ptrace
 */

#ifndef ENV_H
#define ENV_H

#include <stdbool.h>

/* Screen environment variables for secrets.
 * Returns 0 on success, -1 on error. */
int env_screen(void);

/* Get number of flagged environment variables */
int env_get_flagged_count(void);

/* Get flagged env name by index */
const char *env_get_flagged_name(int idx);

/* Get flagged env score by index */
double env_get_flagged_score(int idx);

/* Clear all flagged envs */
void env_clear_flagged(void);

#endif /* ENV_H */
