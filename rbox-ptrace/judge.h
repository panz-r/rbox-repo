/*
 * judge.h - Judge execution for readonlybox-ptrace
 */

#ifndef JUDGE_H
#define JUDGE_H

/* Run readonlybox --judge to get server decision
 * Returns: 0 = ALLOW, 9 = DENY, -1 = error
 */
int judge_run(const char *command, const char *caller_info);

/* Get path to readonlybox binary */
const char *judge_get_readonlybox_path(void);

#endif /* JUDGE_H */
