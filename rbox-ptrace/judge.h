/*
 * judge.h - Judge execution for readonlybox-ptrace
 */

#ifndef JUDGE_H
#define JUDGE_H

/* Validate that rbox-wrap can be executed
 * Returns 0 on success, -1 on failure
 */
int validate_wrap_binary(void);

/* Run readonlybox --judge to get server decision
 * Returns: 0 = ALLOW, 9 = DENY, -1 = error
 */
int judge_run(const char *command, const char *caller_info);

#endif /* JUDGE_H */
