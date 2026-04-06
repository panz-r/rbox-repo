/*
 * pkexec.h - pkexec launching for readonlybox-ptrace
 */

#ifndef PKEXEC_H
#define PKEXEC_H

#include <stdbool.h>

/* Set program name for error messages */
void pkexec_set_progname(const char *progname);

/* Relaunch with pkexec for privilege escalation.
 * Returns only on error (execve doesn't return on success).
 * resolved_cmd is the already-resolved command path to pass via --cmd.
 */
int pkexec_launch(int argc, char *argv[], const char *resolved_cmd);

#endif /* PKEXEC_H */
