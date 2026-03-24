/*
 * privilege.c - Privilege management for readonlybox-ptrace
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdbool.h>

/* Original user information */
static uid_t g_original_uid = 0;
static gid_t g_original_gid = 0;
static char g_original_cwd[4096] = ".";

/* Clean environment flag */
static bool g_clean_env = false;

/* Set clean environment mode */
void privilege_set_clean_env(bool clean) {
    g_clean_env = clean;
}

/* Initialize privilege state with provided UID and CWD */
void privilege_init(uid_t provided_uid, const char *provided_cwd) {
    if (provided_uid != 0) {
        g_original_uid = provided_uid;
        struct passwd *pw = getpwuid(g_original_uid);
        g_original_gid = pw ? pw->pw_gid : getgid();
    } else {
        g_original_uid = getuid();
        g_original_gid = getgid();
    }

    if (provided_cwd && provided_cwd[0]) {
        strncpy(g_original_cwd, provided_cwd, sizeof(g_original_cwd) - 1);
        g_original_cwd[sizeof(g_original_cwd) - 1] = '\0';
    } else {
        if (getcwd(g_original_cwd, sizeof(g_original_cwd)) == NULL) {
            strcpy(g_original_cwd, ".");
        }
    }
}

/* Check if we have all required capabilities (ptrace + admin for sandbox) */
bool privilege_has_ptrace_capability(void) {
    if (geteuid() == 0) return true;

    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return false;

    char line[256];
    unsigned long long caps = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "CapEff:", 7) == 0) {
            sscanf(line + 7, "%llx", &caps);
            break;
        }
    }
    fclose(f);

    // CAP_SYS_PTRACE is bit 19, CAP_SYS_ADMIN is bit 21
    // Both are needed: ptrace for tracing, admin for Landlock/seccomp
    int has_ptrace = (caps >> 19) & 1;
    int has_admin = (caps >> 21) & 1;

    return has_ptrace && has_admin;
}

/* Drop privileges to the original user */
void privilege_drop(void) {
    if (chdir(g_original_cwd) < 0) {
        perror("chdir");
    }

    /* Always drop privileges if we're running as root with a non-root original UID */
    if (geteuid() == 0 && g_original_uid != 0) {
        struct passwd *pw = getpwuid(g_original_uid);
        gid_t gid = pw ? pw->pw_gid : g_original_gid;
        const char *username = pw ? pw->pw_name : "nobody";
        const char *home = pw ? pw->pw_dir : "/";
        const char *shell = pw ? pw->pw_shell : "/bin/sh";

        if (initgroups(username, gid) < 0) {
            perror("initgroups");
        }
        if (setgid(gid) < 0) {
            perror("setgid");
        }
        if (setuid(g_original_uid) < 0) {
            perror("setuid");
        }
        if (geteuid() != g_original_uid) {
            fprintf(stderr, "ERROR: Failed to drop privileges\n");
            _exit(1);
        }

        /* Prevent gaining new privileges via execve (e.g., setuid binaries) */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            fprintf(stderr, "Warning: failed to set PR_SET_NO_NEW_PRIVS\n");
        }

        if (setenv("HOME", home, 1) != 0) {
            fprintf(stderr, "Warning: failed to set HOME\n");
        }
        if (setenv("USER", username, 1) != 0) {
            fprintf(stderr, "Warning: failed to set USER\n");
        }
        if (setenv("LOGNAME", username, 1) != 0) {
            fprintf(stderr, "Warning: failed to set LOGNAME\n");
        }
        if (setenv("SHELL", shell, 1) != 0) {
            fprintf(stderr, "Warning: failed to set SHELL\n");
        }
        unsetenv("PKEXEC_UID");
        unsetenv("PKEXEC_AGENT");
    }

    if (g_clean_env) {
        /* Clear all environment variables - only when explicitly requested.
         * This prevents LD_PRELOAD and other environment-based attacks.
         * Use portable implementation for non-glibc systems (e.g., musl). */
#if HAVE_CLEARENV
        if (clearenv() != 0) {
            fprintf(stderr, "Warning: clearenv() failed\n");
        }
#else
        extern char **environ;
        if (environ) {
            /* Save original environ pointer since we'll modify it */
            char **original_environ = environ;
            /* Unset each variable - iterate using original pointer */
            for (char **e = original_environ; *e; e++) {
                char *eq = strchr(*e, '=');
                if (eq) {
                    size_t len = eq - *e;
                    if (len > 0) {
                        char name[len + 1];
                        memcpy(name, *e, len);
                        name[len] = '\0';
                        unsetenv(name);
                    }
                } else {
                    unsetenv(*e);
                }
            }
            /* Restore environ to empty state */
            environ = NULL;
        }
#endif
    }
}
