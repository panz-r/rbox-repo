/*
 * libreadonlybox_intercept.so - LD_PRELOAD library for command interception
 *
 * Usage: LD_PRELOAD=/path/to/libreadonlybox_intercept.so <command>
 *
 * This library intercepts execve/execveat syscalls and routes known commands
 * through readonlybox for security validation before execution.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>

/* Registry of commands that should be intercepted */
static const char *intercepted_commands[] = {
    "git", "find", "ls", "cat", "grep", "head", "tail", "echo", "date",
    "sort", "wc", "uniq", "tr", "cut", "paste", "join", "diff", "comm",
    "sed", "awk", "df", "du", "ps", "free", "stat", "file", "touch",
    "mkdir", "rm", "rmdir", "cp", "mv", "ln", "chmod", "chown", "pwd",
    "hostname", "uname", "whoami", "id", "who", "last", "printenv",
    "sleep", "expr", "timeout", "man", "tar", "gzip", "bzip2", "dd",
    "od", "strings", "bash", "sh", "ulimit", "readlink", "basename",
    "dirname", "uptime", "which", "yes", "true", "false", "null",
    NULL
};

/* Path to readonlybox binary - set at build time or via environment */
static char readonlybox_path[1024] = {0};

/* Check if a command should be intercepted */
static int should_intercept(const char *cmd) {
    if (cmd == NULL) return 0;
    
    /* Skip if already going through readonlybox */
    if (strstr(cmd, "readonlybox") != NULL) return 0;
    
    /* Check against registry */
    for (int i = 0; intercepted_commands[i] != NULL; i++) {
        if (strcmp(cmd, intercepted_commands[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Get the basename of a path */
static const char *basename_path(const char *path) {
    if (path == NULL) return NULL;
    const char *last_slash = strrchr(path, '/');
    return last_slash ? last_slash + 1 : path;
}

/* Check if readonlybox binary exists and is executable */
static int readonlybox_exists(void) {
    if (readonlybox_path[0] == '\0') return 0;
    struct stat st;
    return stat(readonlybox_path, &st) == 0 && (st.st_mode & S_IXUSR);
}

/* Execute command through readonlybox - returns exit code or -1 on error */
static int execute_via_readonlybox(const char *cmd, char *const argv[], char *const envp[]) {
    if (!readonlybox_exists()) {
        fprintf(stderr, "readonlybox: binary not found at %s\n", readonlybox_path);
        return 1;
    }

    /* Build new argv: readonlybox <cmd> <args...> */
    int argc = 0;
    while (argv[argc] != NULL) argc++;
    
    char **new_argv = malloc((argc + 2) * sizeof(char*));
    if (new_argv == NULL) return -1;
    
    new_argv[0] = readonlybox_path;
    new_argv[1] = (char*)cmd;
    for (int i = 0; i < argc; i++) {
        new_argv[i + 2] = argv[i];
    }
    new_argv[argc + 2] = NULL;

    /* Fork and execute readonlybox */
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: exec readonlybox */
        execve(readonlybox_path, new_argv, envp);
        /* If we get here, exec failed */
        fprintf(stderr, "readonlybox: failed to execute %s: %s\n", 
                readonlybox_path, strerror(errno));
        _exit(127);
    } else if (pid > 0) {
        /* Parent: wait for child */
        int status;
        waitpid(pid, &status, 0);
        free(new_argv);
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        return -1;
    } else {
        /* Fork failed */
        fprintf(stderr, "readonlybox: fork failed: %s\n", strerror(errno));
        free(new_argv);
        return -1;
    }
}

/*
 * execve - The main syscall we intercept
 *
 * If the command should be intercepted, we execute it through readonlybox
 * and return the exit code. Otherwise, we call the real execve.
 */
int execve(const char *path, char *const argv[], char *const envp[]) {
    static int (*real_execve)(const char *, char *const[], char *const[]) = NULL;
    
    if (real_execve == NULL) {
        real_execve = dlsym(RTLD_NEXT, "execve");
    }
    
    /* Get the command name from the path */
    const char *cmd = basename_path(path);
    
    /* Debug output */
    if (getenv("READONLYBOX_DEBUG") != NULL) {
        fprintf(stderr, "[readonlybox] execve: path=%s cmd=%s\n", path, cmd ? cmd : "(null)");
    }
    
    /* Check if we should intercept this command */
    if (should_intercept(cmd)) {
        /* Debug output */
        if (getenv("READONLYBOX_DEBUG") != NULL) {
            fprintf(stderr, "[readonlybox] Intercepting: %s\n", cmd);
        }
        
        /* Execute via readonlybox */
        int result = execute_via_readonlybox(cmd, argv, envp);
        if (result >= 0) {
            /* readonlybox executed successfully, exit with its code */
            if (getenv("READONLYBOX_DEBUG") != NULL) {
                fprintf(stderr, "[readonlybox] readonlybox returned: %d\n", result);
            }
            _exit(result);
        }
        /* Fall through to real execve on error */
    }
    
    /* Not intercepted or error - execute normally */
    return real_execve(path, argv, envp);
}

/*
 * execveat - Same as execve but for directory file descriptors
 */
int execveat(int dirfd, const char *pathname, char *const argv[], 
             char *const envp[], int flags) {
    static int (*real_execveat)(int, const char *, char *const[], char *const[], int) = NULL;
    
    if (real_execveat == NULL) {
        real_execveat = dlsym(RTLD_NEXT, "execveat");
    }
    
    const char *cmd = basename_path(pathname);
    
    if (should_intercept(cmd)) {
        int result = execute_via_readonlybox(cmd, argv, envp);
        if (result >= 0) {
            _exit(result);
        }
    }
    
    return real_execveat(dirfd, pathname, argv, envp, flags);
}

/*
 * Initialize - called when library is loaded
 */
__attribute__((constructor))
static void init_readonlybox_intercept(void) {
    /* Check for environment variable first */
    const char *env_path = getenv("READONLYBOX_PATH");
    if (env_path != NULL && env_path[0] != '\0') {
        strncpy(readonlybox_path, env_path, sizeof(readonlybox_path) - 1);
    }
    
    /* If not set, try to find readonlybox in common locations */
    if (readonlybox_path[0] == '\0') {
        const char *paths[] = {
            "/usr/local/bin/readonlybox",
            "/usr/bin/readonlybox",
            "./readonlybox",
            NULL
        };
        for (int i = 0; paths[i] != NULL; i++) {
            struct stat st;
            if (stat(paths[i], &st) == 0 && (st.st_mode & S_IXUSR)) {
                strncpy(readonlybox_path, paths[i], sizeof(readonlybox_path) - 1);
                break;
            }
        }
    }
    
    /* Debug output if requested */
    if (getenv("READONLYBOX_DEBUG") != NULL) {
        fprintf(stderr, "[readonlybox] Intercept library initialized\n");
        fprintf(stderr, "[readonlybox] readonlybox path: %s\n", 
                readonlybox_path[0] ? readonlybox_path : "(not found)");
    }
}
