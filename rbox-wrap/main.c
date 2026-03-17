/*
 * rbox-wrap.c - ReadOnlyBox wrapper for executing read-only commands
 * 
 * This is a thin wrapper that:
 * 1. Optionally checks local DFA for fast-path approval
 * 2. Queries the server for a decision on a command
 * 3. If allowed, executes the command locally
 * 4. If denied, prints the denial and exits with error
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include <rbox_protocol.h>
#include <shell_tokenizer.h>
#include <dfa.h>

#define DEFAULT_SOCKET "/tmp/readonlybox.sock"
#define DEFAULT_DFA     "./expanded_perf.dfa"

/* Global DFA state */
static int g_dfa_loaded = 0;

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options] <command> [args...]\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  --judge    Query server for decision, print result (default)\n");
    fprintf(stderr, "  --run      Query server and execute if allowed\n");
    fprintf(stderr, "  --bin      Output raw response packet to stdout\n");
    fprintf(stderr, "  --relay    Skip DFA, always contact server\n");
    fprintf(stderr, "  --socket   Unix socket path (default: %s)\n", DEFAULT_SOCKET);
    fprintf(stderr, "  -h, --help Show this help\n");
    fprintf(stderr, "\nExit codes:\n");
    fprintf(stderr, "  0 - Command allowed and executed (--run only)\n");
    fprintf(stderr, "  1 - Command denied or error\n");
    fprintf(stderr, "  9 - Server decision (deny once) printed\n");
}

/* Load DFA from file */
static int load_dfa(const char *dfa_path) {
    if (g_dfa_loaded) {
        return 0;  /* Already loaded */
    }
    
    FILE *f = fopen(dfa_path, "rb");
    if (!f) {
        return -1;
    }
    
    /* Get file size */
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    void *data = malloc(size);
    if (!data || fread(data, size, 1, f) != 1) {
        fclose(f);
        free(data);
        return -1;
    }
    fclose(f);
    
    /* Initialize DFA */
    if (!dfa_init(data, size)) {
        free(data);
        return -1;
    }
    
    if (!dfa_is_valid()) {
        dfa_reset();
        free(data);
        return -1;
    }
    
    g_dfa_loaded = 1;
    free(data);
    return 0;
}

/* Check DFA for fast-path approval
 * Returns: 1 if allowed, 0 if not, -1 on error/unavailable */
static int check_dfa(int argc, const char *const *args) {
    if (!g_dfa_loaded) {
        /* Try loading default DFA */
        if (load_dfa(DEFAULT_DFA) != 0) {
            return -1;  /* DFA not available */
        }
    }
    
    if (!g_dfa_loaded || !dfa_is_valid()) {
        return -1;
    }
    
    /* Build command string for DFA */
    char cmd_buf[1024];
    cmd_buf[0] = '\0';
    for (int i = 0; i < argc && strlen(cmd_buf) < sizeof(cmd_buf) - 2; i++) {
        if (i > 0) strcat(cmd_buf, " ");
        strncat(cmd_buf, args[i], sizeof(cmd_buf) - strlen(cmd_buf) - 1);
    }
    
    /* Evaluate against DFA */
    dfa_result_t result;
    dfa_evaluate(cmd_buf, strlen(cmd_buf), &result);
    
    /* Category = DFA_CMD_READONLY_SAFE = read-only commands */
    if (result.matched && result.category == DFA_CMD_READONLY_SAFE) {
        return 1;  /* Allowed */
    }
    
    return 0;  /* Not fast-path allowed, contact server */
}

static int run_command(const char *cmd, int argc, char *argv[]) {
    (void)argc;
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    
    if (pid == 0) {
        /* Child: execute command */
        execvp(cmd, argv);
        perror(cmd);
        _exit(127);
    }
    
    /* Parent: wait for child */
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
}

int main(int argc, char *argv[]) {
    const char *socket_path = DEFAULT_SOCKET;
    int mode_run = 0;
    int mode_bin = 0;
    int mode_relay = 0;
    
    /* Parse arguments */
    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "--socket") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --socket requires an argument\n");
                return 1;
            }
            socket_path = argv[i + 1];
            i += 2;
        }
        else if (strcmp(argv[i], "--judge") == 0) {
            mode_run = 0;
            i++;
        }
        else if (strcmp(argv[i], "--run") == 0) {
            mode_run = 1;
            i++;
        }
        else if (strcmp(argv[i], "--bin") == 0) {
            mode_bin = 1;
            i++;
        }
        else if (strcmp(argv[i], "--relay") == 0) {
            mode_relay = 1;
            i++;
        }
        else if (argv[i][0] == '-') {
            fprintf(stderr, "Error: Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
        else {
            break;  /* Command starts here */
        }
    }
    
    if (i >= argc) {
        fprintf(stderr, "Error: No command specified\n");
        usage(argv[0]);
        return 1;
    }
    
    const char *command = argv[i];
    int cmd_argc = argc - i;
    char **cmd_argv = &argv[i];
    
    /* Build arguments for protocol (needs const char **) */
    const char **args = malloc((cmd_argc + 1) * sizeof(char *));
    if (!args) {
        perror("malloc");
        return 1;
    }
    for (int j = 0; j < cmd_argc; j++) {
        args[j] = cmd_argv[j];
    }
    args[cmd_argc] = NULL;
    
    /* Initialize the library */
    rbox_init();
    
    /* Determine caller and syscall based on mode */
    const char *caller = mode_run ? "run" : "judge";
    const char *syscall = "execve";  /* Most CLI tools use execve to run */
    
    /* Check DFA first for fast-path (unless --relay) */
    int dfa_result = -1;
    if (!mode_relay) {
        dfa_result = check_dfa(cmd_argc, args);
    }
    
    /* Handle DFA fast-path */
    if (dfa_result == 1) {
        if (mode_bin) {
            /* DFA fast-path in --bin mode: build and output response packet */
            char *packet;
            size_t pkt_len;
            rbox_error_t build_err = rbox_build_response(
                RBOX_DECISION_ALLOW, "DFA fast-path", 0, 0, 0, NULL, &packet, &pkt_len);
            if (build_err != RBOX_OK) {
                fprintf(stderr, "Error: failed to build response packet\n");
                free(args);
                return 1;
            }
            /* Output raw packet to stdout */
            if (fwrite(packet, 1, pkt_len, stdout) != pkt_len) {
                fprintf(stderr, "Error: failed to write packet\n");
                free(packet);
                free(args);
                return 1;
            }
            free(packet);
            free(args);
            return 0;
        } else {
            /* DFA fast-path: allow without server contact */
            printf("ALLOW DFA fast-path\n");
            free(args);
            if (mode_run) {
                return run_command(command, cmd_argc, cmd_argv);
            }
            return 0;
        }
    }
    
    /* For --bin mode, use raw request to get binary packet */
    if (mode_bin) {
        char *packet;
        size_t pkt_len;
        rbox_error_t err = rbox_blocking_request_raw(
            socket_path,
            command,
            cmd_argc,
            args,
            caller,
            syscall,
            0, NULL, NULL,  /* no env vars */
            &packet,
            &pkt_len,
            100,   /* base_delay_ms */
            3      /* max_retries */
        );
        free(args);
        
        if (err != RBOX_OK) {
            fprintf(stderr, "Error: %s\n", rbox_strerror(err));
            return 1;
        }
        
        /* Output raw packet to stdout */
        if (fwrite(packet, 1, pkt_len, stdout) != pkt_len) {
            fprintf(stderr, "Error: failed to write packet\n");
            free(packet);
            return 1;
        }
        free(packet);
        return 0;
    }
    
    /* Query the server (text mode) */
    rbox_response_t response;
    rbox_error_t err = rbox_blocking_request(
        socket_path,
        command,
        cmd_argc,
        args,
        caller,
        syscall,
        0,      /* env_var_count */
        NULL,   /* env_var_names */
        NULL,   /* env_var_scores */
        &response,
        100,   /* base_delay_ms */
        3      /* max_retries */
    );
    
    free(args);
    
    if (err != RBOX_OK) {
        fprintf(stderr, "Error: %s\n", rbox_strerror(err));
        return 1;
    }
    
    /* Handle response */
    if (response.decision == RBOX_DECISION_ALLOW) {
        if (mode_run) {
            /* Execute the command */
            return run_command(command, cmd_argc, cmd_argv);
        } else {
            /* Judge mode: print decision */
            printf("ALLOW %s\n", response.reason[0] ? response.reason : "");
            return 0;
        }
    }
    else if (response.decision == RBOX_DECISION_DENY) {
        /* Print denial */
        printf("DENY %s\n", response.reason[0] ? response.reason : "");
        return 9;  /* Special code for denied */
    }
    else {
        fprintf(stderr, "Error: Unknown decision: %d\n", response.decision);
        return 1;
    }
}
