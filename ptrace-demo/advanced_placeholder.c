// advanced_placeholder.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

// Simulate output for common commands
static void simulate_ls() {
    // Simulate empty directory
    printf("# Security: 'ls' command simulated (no actual files accessed)\n");
}

static void simulate_cat(const char *filename) {
    printf("# Security: File access blocked\n");
    printf("# Requested file: %s\n", filename);
    printf("# Content would be here if allowed by policy\n");
}

static void simulate_whoami() {
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    if (pw) {
        printf("%s\n", pw->pw_name);
    } else {
        printf("user%d\n", uid);
    }
}

static void simulate_id() {
    uid_t uid = getuid();
    gid_t gid = getgid();
    
    struct passwd *pw = getpwuid(uid);
    struct group *gr = getgrgid(gid);
    
    printf("uid=%d(%s) gid=%d(%s) groups=", 
           uid, pw ? pw->pw_name : "?", 
           gid, gr ? gr->gr_name : "?");
    
    // Just show primary group for simplicity
    printf("%d(%s)\n", gid, gr ? gr->gr_name : "?");
}

static void simulate_echo(char **args, int start_idx) {
    for (int i = start_idx; args[i]; i++) {
        printf("%s", args[i]);
        if (args[i+1]) printf(" ");
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    int show_denied = 0;
    char *original_cmd = NULL;
    char *cmd_basename = NULL;
    
    // Parse arguments
    struct option long_options[] = {
        {"denied", no_argument, 0, 'd'},
        {"cmd", required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "dc:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'd':
                show_denied = 1;
                break;
            case 'c':
                original_cmd = optarg;
                // Extract basename for simulation
                cmd_basename = strrchr(original_cmd, '/');
                if (cmd_basename) cmd_basename++;
                else cmd_basename = original_cmd;
                break;
            default:
                break;
        }
    }
    
    if (show_denied) {
        // Output to stderr
        fprintf(stderr, "Permission denied: Command '%s' blocked by security policy\n", 
                original_cmd ? original_cmd : "unknown");
        
        // Simulate command output based on command type
        if (cmd_basename) {
            if (strstr(cmd_basename, "ls")) {
                simulate_ls();
            } else if (strstr(cmd_basename, "cat")) {
                // Next argument would be filename
                if (argv[optind]) simulate_cat(argv[optind]);
                else simulate_cat("unknown file");
            } else if (strstr(cmd_basename, "whoami")) {
                simulate_whoami();
            } else if (strstr(cmd_basename, "id")) {
                simulate_id();
            } else if (strstr(cmd_basename, "echo")) {
                simulate_echo(argv, optind);
            } else {
                // Generic success output
                printf("# Command executed successfully (simulated)\n");
                printf("# Original: %s\n", original_cmd);
                for (int i = optind; i < argc && argv[i]; i++) {
                    printf("# Arg %d: %s\n", i - optind + 1, argv[i]);
                }
            }
        }
        
        // Always return success (0)
        return 0;
    }
    
    // If called without --denied, maybe we're being tested
    printf("Security wrapper placeholder\n");
    printf("This binary simulates successful command execution when real commands are blocked.\n");
    return 0;
}
