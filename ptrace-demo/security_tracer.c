#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>

// Configuration
#define PLACEHOLDER_BINARY "/usr/lib/security_wrapper/placeholder"
#define PLACEHOLDER_DIR "/usr/lib/security_wrapper"
#define DENIED_MESSAGE "Permission denied: Command not allowed by security policy\n"

// For x86_64 syscall numbers
#ifdef __x86_64__
    #define SYSCALL_EXECVE 59
    #define SYSCALL_EXECVEAT 322
    #define SYSCALL_CLONE 56
    #define SYSCALL_FORK 57
    #define SYSCALL_VFORK 58
    #define SYSCALL_EXIT_GROUP 231
    #define REGS struct user_regs_struct
    #define SYSNUM orig_rax
    #define ARG1 rdi
    #define ARG2 rsi
    #define ARG3 rdx
    #define ARG4 r10
    #define STACK_POINTER rsp
#elif __i386__
    #define SYSCALL_EXECVE 11
    #define SYSCALL_CLONE 120
    #define SYSCALL_FORK 2
    #define SYSCALL_VFORK 190
    #define SYSCALL_EXIT_GROUP 252
    #define REGS struct user_regs_struct
    #define SYSNUM orig_eax
    #define ARG1 ebx
    #define ARG2 ecx
    #define ARG3 edx
    #define STACK_POINTER esp
#endif

// Memory management for traced process
typedef struct {
    pid_t pid;
    unsigned long free_addr;
} ProcessMemory;

// Read a string from traced process memory
static char *read_string(pid_t pid, unsigned long addr) {
    if (addr == 0) return NULL;
    
    char *buffer = malloc(4096);
    if (!buffer) return NULL;
    
    unsigned long word;
    int offset = 0;
    
    while (offset < 4095) {
        word = ptrace(PTRACE_PEEKDATA, pid, addr + offset, NULL);
        if (errno != 0) {
            free(buffer);
            return NULL;
        }
        
        // Copy bytes from the word
        for (int i = 0; i < sizeof(long); i++) {
            char c = (word >> (i * 8)) & 0xFF;
            buffer[offset + i] = c;
            if (c == '\0') {
                return buffer;
            }
        }
        offset += sizeof(long);
    }
    
    buffer[4095] = '\0';
    return buffer;
}

// Read an array of strings (argv, envp)
static char **read_string_array(pid_t pid, unsigned long addr) {
    if (addr == 0) return NULL;
    
    char **array = malloc(256 * sizeof(char *));
    if (!array) return NULL;
    
    unsigned long ptr;
    int i = 0;
    
    while (i < 255) {
        ptr = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
        if (errno != 0 || ptr == 0) break;
        
        array[i] = read_string(pid, ptr);
        if (!array[i]) break;
        
        i++;
    }
    
    array[i] = NULL;
    return array;
}

// Write a string to traced process memory
static unsigned long write_string(ProcessMemory *mem, const char *str) {
    int len = strlen(str) + 1;
    int words = (len + sizeof(long) - 1) / sizeof(long);
    
    for (int i = 0; i < words; i++) {
        long word = 0;
        int bytes_to_copy = (len - i * sizeof(long)) > sizeof(long) ? 
                            sizeof(long) : (len - i * sizeof(long));
        memcpy(&word, str + i * sizeof(long), bytes_to_copy);
        
        if (ptrace(PTRACE_POKEDATA, mem->pid, mem->free_addr + i * sizeof(long), word) == -1) {
            return 0;
        }
    }
    
    unsigned long result = mem->free_addr;
    mem->free_addr += words * sizeof(long);
    return result;
}

// Write an array of pointers to traced process memory
static unsigned long write_pointer_array(ProcessMemory *mem, unsigned long *pointers, int count) {
    unsigned long base = mem->free_addr;
    
    for (int i = 0; i < count; i++) {
        if (ptrace(PTRACE_POKEDATA, mem->pid, base + i * sizeof(long), pointers[i]) == -1) {
            return 0;
        }
    }
    
    // Add NULL terminator
    if (ptrace(PTRACE_POKEDATA, mem->pid, base + count * sizeof(long), 0) == -1) {
        return 0;
    }
    
    mem->free_addr += (count + 1) * sizeof(long);
    return base;
}

// Build a new argv for the placeholder binary
// Format: placeholder --denied --original-cmd=<path> --original-arg1 --original-arg2 ...
static unsigned long build_placeholder_argv(ProcessMemory *mem, const char *original_path, 
                                          char **original_argv) {
    // Count original argc
    int orig_argc = 0;
    while (original_argv[orig_argc]) orig_argc++;
    
    // We'll build: placeholder, "--denied", "--cmd=<path>", [original args...]
    int new_argc = 3 + orig_argc;
    unsigned long *argv_ptrs = malloc(new_argc * sizeof(unsigned long));
    
    if (!argv_ptrs) return 0;
    
    // Build the command string
    char cmd_arg[1024];
    snprintf(cmd_arg, sizeof(cmd_arg), "--cmd=%s", original_path);
    
    // Write strings to memory and collect pointers
    argv_ptrs[0] = write_string(mem, PLACEHOLDER_BINARY);
    argv_ptrs[1] = write_string(mem, "--denied");
    argv_ptrs[2] = write_string(mem, cmd_arg);
    
    // Copy original arguments
    for (int i = 0; i < orig_argc; i++) {
        argv_ptrs[3 + i] = write_string(mem, original_argv[i]);
    }
    
    // Write the pointer array
    unsigned long argv_addr = write_pointer_array(mem, argv_ptrs, new_argc);
    
    free(argv_ptrs);
    return argv_addr;
}

// Your security policy check
static int is_command_allowed(const char *path, char *const argv[]) {
    // Implement your security policy here
    // Return 1 for allowed, 0 for denied
    
    // Example: Block commands with "unsafefile" in arguments
    for (int i = 0; argv[i] != NULL; i++) {
        if (strstr(argv[i], "unsafefile")) {
            fprintf(stderr, "Security: Blocking command with 'unsafefile' argument\n");
            return 0;
        }
    }
    
    // Example: Allow specific commands
    const char *allowed[] = {
        "/bin/ls", "/bin/cat", "/bin/echo", "/usr/bin/whoami",
        "/bin/bash", "/bin/sh", "/usr/bin/id", NULL
    };
    
    for (int i = 0; allowed[i]; i++) {
        if (strcmp(path, allowed[i]) == 0) {
            return 1;
        }
    }
    
    fprintf(stderr, "Security: Command not in allowed list: %s\n", path);
    return 0;
}

// Replace execve call with placeholder
static int replace_with_placeholder(pid_t pid, REGS *regs, 
                                   const char *original_path, 
                                   char **original_argv,
                                   char **original_envp) {
    ProcessMemory mem = { .pid = pid };
    
    // Find safe memory area (use stack with some margin)
    mem.free_addr = regs->STACK_POINTER - 4096;
    
    // Build new argv for placeholder
    unsigned long new_argv = build_placeholder_argv(&mem, original_path, original_argv);
    if (!new_argv) {
        fprintf(stderr, "Failed to build placeholder argv\n");
        return -1;
    }
    
    // Copy environment (keep original)
    int env_count = 0;
    while (original_envp[env_count]) env_count++;
    
    unsigned long *env_ptrs = malloc((env_count + 1) * sizeof(unsigned long));
    for (int i = 0; i < env_count; i++) {
        env_ptrs[i] = write_string(&mem, original_envp[i]);
    }
    unsigned long new_envp = write_pointer_array(&mem, env_ptrs, env_count);
    free(env_ptrs);
    
    if (!new_envp) {
        fprintf(stderr, "Failed to copy environment\n");
        return -1;
    }
    
    // Write the placeholder binary path
    unsigned long new_path = write_string(&mem, PLACEHOLDER_BINARY);
    if (!new_path) {
        fprintf(stderr, "Failed to write placeholder path\n");
        return -1;
    }
    
    // Update registers to point to new arguments
    regs->ARG1 = new_path;      // pathname
    regs->ARG2 = new_argv;      // argv
    regs->ARG3 = new_envp;      // envp
    
    // Apply the changes
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
        perror("ptrace(SETREGS)");
        return -1;
    }
    
    fprintf(stderr, "Security: Replaced denied exec with placeholder: %s\n", original_path);
    return 0;
}

// Handle execve syscall
static void handle_execve(pid_t pid, REGS *regs) {
    // Read execve arguments from traced process
    char *pathname = read_string(pid, (unsigned long)regs->ARG1);
    if (!pathname) {
        fprintf(stderr, "Failed to read pathname\n");
        return;
    }
    
    char **argv = read_string_array(pid, (unsigned long)regs->ARG2);
    char **envp = read_string_array(pid, (unsigned long)regs->ARG3);
    
    if (!argv || !envp) {
        fprintf(stderr, "Failed to read argv/envp\n");
        free(pathname);
        free(argv);
        free(envp);
        return;
    }
    
    // Check if command is allowed
    if (is_command_allowed(pathname, argv)) {
        // Allow the execve to proceed normally
        fprintf(stderr, "Security: Allowing exec: %s\n", pathname);
    } else {
        // Replace with placeholder binary
        if (replace_with_placeholder(pid, regs, pathname, argv, envp) != 0) {
            // If replacement fails, kill the process
            fprintf(stderr, "Security: Replacement failed, terminating process\n");
            kill(pid, SIGKILL);
        }
    }
    
    // Cleanup
    free(pathname);
    if (argv) {
        for (int i = 0; argv[i]; i++) free(argv[i]);
        free(argv);
    }
    if (envp) {
        for (int i = 0; envp[i]; i++) free(envp[i]);
        free(envp);
    }
}

// Main tracer loop
static void trace_process(pid_t pid) {
    int status;
    REGS regs;
    
    // Wait for child to stop after PTRACE_TRACEME
    waitpid(pid, &status, 0);
    
    // Set ptrace options
    ptrace(PTRACE_SETOPTIONS, pid, 0, 
           PTRACE_O_TRACESYSGOOD | 
           PTRACE_O_TRACEEXEC |
           PTRACE_O_TRACECLONE |
           PTRACE_O_TRACEFORK |
           PTRACE_O_TRACEVFORK);
    
    // Continue the child
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    
    while (1) {
        if (waitpid(pid, &status, 0) == -1) {
            break;
        }
        
        if (WIFEXITED(status)) {
            fprintf(stderr, "Child exited with status %d\n", WEXITSTATUS(status));
            break;
        }
        
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "Child terminated by signal %d\n", WTERMSIG(status));
            break;
        }
        
        // Check for syscall stop
        if (WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80)) {
            // Get registers
            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
                perror("ptrace(GETREGS)");
                break;
            }
            
            // Check for execve syscall
            if (regs.SYSNUM == SYSCALL_EXECVE) {
                handle_execve(pid, &regs);
            }
        }
        
        // Continue execution
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
    }
}

// Placeholder binary implementation
// Compile this separately: gcc -o placeholder placeholder.c
/*
// placeholder.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

int main(int argc, char *argv[]) {
    int show_denied = 0;
    char *original_cmd = NULL;
    
    // Parse arguments
    struct option long_options[] = {
        {"denied", no_argument, 0, 'd'},
        {"cmd", required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "dc:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'd':
                show_denied = 1;
                break;
            case 'c':
                original_cmd = optarg;
                break;
            default:
                break;
        }
    }
    
    // Output simulation
    if (show_denied) {
        // Print to stderr (simulating command error)
        fprintf(stderr, "Permission denied: Command '%s' blocked by security policy\n", 
                original_cmd ? original_cmd : "unknown");
        
        // Simulate successful command output on stdout
        // Could output nothing, or simulate expected output
        printf("# Security wrapper: Command was blocked\n");
        printf("# Original command: %s\n", original_cmd ? original_cmd : "unknown");
        
        // Return success exit code
        return 0;
    }
    
    // If not --denied, just do nothing and exit
    return 0;
}
*/

// Setup function to ensure placeholder exists
static int setup_placeholder() {
    // Check if placeholder exists
    if (access(PLACEHOLDER_BINARY, X_OK) == 0) {
        return 0;
    }
    
    // Create directory
    mkdir(PLACEHOLDER_DIR, 0755);
    
    // Create simple placeholder shell script
    char script_path[1024];
    snprintf(script_path, sizeof(script_path), "%s/placeholder.sh", PLACEHOLDER_DIR);
    
    FILE *f = fopen(script_path, "w");
    if (!f) {
        perror("Failed to create placeholder script");
        return -1;
    }
    
    fprintf(f, "#!/bin/bash\n");
    fprintf(f, "# Security wrapper placeholder\n");
    fprintf(f, "# Simulates successful command execution when real command is blocked\n");
    fprintf(f, "\n");
    fprintf(f, "if [[ \"$1\" == \"--denied\" ]]; then\n");
    fprintf(f, "    shift\n");
    fprintf(f, "    if [[ \"$1\" == --cmd=* ]]; then\n");
    fprintf(f, "        cmd=\"${1#--cmd=}\"\n");
    fprintf(f, "        shift\n");
    fprintf(f, "        echo \"Permission denied: Command '$cmd' blocked by security policy\" >&2\n");
    fprintf(f, "        # Output nothing to stdout (simulates empty output)\n");
    fprintf(f, "        # Or simulate expected output based on command\n");
    fprintf(f, "        case \"$cmd\" in\n");
    fprintf(f, "            */cat*)\n");
    fprintf(f, "                # cat would output file contents, we output nothing\n");
    fprintf(f, "                ;;\n");
    fprintf(f, "            */ls*)\n");
    fprintf(f, "                # ls would list files, output empty\n");
    fprintf(f, "                ;;\n");
    fprintf(f, "            *)\n");
    fprintf(f, "                # Generic success\n");
    fprintf(f, "                ;;\n");
    fprintf(f, "        esac\n");
    fprintf(f, "        exit 0\n");
    fprintf(f, "    fi\n");
    fprintf(f, "fi\n");
    fprintf(f, "\n");
    fprintf(f, "# Default: do nothing, exit successfully\n");
    fprintf(f, "exit 0\n");
    
    fclose(f);
    chmod(script_path, 0755);
    
    // Create symlink
    symlink(script_path, PLACEHOLDER_BINARY);
    
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        fprintf(stderr, "Example: %s /bin/cat /etc/passwd\n", argv[0]);
        return 1;
    }
    
    // Ensure placeholder exists
    if (setup_placeholder() != 0) {
        fprintf(stderr, "Failed to setup placeholder binary\n");
        return 1;
    }
    
    pid_t child = fork();
    if (child == -1) {
        perror("fork");
        return 1;
    }
    
    if (child == 0) {
        // Child process: ask to be traced
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        
        // Stop ourselves so parent can setup tracing
        kill(getpid(), SIGSTOP);
        
        // Execute the command (will be traced)
        execvp(argv[1], &argv[1]);
        
        // If execvp fails
        perror("execvp");
        return 1;
    } else {
        // Parent: trace the child
        trace_process(child);
        return 0;
    }
}
