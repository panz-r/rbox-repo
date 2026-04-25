// ============================================================================
// Command Utilities - Command execution helpers
// ============================================================================

#include "command_utils.h"
#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <libgen.h>
#include <signal.h>
#include <sys/wait.h>

CommandResult runCommand(const std::string& cmd, int timeout_secs) {
    CommandResult result;
    result.exit_code = 0;
    
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        result.exit_code = -1;
        return result;
    }
    
    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        result.exit_code = -1;
        return result;
    }
    
    if (pid == 0) {
        // Child process
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        
        // Set up timeout alarm
        if (timeout_secs > 0) {
            alarm(timeout_secs);
        }
        
        execl("/bin/bash", "bash", "-c", cmd.c_str(), (char*)nullptr);
        _exit(127);
    }
    
    // Parent process
    close(pipefd[1]);
    
    char buf[256];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        result.stdout += buf;
    }
    close(pipefd[0]);
    
    // Wait with timeout
    int status;
    int wait_ret;
    if (timeout_secs > 0) {
        // Use alarm-based timeout
        alarm(timeout_secs);
        wait_ret = waitpid(pid, &status, 0);
        alarm(0);  // Cancel any remaining alarm
    } else {
        wait_ret = waitpid(pid, &status, 0);
    }
    
    if (wait_ret == -1) {
        result.exit_code = -1;
    } else if (WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result.exit_code = 128 + WTERMSIG(status);
        result.stdout += "\n[TIMEOUT or SIGNAL]\n";
    } else {
        result.exit_code = -1;
    }
    
    return result;
}

std::string getToolsDir() {
    char exe_path[4096];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len != -1) {
        exe_path[len] = '\0';
        std::string exe_dir = dirname(exe_path);
        if (exe_dir.find("testgen") != std::string::npos) {
            return exe_dir + "/../tools";
        }
        return exe_dir + "/tools";
    }
    return "./tools";
}
