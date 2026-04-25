#ifndef COMMAND_UTILS_H
#define COMMAND_UTILS_H

#include <string>

struct CommandResult {
    std::string stdout = {};
    std::string stderr = {};
    int exit_code = 0;
};

// Run command with optional timeout (in seconds)
// timeout_secs <= 0 means no timeout
CommandResult runCommand(const std::string& cmd, int timeout_secs = 0);
std::string getToolsDir();

#endif // COMMAND_UTILS_H
