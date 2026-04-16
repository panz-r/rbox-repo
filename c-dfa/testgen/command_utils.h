#ifndef COMMAND_UTILS_H
#define COMMAND_UTILS_H

#include <string>

struct CommandResult {
    std::string stdout = {};
    std::string stderr = {};
    int exit_code = 0;
};

CommandResult runCommand(const std::string& cmd);
std::string getToolsDir();

#endif // COMMAND_UTILS_H
