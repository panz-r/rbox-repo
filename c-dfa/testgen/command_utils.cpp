// ============================================================================
// Command Utilities - Command execution helpers
// ============================================================================

#include "command_utils.h"
#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

CommandResult runCommand(const std::string& cmd) {
    CommandResult result;
    result.exit_code = 0;
    
    FILE* fp = popen((cmd + " 2>&1").c_str(), "r");
    if (!fp) {
        result.exit_code = -1;
        return result;
    }
    
    char buf[256];
    while (fgets(buf, sizeof(buf), fp) != nullptr) {
        result.stdout += buf;
    }
    
    int status = pclose(fp);
    if (WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    } else {
        result.exit_code = -1;
    }
    
    return result;
}
