package rogit

import (
	"strings"
)

// List of git commands that are considered write operations
var writeCommands = map[string]bool{
	"add": true, "am": true, "apply": true, "archive": true, "bisect": true,
	"branch": true, "bundle": true, "checkout": true, "cherry-pick": true,
	"clean": true, "clone": true, "commit": true, "fetch": true,
	"format-patch": true, "gc": true, "init": true, "merge": true,
	"mv": true, "notes": true, "pull": true, "push": true, "rebase": true,
	"reflog": true, "remote": true, "repair": true, "replace": true,
	"request-pull": true, "reset": true, "restore": true, "revert": true,
	"rm": true, "send-email": true, "stash": true, "submodule": true,
	"switch": true, "tag": true, "worktree": true, "write-tree": true,
}

// IsWriteCommand checks if a git command is a write operation
func IsWriteCommand(command string) bool {
	return writeCommands[command]
}

// IsConfigWriteOperation checks if git config command is a write operation
func IsConfigWriteOperation(args []string) bool {
	// Check if this is a write operation (setting config)
	if len(args) >= 1 && !strings.HasPrefix(args[0], "--") {
		// If first arg doesn't start with --, it might be a config set operation
		if len(args) >= 2 {
			// config <name> <value> is a write operation
			return true
		}
	}
	// Check for write flags
	for _, arg := range args {
		if arg == "--replace-all" || arg == "--add" || arg == "--unset" || arg == "--unset-all" {
			return true
		}
	}
	return false
}

// IsAllowedCommand checks if a git command and its arguments are allowed in read-only mode
func IsAllowedCommand(command string, args []string) (bool, string) {
	// Check if the command is in our write commands list
	if IsWriteCommand(command) {
		return false, "write operation not allowed"
	}

	// Additional checks for commands that could write with certain flags
	switch command {
	case "config":
		if IsConfigWriteOperation(args) {
			return false, "config modification not allowed"
		}
	}

	return true, ""
}
