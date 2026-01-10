package rofind

import (
	"strings"
)

// IsDangerousFindOption checks if a find option is dangerous (can execute or delete)
func IsDangerousFindOption(arg string, nextArg string) (bool, string) {
	// Check for options that can execute commands
	switch arg {
	case "-exec", "-execdir", "-ok", "-okdir":
		return true, "can execute commands"
	case "-delete":
		return true, "can delete files"
	case "-printf", "-fprintf":
		// Check if next argument indicates file writing
		if strings.HasPrefix(nextArg, ">") {
			return true, "appears to write to a file"
		}
		return false, ""
	}

	return false, ""
}

// AreFindArgsSafe checks if find arguments are safe for read-only operation
func AreFindArgsSafe(args []string) (bool, string) {
	for i, arg := range args {
		// Get next arg if available, empty string otherwise
		nextArg := ""
		if i+1 < len(args) {
			nextArg = args[i+1]
		}

		if dangerous, reason := IsDangerousFindOption(arg, nextArg); dangerous {
			return false, reason
		}
	}

	return true, ""
}