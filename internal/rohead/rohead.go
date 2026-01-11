package rohead

import (
	"strings"
)

// IsDangerousHeadOption checks if a head option is dangerous
func IsDangerousHeadOption(arg string) (bool, string) {
	// Check for options that could be dangerous
	switch arg {
	case "--help", "--version":
		return false, "" // Safe informational options
	case "-c", "--bytes":
		return false, "" // Safe - specify bytes
	case "-n", "--lines":
		return false, "" // Safe - specify lines
	case "-q", "--quiet", "--silent":
		return false, "" // Safe - quiet mode
	case "-v", "--verbose":
		return false, "" // Safe - verbose mode
	}

	// Check for potential output redirection or dangerous patterns
	if strings.HasPrefix(arg, ">") || strings.HasPrefix(arg, ">>") || strings.HasPrefix(arg, "|") {
		return true, "appears to redirect output"
	}

	// Check for redirect patterns within the argument
	if strings.Contains(arg, ">") || strings.Contains(arg, "|") {
		return true, "appears to contain redirection"
	}

	// If it's a flag we don't recognize, be cautious but allow it
	// Most head flags are safe (read-only by nature)
	if strings.HasPrefix(arg, "-") {
		return false, "unknown flag but likely safe"
	}

	// Regular arguments (files) are safe
	return false, ""
}

// AreHeadArgsSafe checks if head arguments are safe for read-only operation
func AreHeadArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousHeadOption(arg); dangerous {
			return false, reason
		}
	}
	return true, ""
}
