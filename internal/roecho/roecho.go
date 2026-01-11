package roecho

import (
	"strings"
)

// IsDangerousEchoOption checks if an echo option is dangerous
func IsDangerousEchoOption(arg string) (bool, string) {
	// Check for options that could be dangerous
	switch arg {
	case "--help", "--version":
		return false, "" // Safe informational options
	case "-n":
		return false, "" // Safe - no trailing newline
	case "-e":
		return false, "" // Safe - enable interpretation of backslash escapes
	case "-E":
		return false, "" // Safe - disable interpretation of backslash escapes
	}

	// Check for potential output redirection or dangerous patterns
	if strings.HasPrefix(arg, ">") || strings.HasPrefix(arg, ">>") || strings.HasPrefix(arg, "|") {
		return true, "appears to redirect output"
	}

	// Check for redirect patterns within the argument
	if strings.Contains(arg, ">") || strings.Contains(arg, "|") {
		return true, "appears to contain redirection"
	}

	// Check for command substitution patterns
	if strings.Contains(arg, "$") && strings.Contains(arg, "(") {
		return true, "appears to contain command substitution"
	}

	// Check for backticks (command substitution)
	if strings.Contains(arg, "`") {
		return true, "appears to contain command substitution"
	}

	// If it's a flag we don't recognize, be cautious but allow it
	if strings.HasPrefix(arg, "-") {
		return false, "unknown flag but likely safe"
	}

	// Regular arguments (text) are safe as long as they don't contain dangerous patterns
	return false, ""
}

// AreEchoArgsSafe checks if echo arguments are safe for read-only operation
func AreEchoArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousEchoOption(arg); dangerous {
			return false, reason
		}
	}
	return true, ""
}
