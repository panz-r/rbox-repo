package ropwd

import (
	"strings"
)

// IsDangerousPwdOption checks if a pwd option is dangerous
// pwd is generally read-only, but some options could be problematic
func IsDangerousPwdOption(arg string) (bool, string) {
	// Check for options that might be problematic in certain contexts
	switch arg {
	case "--help", "--version", "-h", "-V":
		// These are safe informational options
		return false, ""
	case "-L", "--logical":
		// Logical path - safe
		return false, ""
	case "-P", "--physical":
		// Physical path - safe
		return false, ""
	}

	// Check for any suspicious patterns that might indicate
	// command injection or other dangerous behavior
	if strings.Contains(arg, "`") || strings.Contains(arg, "$") {
		return true, "contains potential command injection characters"
	}

	// Check for suspiciously long arguments (regardless of prefix)
	if len(arg) >= 50 {
		return true, "suspiciously long option"
	}

	if strings.HasPrefix(arg, "--") || strings.HasPrefix(arg, "-") {
		// Most pwd options are safe
		return false, ""
	}

	// pwd generally doesn't take non-option arguments
	// but if provided, they should be safe
	return false, ""
}

// ArePwdArgsSafe checks if pwd arguments are safe for read-only operation
func ArePwdArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousPwdOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}