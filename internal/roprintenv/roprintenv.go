package roprintenv

import (
	"strings"
)

// IsDangerousPrintenvOption checks if a printenv option is dangerous
// printenv is generally read-only, but some options could be problematic
func IsDangerousPrintenvOption(arg string) (bool, string) {
	// Check for options that might be problematic in certain contexts
	switch arg {
	case "--help", "--version", "-h", "-V":
		// These are safe informational options
		return false, ""
	case "-0", "--null":
		// Null delimiter - safe
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
		// Most printenv options are safe
		return false, ""
	}

	// Environment variable names are generally safe
	// but let's validate them
	if len(arg) > 0 {
		// Check for valid environment variable name characters
		for i, c := range arg {
			if i == 0 && (c >= '0' && c <= '9') {
				// First character can't be a digit
				return true, "invalid environment variable name"
			}
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '_') {
				return true, "invalid environment variable name"
			}
		}
	}

	return false, ""
}

// ArePrintenvArgsSafe checks if printenv arguments are safe for read-only operation
func ArePrintenvArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousPrintenvOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}