package rostat

import (
	"strings"
)

// IsDangerousStatOption checks if a stat option is dangerous
// stat is generally read-only, but some options could be problematic
func IsDangerousStatOption(arg string) (bool, string) {
	// Check for options that might be problematic in certain contexts
	switch arg {
	case "--help", "--version", "-h", "-V":
		// These are safe informational options
		return false, ""
	case "-c", "--format":
		// Format specification - safe
		return false, ""
	case "-t", "--ters":
		// Terse format - safe
		return false, ""
	case "-f":
		// Filesystem info - safe
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
		// Most stat options are safe
		return false, ""
	}

	// File paths are generally safe for stat
	return false, ""
}

// AreStatArgsSafe checks if stat arguments are safe for read-only operation
func AreStatArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousStatOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}