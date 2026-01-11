package rops

import (
	"strings"
)

// IsDangerousPsOption checks if a ps option is dangerous
// ps is generally read-only, but some options could be problematic
func IsDangerousPsOption(arg string) (bool, string) {
	// Check for options that might be problematic in certain contexts
	switch arg {
	case "--format", "-o", "-f":
		// These are generally safe, but we should be cautious
		return false, ""
	case "--sort", "--no-headers", "--headers":
		// These are safe formatting options
		return false, ""
	}

	// Check for suspiciously long arguments first (regardless of prefix)
	if len(arg) >= 50 {
		return true, "suspiciously long option"
	}

	// Check for any suspicious patterns that might indicate
	// command injection or other dangerous behavior
	if strings.Contains(arg, "`") || strings.Contains(arg, "$") {
		return true, "contains potential command injection characters"
	}

	if strings.HasPrefix(arg, "--") || strings.HasPrefix(arg, "-") {
		// Most ps options are safe
		return false, ""
	}

	return false, ""
}

// ArePsArgsSafe checks if ps arguments are safe for read-only operation
func ArePsArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousPsOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}