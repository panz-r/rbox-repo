package rodu

import (
	"strings"
)

// IsDangerousDuOption checks if a du option is dangerous
// du is generally read-only, but some options could be problematic
func IsDangerousDuOption(arg string) (bool, string) {
	// Check for options that might be problematic in certain contexts
	switch arg {
	case "--help", "--version", "-h", "-V":
		// These are safe informational options
		return false, ""
	case "-a", "--all":
		// Show all files - safe
		return false, ""
	case "-s", "--summarize":
		// Summarize - safe
		return false, ""
	case "-k", "-m", "-g":
		// Size formatting options - safe
		return false, ""
	case "-d", "--max-depth":
		// Max depth - safe
		return false, ""
	case "-c", "--total":
		// Show total - safe
		return false, ""
	case "--human-readable":
		// Human readable - safe
		return false, ""
	case "--si":
		// SI units - safe
		return false, ""
	case "--apparent-size":
		// Apparent size - safe
		return false, ""
	case "--block-size":
		// Block size - safe
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
		// Most du options are safe
		return false, ""
	}

	// Filesystem paths are generally safe for du
	return false, ""
}

// AreDuArgsSafe checks if du arguments are safe for read-only operation
func AreDuArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousDuOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}