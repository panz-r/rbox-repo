package rodiff

import (
	"strings"
)

// IsDangerousDiffOption checks if a diff option is dangerous
// diff is generally read-only, but some options could be problematic
func IsDangerousDiffOption(arg string) (bool, string) {
	// Check for options that might be problematic in certain contexts
	switch arg {
	case "--help", "--version", "-h", "-V":
		// These are safe informational options
		return false, ""
	case "-q", "--brief":
		// Brief output - safe
		return false, ""
	case "-i", "--ignore-case":
		// Ignore case - safe
		return false, ""
	case "-w", "--ignore-all-space":
		// Ignore whitespace - safe
		return false, ""
	case "-b", "--ignore-space-change":
		// Ignore space changes - safe
		return false, ""
	case "-B", "--ignore-blank-lines":
		// Ignore blank lines - safe
		return false, ""
	case "-y", "--side-by-side":
		// Side by side - safe
		return false, ""
	case "-W", "--width":
		// Width specification - safe
		return false, ""
	case "--color", "--colour":
		// Color output - safe
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
		// Most diff options are safe
		return false, ""
	}

	// File paths are generally safe for diff
	return false, ""
}

// AreDiffArgsSafe checks if diff arguments are safe for read-only operation
func AreDiffArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousDiffOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}