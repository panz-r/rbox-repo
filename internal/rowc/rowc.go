package rowc

import (
	"strings"
)

// IsDangerousWcOption checks if a wc option is dangerous
// wc is generally read-only, but some options could be problematic
func IsDangerousWcOption(arg string) (bool, string) {
	// Check for options that might be problematic in certain contexts
	switch arg {
	case "--help", "--version", "-h", "-V":
		// These are safe informational options
		return false, ""
	case "-c", "--bytes":
		// Count bytes - safe
		return false, ""
	case "-m", "--chars":
		// Count characters - safe
		return false, ""
	case "-l", "--lines":
		// Count lines - safe
		return false, ""
	case "-w", "--words":
		// Count words - safe
		return false, ""
	case "-L", "--max-line-length":
		// Max line length - safe
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
		// Most wc options are safe
		return false, ""
	}

	// File paths are generally safe for wc
	return false, ""
}

// AreWcArgsSafe checks if wc arguments are safe for read-only operation
func AreWcArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousWcOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}