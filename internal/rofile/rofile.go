package rofile

import (
	"strings"
)

// IsDangerousFileOption checks if a file option is dangerous
// file is generally read-only, but some options could be problematic
func IsDangerousFileOption(arg string) (bool, string) {
	// Check for options that might be problematic in certain contexts
	switch arg {
	case "--help", "--version", "-h", "-V":
		// These are safe informational options
		return false, ""
	case "-b", "--brief":
		// Brief mode - safe
		return false, ""
	case "-i", "--mime":
		// MIME type - safe
		return false, ""
	case "-z", "--uncompress":
		// Uncompress - safe (read-only)
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
		// Most file options are safe
		return false, ""
	}

	// File paths are generally safe for file
	return false, ""
}

// AreFileArgsSafe checks if file arguments are safe for read-only operation
func AreFileArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousFileOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}