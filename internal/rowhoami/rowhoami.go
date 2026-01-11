package rowhoami

import (
	"strings"
)

// IsDangerousWhoamiOption checks if a whoami option is dangerous
// whoami is generally read-only, but some options could be problematic
func IsDangerousWhoamiOption(arg string) (bool, string) {
	// Check for options that might be problematic in certain contexts
	switch arg {
	case "--help", "--version", "-h", "-V":
		// These are safe informational options
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
		// Most whoami options are safe
		return false, ""
	}

	// whoami generally doesn't take non-option arguments
	return false, ""
}

// AreWhoamiArgsSafe checks if whoami arguments are safe for read-only operation
func AreWhoamiArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousWhoamiOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}