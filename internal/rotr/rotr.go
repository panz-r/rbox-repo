package rotr

import (
	"strings"
)

// IsDangerousTrOption checks if a tr option is dangerous
// tr is generally read-only, but some options could be problematic
func IsDangerousTrOption(arg string) (bool, string) {
	// Check for options that might be problematic in certain contexts
	switch arg {
	case "--help", "--version", "-h", "-V":
		// These are safe informational options
		return false, ""
	case "-c", "--complement":
		// Complement - safe
		return false, ""
	case "-d", "--delete":
		// Delete - safe (only affects stdin/stdout)
		return false, ""
	case "-s", "--squeeze-repeats":
		// Squeeze repeats - safe
		return false, ""
	case "-t", "--truncate-set1":
		// Truncate set1 - safe
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
		// Most tr options are safe
		return false, ""
	}

	// Character sets are generally safe for tr
	return false, ""
}

// AreTrArgsSafe checks if tr arguments are safe for read-only operation
func AreTrArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousTrOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}