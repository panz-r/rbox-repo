package roman

import (
	"strings"
)

// IsDangerousManOption checks if a man option is dangerous
// man is generally read-only, but some options could be problematic
func IsDangerousManOption(arg string) (bool, string) {
	// Check for options that might be problematic in certain contexts
	switch arg {
	case "--help", "--version", "-h", "-V":
		// These are safe informational options
		return false, ""
	case "-k", "--apropos":
		// Apropos - safe
		return false, ""
	case "-f", "--whatis":
		// Whatis - safe
		return false, ""
	case "-P", "--pager":
		// Pager specification - we control this to be safe
		return false, ""
	case "--local-file":
		// Local file - safe
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
		// Most man options are safe
		return false, ""
	}

	// Manual page names are generally safe
	return false, ""
}

// AreManArgsSafe checks if man arguments are safe for read-only operation
func AreManArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousManOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}