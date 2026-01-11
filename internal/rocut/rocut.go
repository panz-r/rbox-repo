package rocut

import (
	"strings"
)

// IsDangerousCutOption checks if a cut option is dangerous
// cut is generally read-only, but some options could be problematic
func IsDangerousCutOption(arg string) (bool, string) {
	// Check for options that might be problematic in certain contexts
	switch arg {
	case "--help", "--version", "-h", "-V":
		// These are safe informational options
		return false, ""
	case "-b", "--bytes":
		// Bytes - safe
		return false, ""
	case "-c", "--characters":
		// Characters - safe
		return false, ""
	case "-f", "--fields":
		// Fields - safe
		return false, ""
	case "-d", "--delimiter":
		// Delimiter - safe
		return false, ""
	case "-s", "--only-delimited":
		// Only delimited - safe
		return false, ""
	case "--complement":
		// Complement - safe
		return false, ""
	case "--output-delimiter":
		// Output delimiter - safe
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
		// Most cut options are safe
		return false, ""
	}

	// File paths and delimiters are generally safe for cut
	return false, ""
}

// AreCutArgsSafe checks if cut arguments are safe for read-only operation
func AreCutArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousCutOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}