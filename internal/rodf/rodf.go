package rodf

import (
	"strings"
)

// IsDangerousDfOption checks if a df option is dangerous
// df is generally read-only, but some options could be problematic
func IsDangerousDfOption(arg string) (bool, string) {
	// Check for options that might be problematic in certain contexts
	switch arg {
	case "--help", "--version", "-h", "-V":
		// These are safe informational options
		return false, ""
	case "-a", "--all":
		// Show all filesystems - safe
		return false, ""
	case "-i", "--inodes":
		// Show inode information - safe
		return false, ""
	case "-k", "-m", "-g", "-T":
		// Size formatting options - safe
		return false, ""
	case "-t", "--type":
		// Filter by filesystem type - safe
		return false, ""
	case "-x", "--exclude-type":
		// Exclude filesystem type - safe
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
		// Most df options are safe
		return false, ""
	}

	// Filesystem paths are generally safe for df
	return false, ""
}

// AreDfArgsSafe checks if df arguments are safe for read-only operation
func AreDfArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousDfOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}