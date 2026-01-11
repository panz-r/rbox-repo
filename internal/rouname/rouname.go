package rouname

import (
	"strings"
)

// IsDangerousUnameOption checks if a uname option is dangerous
// uname is generally read-only, but some options could be problematic
func IsDangerousUnameOption(arg string) (bool, string) {
	// Check for options that might be problematic in certain contexts
	switch arg {
	case "--help", "--version", "-h", "-V":
		// These are safe informational options
		return false, ""
	case "-a", "--all":
		// Show all information - safe
		return false, ""
	case "-s", "--kernel-name":
		// Kernel name - safe
		return false, ""
	case "-n", "--nodename":
		// Node name - safe
		return false, ""
	case "-r", "--kernel-release":
		// Kernel release - safe
		return false, ""
	case "-v", "--kernel-version":
		// Kernel version - safe
		return false, ""
	case "-m", "--machine":
		// Machine hardware - safe
		return false, ""
	case "-p", "--processor":
		// Processor type - safe
		return false, ""
	case "-i", "--hardware-platform":
		// Hardware platform - safe
		return false, ""
	case "-o", "--operating-system":
		// Operating system - safe
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
		// Most uname options are safe
		return false, ""
	}

	return false, ""
}

// AreUnameArgsSafe checks if uname arguments are safe for read-only operation
func AreUnameArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousUnameOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}