package rotail

import (
	"strings"
)

// IsDangerousTailOption checks if a tail option is dangerous
func IsDangerousTailOption(arg string) (bool, string) {
	// Check for options that could be dangerous
	switch arg {
	case "--help", "--version":
		return false, "" // Safe informational options
	case "-c", "--bytes":
		return false, "" // Safe - specify bytes
	case "-n", "--lines":
		return false, "" // Safe - specify lines
	case "-f", "--follow":
		return false, "" // Safe - follow mode (read-only)
	case "-F":
		return false, "" // Safe - follow with retry
	case "-q", "--quiet", "--silent":
		return false, "" // Safe - quiet mode
	case "-v", "--verbose":
		return false, "" // Safe - verbose mode
	case "--retry":
		return false, "" // Safe - retry if file doesn't exist
	case "--max-unchanged-stats":
		return false, "" // Safe - max unchanged stats
	case "--pid":
		return false, "" // Safe - process ID to monitor
	case "-s", "--sleep-interval":
		return false, "" // Safe - sleep interval
	}

	// Check for potential output redirection or dangerous patterns
	if strings.HasPrefix(arg, ">") || strings.HasPrefix(arg, ">>") || strings.HasPrefix(arg, "|") {
		return true, "appears to redirect output"
	}

	// Check for redirect patterns within the argument
	if strings.Contains(arg, ">") || strings.Contains(arg, "|") {
		return true, "appears to contain redirection"
	}

	// If it's a flag we don't recognize, be cautious but allow it
	// Most tail flags are safe (read-only by nature)
	if strings.HasPrefix(arg, "-") {
		return false, "unknown flag but likely safe"
	}

	// Regular arguments (files) are safe
	return false, ""
}

// AreTailArgsSafe checks if tail arguments are safe for read-only operation
func AreTailArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousTailOption(arg); dangerous {
			return false, reason
		}
	}
	return true, ""
}
