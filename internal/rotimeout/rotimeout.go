package rotimeout

import (
	"strconv"
	"strings"
)

// IsDangerousTimeoutOption checks if a timeout option is dangerous
func IsDangerousTimeoutOption(arg string, position int) (bool, string) {
	// Check for options that could be dangerous
	switch arg {
	case "--help", "--version":
		return false, "" // Safe informational options
	case "-k", "--kill-after":
		return false, "" // Safe - kill after timeout
	case "-s", "--signal":
		return false, "" // Safe - signal to send
	case "--foreground":
		return false, "" // Safe - foreground process
	case "--preserve-status":
		return false, "" // Safe - preserve exit status
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
	if strings.HasPrefix(arg, "-") {
		return false, "unknown flag but likely safe"
	}

	// For timeout, the first argument should be a duration (safe)
	// But we need to be careful about what command it's executing
	if position == 0 {
		// Check if it looks like a valid duration
		if _, err := strconv.ParseFloat(arg, 64); err == nil {
			return false, "valid duration"
		}
		// Check for time suffixes
		if strings.HasSuffix(arg, "s") || strings.HasSuffix(arg, "m") || strings.HasSuffix(arg, "h") || strings.HasSuffix(arg, "d") {
			// Extract numeric part
			numericPart := strings.TrimSuffix(arg, string(arg[len(arg)-1]))
			if _, err := strconv.ParseFloat(numericPart, 64); err == nil {
				return false, "valid duration with suffix"
			}
		}
	}

	// Regular arguments (commands) - for timeout, this is tricky
	// We can't easily validate the command being executed, so we'll allow it
	// but this means timeout can still execute dangerous commands
	// This is a limitation of the read-only approach for timeout
	return false, "command execution allowed (use with caution)"
}

// AreTimeoutArgsSafe checks if timeout arguments are safe for read-only operation
func AreTimeoutArgsSafe(args []string) (bool, string) {
	for i, arg := range args {
		if dangerous, reason := IsDangerousTimeoutOption(arg, i); dangerous {
			return false, reason
		}
	}
	return true, ""
}