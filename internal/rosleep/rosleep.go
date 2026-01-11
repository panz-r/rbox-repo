package rosleep

import (
	"strings"
	"strconv"
)

// IsDangerousSleepOption checks if a sleep option is dangerous
// sleep is generally read-only, but some options could be problematic
func IsDangerousSleepOption(arg string) (bool, string) {
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
		// Most sleep options are safe
		return false, ""
	}

	// Check if it's a duration argument
	// Sleep durations should be reasonable numbers
	if !strings.HasPrefix(arg, "-") {
		// Try to parse as number
		if _, err := strconv.ParseFloat(arg, 64); err != nil {
			// Check if it's a suffix format (e.g., 1s, 2m, 3h)
			if !strings.HasSuffix(arg, "s") && !strings.HasSuffix(arg, "m") &&
			   !strings.HasSuffix(arg, "h") && !strings.HasSuffix(arg, "d") {
				return true, "invalid sleep duration format"
			}
		}

		// Check for reasonable duration (block extremely long sleeps)
		// Parse the numeric part
		var durationStr string
		if strings.HasSuffix(arg, "s") || strings.HasSuffix(arg, "m") ||
		   strings.HasSuffix(arg, "h") || strings.HasSuffix(arg, "d") {
			durationStr = arg[:len(arg)-1]
		} else {
			durationStr = arg
		}

		if duration, err := strconv.ParseFloat(durationStr, 64); err == nil {
			// Block sleeps longer than 1 hour (3600 seconds)
			// This prevents accidental long sleeps in scripts
			if duration > 3600 {
				return true, "sleep duration too long (max 1 hour)"
			}
		}
	}

	return false, ""
}

// AreSleepArgsSafe checks if sleep arguments are safe for read-only operation
func AreSleepArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousSleepOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}