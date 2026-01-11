package roexpr

import (
	"strings"
)

// IsDangerousExprOption checks if a expr option is dangerous
// expr can be dangerous if it executes commands, so we need to be careful
func IsDangerousExprOption(arg string) (bool, string) {
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
		// Most expr options are safe
		return false, ""
	}

	// expr arguments can be expressions, but we need to be cautious
	// Block certain dangerous patterns
	if strings.Contains(arg, ";") || strings.Contains(arg, "&&") || strings.Contains(arg, "||") {
		return true, "contains potential command chaining"
	}

	return false, ""
}

// AreExprArgsSafe checks if expr arguments are safe for read-only operation
func AreExprArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousExprOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}