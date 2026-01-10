package rodate

import (
	"strings"
)

// IsDangerousDateOption checks if a date option is dangerous
func IsDangerousDateOption(arg string) (bool, string) {
	// Check for options that could be dangerous
	switch arg {
	case "--help", "--version":
		return false, "" // Safe informational options
	case "-u", "--utc", "--universal":
		return false, "" // Safe - UTC time
	case "-R", "--rfc-2822":
		return false, "" // Safe - RFC 2822 format
	case "--rfc-3339":
		return false, "" // Safe - RFC 3339 format
	case "--rfc-email":
		return false, "" // Safe - RFC 5322 format
	case "--rfc-3339ns":
		return false, "" // Safe - RFC 3339 with nanoseconds
	case "--iso-8601":
		return false, "" // Safe - ISO 8601 format
	case "-r", "--reference":
		return false, "" // Safe - reference file
	case "-d", "--date":
		return false, "" // Safe - display time described by STRING
	case "-f", "--file":
		return false, "" // Safe - like --date once for each line of FILE
	case "--debug":
		return false, "" // Safe - debug output
	}

	// Check for potential output redirection or dangerous patterns
	if strings.HasPrefix(arg, ">") || strings.HasPrefix(arg, ">>") || strings.HasPrefix(arg, "|") {
		return true, "appears to redirect output"
	}

	// Check for redirect patterns within the argument
	if strings.Contains(arg, ">") || strings.Contains(arg, "|") {
		return true, "appears to contain redirection"
	}

	// Check for command substitution patterns
	if strings.Contains(arg, "$") && strings.Contains(arg, "(") {
		return true, "appears to contain command substitution"
	}

	// Check for backticks (command substitution)
	if strings.Contains(arg, "`") {
		return true, "appears to contain command substitution"
	}

	// If it's a flag we don't recognize, be cautious but allow it
	if strings.HasPrefix(arg, "-") {
		return false, "unknown flag but likely safe"
	}

	// Regular arguments (format strings, files) are safe
	return false, ""
}

// AreDateArgsSafe checks if date arguments are safe for read-only operation
func AreDateArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousDateOption(arg); dangerous {
			return false, reason
		}
	}
	return true, ""
}