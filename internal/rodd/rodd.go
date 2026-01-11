package rodd

import (
	"fmt"
	"regexp"
	"strings"
)

// Dangerous dd options that perform data operations
var dangerousDdOptions = map[string]bool{
	"if":     true, // Input file (dangerous if it's a device)
	"of":     true, // Output file (very dangerous - write operation)
	"bs":     true, // Block size
	"ibs":    true, // Input block size
	"obs":    true, // Output block size
	"cbs":    true, // Conversion block size
	"skip":   true, // Skip blocks
	"seek":   true, // Seek blocks
	"count":  true, // Copy only this many blocks
	"conv":   true, // Conversion options
	"status": true, // Status level
}

// Safe dd options that are informational only
var safeDdOptions = map[string]bool{
	"--help":    true, // Display help
	"--version": true, // Display version
}

// Dangerous patterns to detect in dd arguments
var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`>\s*[^\s]+`),                  // Output redirection >
	regexp.MustCompile(`>>\s*[^\s]+`),                 // Append redirection >>
	regexp.MustCompile(`\|\s*[^\s]+`),                 // Pipe |
	regexp.MustCompile(`\$\s*\([^)]+\)`),              // Command substitution $(...)
	regexp.MustCompile("`[^`]+`"),                     // Backtick command substitution
	regexp.MustCompile(`\$\s*\{[^}]+\}`),              // Variable expansion ${...}
	regexp.MustCompile(`\$\s*[A-Za-z_][A-Za-z0-9_]*`), // Simple variable $VAR
	regexp.MustCompile(`\s*;\s*`),                     // Command chaining with ;
	regexp.MustCompile(`\s*&&\s*`),                    // Command chaining with &&
	regexp.MustCompile(`\s*\|\|\s*`),                  // Command chaining with ||
	regexp.MustCompile(`&\s*$`),                       // Background process &
	regexp.MustCompile(`\s*&\s*`),                     // Background process &
}

// isDdParameter checks if a parameter looks like a dd parameter
func isDdParameter(param string) bool {
	// dd parameters are typically in format key=value
	if strings.Contains(param, "=") {
		parts := strings.SplitN(param, "=", 2)
		if len(parts) == 2 {
			key := parts[0]
			value := parts[1]

			// Check if it's a known dd parameter
			if dangerousDdOptions[key] {
				return true
			}

			// Check if value looks like a file path or device
			if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") {
				return true
			}
			if strings.Contains(value, "/dev/") || len(value) == 1 {
				return true // Device or single char (like /dev/sda)
			}
		}
	}
	return false
}

// IsDdOptionSafe checks if a dd option is safe for read-only operation
func IsDdOptionSafe(option string) (bool, string) {
	// Check if it's explicitly dangerous
	if dangerousDdOptions[option] {
		return false, "dangerous dd option"
	}

	// Check if it's explicitly safe
	if safeDdOptions[option] {
		return true, ""
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(option) {
			return false, "contains dangerous pattern"
		}
	}

	// Check if it looks like a dd parameter
	if isDdParameter(option) {
		return false, "dd parameter not allowed in read-only mode"
	}

	// If it's a flag we don't recognize, be conservative and block it
	if strings.HasPrefix(option, "-") {
		return false, "unknown dd option"
	}

	// For dd, any argument could be dangerous
	return false, "dd operation not allowed in read-only mode"
}

// IsDdSafe checks if dd arguments are safe for read-only operation
func IsDdSafe(args []string) (bool, string) {
	if len(args) == 0 {
		return false, "no arguments provided"
	}

	// dd requires parameters to be useful
	// In read-only mode, we only allow informational options

	for _, arg := range args {
		if safe, reason := IsDdOptionSafe(arg); !safe {
			return false, fmt.Sprintf("dd argument '%s' %s", arg, reason)
		}
	}

	// The only safe dd commands are help and version
	for _, arg := range args {
		if arg != "--help" && arg != "--version" {
			return false, "dd operation not allowed in read-only mode"
		}
	}

	return true, ""
}
