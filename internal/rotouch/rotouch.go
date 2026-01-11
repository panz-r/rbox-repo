package rotouch

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Dangerous touch options that modify files
var dangerousTouchOptions = map[string]bool{
	"-a": true, "--time=atime": true, "--time=access": true, // Change only access time
	"-c": true, "--no-create": true, // Don't create files
	"-d": true,                                              // Use specific date/time
	"-f": true,                                              // (Ignored, for compatibility)
	"-m": true, "--time=mtime": true, "--time=modify": true, // Change only modification time
	"-r": true, "--reference": true, // Use reference file's time
	"-t":     true, // Use [[CC]YY]MMDDhhmm[.ss] format
	"--time": true, // Change specific timestamp
}

// Safe touch options that are informational only
var safeTouchOptions = map[string]bool{
	"--help":    true, // Display help
	"--version": true, // Display version
}

// Dangerous patterns to detect in touch arguments
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

// isDateFormat checks if a string looks like a date format
func isDateFormat(arg string) bool {
	// Check for common date formats
	if strings.Contains(arg, "-") || strings.Contains(arg, "/") || strings.Contains(arg, ":") {
		// Try to parse as a date
		_, err := time.Parse(time.RFC3339, arg)
		if err == nil {
			return true
		}
		// Try other common formats
		_, err = time.Parse("2006-01-02", arg)
		if err == nil {
			return true
		}
		_, err = time.Parse("01/02/2006", arg)
		if err == nil {
			return true
		}
		_, err = time.Parse("2006-01-02 15:04:05", arg)
		if err == nil {
			return true
		}
	}
	return false
}

// IsTouchOptionSafe checks if a touch option is safe for read-only operation
func IsTouchOptionSafe(option string) (bool, string) {
	// Check if it's explicitly dangerous
	if dangerousTouchOptions[option] {
		return false, "dangerous touch option"
	}

	// Check if it's explicitly safe
	if safeTouchOptions[option] {
		return true, ""
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(option) {
			return false, "contains dangerous pattern"
		}
	}

	// Check if it looks like a date format
	if isDateFormat(option) {
		return false, "date specification not allowed in read-only mode"
	}

	// If it's a flag we don't recognize, be conservative and block it
	if strings.HasPrefix(option, "-") {
		return false, "unknown touch option"
	}

	// For touch, non-option arguments are files to create/modify
	// In read-only mode, we block any file creation/modification attempts
	return false, "file creation/modification not allowed in read-only mode"
}

// IsTouchSafe checks if touch arguments are safe for read-only operation
func IsTouchSafe(args []string) (bool, string) {
	if len(args) == 0 {
		return false, "no arguments provided"
	}

	// touch requires at least a filename
	// In read-only mode, we only allow informational options

	for _, arg := range args {
		if safe, reason := IsTouchOptionSafe(arg); !safe {
			// Special case: if it's a file name (not an option), we can give a more specific message
			if !strings.HasPrefix(arg, "-") {
				return false, fmt.Sprintf("file creation/modification '%s' not allowed in read-only mode", arg)
			}
			return false, fmt.Sprintf("touch argument '%s' %s", arg, reason)
		}
	}

	// The only safe touch commands are help and version
	for _, arg := range args {
		if arg != "--help" && arg != "--version" {
			return false, "touch file creation/modification not allowed in read-only mode"
		}
	}

	return true, ""
}
