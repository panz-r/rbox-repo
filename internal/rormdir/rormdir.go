package rormdir

import (
	"fmt"
	"regexp"
	"strings"
)

// Dangerous rmdir options (there are very few options for rmdir)
var dangerousRmdirOptions = map[string]bool{
	"-p": true, "--parents": true, // Remove parent directories as well
	"-v": true, "--verbose": true, // Verbose output
	"--ignore-fail-on-non-empty": true, // Ignore non-empty directory errors
}

// Safe rmdir options that are informational only
var safeRmdirOptions = map[string]bool{
	"--help":    true, // Display help
	"--version": true, // Display version
}

// Dangerous patterns to detect in rmdir arguments
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

// IsRmdirOptionSafe checks if a rmdir option is safe for read-only operation
func IsRmdirOptionSafe(option string) (bool, string) {
	// Check if it's explicitly dangerous
	if dangerousRmdirOptions[option] {
		return false, "dangerous rmdir option"
	}

	// Check if it's explicitly safe
	if safeRmdirOptions[option] {
		return true, ""
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(option) {
			return false, "contains dangerous pattern"
		}
	}

	// If it's a flag we don't recognize, be conservative and block it
	if strings.HasPrefix(option, "-") {
		return false, "unknown rmdir option"
	}

	// For rmdir, non-option arguments are directory names to remove
	// In read-only mode, we block any directory removal attempts
	return false, "directory removal not allowed in read-only mode"
}

// IsRmdirSafe checks if rmdir arguments are safe for read-only operation
func IsRmdirSafe(args []string) (bool, string) {
	if len(args) == 0 {
		return false, "no arguments provided"
	}

	// rmdir requires at least a directory name
	// In read-only mode, we only allow informational options

	for _, arg := range args {
		if safe, reason := IsRmdirOptionSafe(arg); !safe {
			// Special case: if it's a directory name (not an option), we can give a more specific message
			if !strings.HasPrefix(arg, "-") {
				return false, fmt.Sprintf("directory removal '%s' not allowed in read-only mode", arg)
			}
			return false, fmt.Sprintf("rmdir argument '%s' %s", arg, reason)
		}
	}

	// The only safe rmdir commands are help and version
	for _, arg := range args {
		if arg != "--help" && arg != "--version" {
			return false, "rmdir directory removal not allowed in read-only mode"
		}
	}

	return true, ""
}
