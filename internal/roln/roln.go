package roln

import (
	"fmt"
	"regexp"
	"strings"
)

// Dangerous ln options that create links
var dangerousLnOptions = map[string]bool{
	"-s": true, "--symbolic": true, // Create symbolic links
	"-f": true, "--force": true, // Remove existing destination files
	"-i": true, "--interactive": true, // Prompt before removing
	"-n": true, "--no-dereference": true, // Treat destination as normal file
	"-b": true, "--backup": true, // Make backup before removal
	"-S": true, "--suffix": true, // Override backup suffix
	"-v": true, "--verbose": true, // Verbose output
	"-t": true, "--target-directory": true, // Specify target directory
	"-T": true, "--no-target-directory": true, // Treat destination as normal file
	"--help":    true, // Display help (actually safe, but we'll handle separately)
	"--version": true, // Display version (actually safe, but we'll handle separately)
}

// Safe ln options that are informational only
var safeLnOptions = map[string]bool{
	"--help":    true, // Display help
	"--version": true, // Display version
}

// Dangerous patterns to detect in ln arguments
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

// IsLnOptionSafe checks if a ln option is safe for read-only operation
func IsLnOptionSafe(option string) (bool, string) {
	// Special case: help and version are safe
	if option == "--help" || option == "--version" {
		return true, ""
	}

	// Check if it's explicitly dangerous
	if dangerousLnOptions[option] {
		return false, "dangerous ln option"
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(option) {
			return false, "contains dangerous pattern"
		}
	}

	// If it's a flag we don't recognize, be conservative and block it
	if strings.HasPrefix(option, "-") {
		return false, "unknown ln option"
	}

	// For ln, non-option arguments are source/target files
	// In read-only mode, we block any link creation attempts
	return false, "link creation not allowed in read-only mode"
}

// IsLnSafe checks if ln arguments are safe for read-only operation
func IsLnSafe(args []string) (bool, string) {
	if len(args) == 0 {
		return false, "no arguments provided"
	}

	// ln requires at least source and target
	// In read-only mode, we only allow informational options

	for _, arg := range args {
		if safe, reason := IsLnOptionSafe(arg); !safe {
			// Special case: if it's a file name (not an option), we can give a more specific message
			if !strings.HasPrefix(arg, "-") {
				return false, fmt.Sprintf("link creation with '%s' not allowed in read-only mode", arg)
			}
			return false, fmt.Sprintf("ln argument '%s' %s", arg, reason)
		}
	}

	// The only safe ln commands are help and version
	for _, arg := range args {
		if arg != "--help" && arg != "--version" {
			return false, "ln link creation not allowed in read-only mode"
		}
	}

	return true, ""
}
