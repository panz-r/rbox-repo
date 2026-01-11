package roremove

import (
	"fmt"
	"regexp"
	"strings"
)

// Dangerous rm options that remove files
var dangerousRmOptions = map[string]bool{
	"-f": true, "--force": true,           // Force removal
	"-i": true, "--interactive": true,      // Prompt before removal
	"-I": true, "--interactive=once": true, // Prompt once before removing many files
	"-r": true, "-R": true, "--recursive": true, // Recursive removal
	"-d": true, "--dir": true,             // Remove empty directories
	"-v": true, "--verbose": true,          // Verbose output
	"--one-file-system": true,              // Stay on this file system
	"--no-preserve-root": true,             // Don't treat '/' specially
	"--preserve-root": true,                // Don't operate recursively on '/'
}

// Safe rm options that are informational only
var safeRmOptions = map[string]bool{
	"--help": true,                         // Display help
	"--version": true,                      // Display version
}

// Dangerous patterns to detect in rm arguments
var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`>\s*[^\s]+`),           // Output redirection >
	regexp.MustCompile(`>>\s*[^\s]+`),          // Append redirection >>
	regexp.MustCompile(`\|\s*[^\s]+`),          // Pipe |
	regexp.MustCompile(`\$\s*\([^)]+\)`),       // Command substitution $(...)
	regexp.MustCompile("`[^`]+`"),               // Backtick command substitution
	regexp.MustCompile(`\$\s*\{[^}]+\}`),      // Variable expansion ${...}
	regexp.MustCompile(`\$\s*[A-Za-z_][A-Za-z0-9_]*`), // Simple variable $VAR
	regexp.MustCompile(`\s*;\s*`),               // Command chaining with ;
	regexp.MustCompile(`\s*&&\s*`),              // Command chaining with &&
	regexp.MustCompile(`\s*\|\|\s*`),           // Command chaining with ||
	regexp.MustCompile(`&\s*$`),                  // Background process &
	regexp.MustCompile(`\s*&\s*`),                // Background process &
}

// IsRemoveOptionSafe checks if a rm option is safe for read-only operation
func IsRemoveOptionSafe(option string) (bool, string) {
	// Check if it's explicitly dangerous
	if dangerousRmOptions[option] {
		return false, "dangerous rm option"
	}

	// Check if it's explicitly safe
	if safeRmOptions[option] {
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
		return false, "unknown rm option"
	}

	// For rm, non-option arguments are files/directories to remove
	// In read-only mode, we block any file removal attempts
	return false, "file removal not allowed in read-only mode"
}

// IsRemoveSafe checks if rm arguments are safe for read-only operation
func IsRemoveSafe(args []string) (bool, string) {
	if len(args) == 0 {
		return false, "no arguments provided"
	}

	// rm requires at least a file/directory to remove
	// In read-only mode, we only allow informational options

	for _, arg := range args {
		if safe, reason := IsRemoveOptionSafe(arg); !safe {
			// Special case: if it's a file name (not an option), we can give a more specific message
			if !strings.HasPrefix(arg, "-") {
				return false, fmt.Sprintf("file removal '%s' not allowed in read-only mode", arg)
			}
			return false, fmt.Sprintf("rm argument '%s' %s", arg, reason)
		}
	}

	// The only safe rm commands are help and version
	for _, arg := range args {
		if arg != "--help" && arg != "--version" {
			return false, "rm file removal not allowed in read-only mode"
		}
	}

	return true, ""
}