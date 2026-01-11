package romv

import (
	"fmt"
	"regexp"
	"strings"
)

// Dangerous mv options that modify files
var dangerousMvOptions = map[string]bool{
	"-f": true, "--force": true, // Force overwrite
	"-i": true, "--interactive": true, // Prompt before overwrite
	"-n": true, "--no-clobber": true, // Don't overwrite existing files
	"-u": true, "--update": true, // Move only when source is newer
	"-v": true, "--verbose": true, // Verbose output
	"-b": true, "--backup": true, // Make backup before removal
	"-S": true, "--suffix": true, // Override backup suffix
	"-t": true, "--target-directory": true, // Specify target directory
	"-T": true, "--no-target-directory": true, // Treat destination as normal file
	"--strip-trailing-slashes": true, // Remove trailing slashes from source
}

// Safe mv options that are informational only
var safeMvOptions = map[string]bool{
	"--help":    true, // Display help
	"--version": true, // Display version
}

// Dangerous patterns to detect in mv arguments
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

// IsMoveOptionSafe checks if a mv option is safe for read-only operation
func IsMoveOptionSafe(option string) (bool, string) {
	// Check if it's explicitly dangerous
	if dangerousMvOptions[option] {
		return false, "dangerous mv option"
	}

	// Check if it's explicitly safe
	if safeMvOptions[option] {
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
		return false, "unknown mv option"
	}

	// For mv, non-option arguments are source/target files
	// In read-only mode, we block any file movement attempts
	return false, "file movement not allowed in read-only mode"
}

// IsMoveSafe checks if mv arguments are safe for read-only operation
func IsMoveSafe(args []string) (bool, string) {
	if len(args) == 0 {
		return false, "no arguments provided"
	}

	// mv requires at least source and target
	// In read-only mode, we only allow informational options

	for _, arg := range args {
		if safe, reason := IsMoveOptionSafe(arg); !safe {
			// Special case: if it's a file name (not an option), we can give a more specific message
			if !strings.HasPrefix(arg, "-") {
				return false, fmt.Sprintf("file movement '%s' not allowed in read-only mode", arg)
			}
			return false, fmt.Sprintf("mv argument '%s' %s", arg, reason)
		}
	}

	// The only safe mv commands are help and version
	for _, arg := range args {
		if arg != "--help" && arg != "--version" {
			return false, "mv file movement not allowed in read-only mode"
		}
	}

	return true, ""
}
