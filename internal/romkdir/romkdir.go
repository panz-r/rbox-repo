package romkdir

import (
	"fmt"
	"regexp"
	"strings"
)

// Dangerous mkdir options that create directories
var dangerousMkdirOptions = map[string]bool{
	"-p": true, "--parents": true,         // Create parent directories as needed
	"-v": true, "--verbose": true,         // Verbose output
	"-m": true, "--mode": true,            // Set permission mode (implies creation)
	"-Z": true, "--context": true,         // Set SELinux security context
}

// Safe mkdir options that are informational only
var safeMkdirOptions = map[string]bool{
	"--help": true,                         // Display help
	"--version": true,                      // Display version
}

// Dangerous patterns to detect in mkdir arguments
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

// IsMkdirOptionSafe checks if a mkdir option is safe for read-only operation
func IsMkdirOptionSafe(option string) (bool, string) {
	// Check if it's explicitly dangerous
	if dangerousMkdirOptions[option] {
		return false, "dangerous mkdir option"
	}

	// Check if it's explicitly safe
	if safeMkdirOptions[option] {
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
		return false, "unknown mkdir option"
	}

	// For mkdir, non-option arguments are directory names
	// In read-only mode, we block any directory creation attempts
	// But we allow the arguments for validation purposes
	return false, "directory creation not allowed in read-only mode"
}

// IsMkdirSafe checks if mkdir arguments are safe for read-only operation
func IsMkdirSafe(args []string) (bool, string) {
	if len(args) == 0 {
		return false, "no arguments provided"
	}

	// mkdir requires at least a directory name
	// In read-only mode, we only allow informational options

	for _, arg := range args {
		if safe, reason := IsMkdirOptionSafe(arg); !safe {
			// Special case: if it's a directory name (not an option), we can give a more specific message
			if !strings.HasPrefix(arg, "-") {
				return false, fmt.Sprintf("directory creation '%s' not allowed in read-only mode", arg)
			}
			return false, fmt.Sprintf("mkdir argument '%s' %s", arg, reason)
		}
	}

	// The only safe mkdir commands are help and version
	for _, arg := range args {
		if arg != "--help" && arg != "--version" {
			return false, "mkdir directory creation not allowed in read-only mode"
		}
	}

	return true, ""
}