package rochown

import (
	"fmt"
	"regexp"
	"strings"
)

// Dangerous chown options that modify ownership
var dangerousChownOptions = map[string]bool{
	"-R": true, "--recursive": true,       // Recursive changes
	"-v": true, "--verbose": true,         // Verbose output
	"-c": true, "--changes": true,         // Report changes
	"-f": true, "--silent": true,          // Suppress errors
	"-h": true, "--no-dereference": true,  // Affect symlinks instead of targets
	"--from": true,                         // Change only if current owner/group matches
	"--reference": true,                    // Change ownership to match reference file
}

// Safe chown options that are informational only
var safeChownOptions = map[string]bool{
	"--help": true,                         // Display help
	"--version": true,                      // Display version
}

// Dangerous patterns to detect in chown arguments
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

// isValidOwnerSpec checks if a string is a valid owner specification
func isValidOwnerSpec(spec string) bool {
	// Valid owner specs can be:
	// - username
	// - username:groupname
	// - :groupname
	// - username:
	// - uid
	// - uid:gid

	if spec == "" {
		return false
	}

	// Check for dangerous patterns first
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(spec) {
			return false
		}
	}

	// Basic validation - should not contain spaces or special chars
	// This is lenient to allow various valid formats
	invalidChars := "<>|&;(){}[]\"'\\`$"
	for _, c := range spec {
		if strings.Contains(invalidChars, string(c)) {
			return false
		}
	}

	return true
}

// IsChownOptionSafe checks if a chown option is safe for read-only operation
func IsChownOptionSafe(option string) (bool, string) {
	// Check if it's explicitly dangerous
	if dangerousChownOptions[option] {
		return false, "dangerous chown option"
	}

	// Check if it's explicitly safe
	if safeChownOptions[option] {
		return true, ""
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(option) {
			return false, "contains dangerous pattern"
		}
	}

	// Check if it looks like an owner specification (user:group format)
	if isValidOwnerSpec(option) {
		// In read-only mode, we block any actual ownership changes
		return false, "attempts to change ownership"
	}

	// If it's a flag we don't recognize, be conservative and block it
	if strings.HasPrefix(option, "-") {
		return false, "unknown chown option"
	}

	// For chown, non-option arguments are typically filenames
	// We'll allow them but they won't do anything in read-only mode
	return true, "filename argument"
}

// IsChownSafe checks if chown arguments are safe for read-only operation
func IsChownSafe(args []string) (bool, string) {
	if len(args) == 0 {
		return false, "no arguments provided"
	}

	// chown requires at least an owner specification
	// In read-only mode, we only allow informational options

	for _, arg := range args {
		if safe, reason := IsChownOptionSafe(arg); !safe {
			return false, fmt.Sprintf("chown argument '%s' %s", arg, reason)
		}
	}

	// Special case: if we have what looks like an owner specification, block it
	for _, arg := range args {
		if isValidOwnerSpec(arg) {
			return false, fmt.Sprintf("chown owner spec '%s' attempts to change ownership", arg)
		}
	}

	return true, ""
}