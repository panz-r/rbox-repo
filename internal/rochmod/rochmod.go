package rochmod

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Dangerous chmod options that modify permissions
var dangerousChmodOptions = map[string]bool{
	"-R": true, "--recursive": true, // Recursive changes
	"-v": true, "--verbose": true, // Verbose output (could be safe, but often used with changes)
	"-c": true, "--changes": true, // Report changes (implies changes are happening)
	"--reference": true, // Change permissions to match reference file
}

// Safe chmod options that are informational only
var safeChmodOptions = map[string]bool{
	"--help":    true, // Display help
	"--version": true, // Display version
}

// Dangerous patterns to detect in chmod arguments
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

// isNumericMode checks if a string is a numeric chmod mode
func isNumericMode(mode string) bool {
	// Numeric modes are 3-4 digits (e.g., 644, 755, 0755)
	if len(mode) < 3 || len(mode) > 4 {
		return false
	}

	// Check if all characters are digits
	for _, c := range mode {
		if c < '0' || c > '7' {
			return false
		}
	}

	return true
}

// isSymbolicMode checks if a string is a symbolic chmod mode
func isSymbolicMode(mode string) bool {
	// Symbolic modes follow patterns like u+r, g-w, o=x, a+rwx
	// Basic pattern: [ugoa]*[+-=][rwxXst]*
	if len(mode) < 2 {
		return false
	}

	// Must contain at least one of +-=
	hasOperator := false
	for _, c := range mode {
		if c == '+' || c == '-' || c == '=' {
			hasOperator = true
			break
		}
	}
	if !hasOperator {
		return false
	}

	// Check for valid symbolic mode components
	validChars := "ugoa+-=rwxXst"
	for _, c := range mode {
		if !strings.Contains(validChars, string(c)) {
			return false
		}
	}

	// Don't allow commas (multi-operation modes like ug+r,o-w)
	// These are complex and we want to be conservative
	if strings.Contains(mode, ",") {
		return false
	}

	return true
}

// containsWritePermission checks if a mode contains write permissions
func containsWritePermission(mode string) bool {
	// For numeric modes, check if any digit has write bit (2)
	if isNumericMode(mode) {
		for _, c := range mode {
			if digit, err := strconv.Atoi(string(c)); err == nil {
				if digit%4 >= 2 { // Write bit is set (2 or 3, 6 or 7)
					return true
				}
			}
		}
		return false
	}

	// For symbolic modes, check for +w or = patterns that include w
	if isSymbolicMode(mode) {
		// Look for +w or = with w in it
		if strings.Contains(mode, "+w") || strings.Contains(mode, "=w") {
			return true
		}
		// Check for patterns like a=rwx, u=w, etc.
		if strings.Contains(mode, "=") && strings.Contains(mode, "w") {
			return true
		}
	}

	return false
}

// IsChmodOptionSafe checks if a chmod option is safe for read-only operation
func IsChmodOptionSafe(option string) (bool, string) {
	// Check if it's explicitly dangerous
	if dangerousChmodOptions[option] {
		return false, "dangerous chmod option"
	}

	// Check if it's explicitly safe
	if safeChmodOptions[option] {
		return true, ""
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(option) {
			return false, "contains dangerous pattern"
		}
	}

	// Check if it's a mode specification (numeric or symbolic)
	if isNumericMode(option) || isSymbolicMode(option) {
		if containsWritePermission(option) {
			return false, "attempts to set write permissions"
		}
		// Read-only modes are allowed (e.g., 444, 555, u+r, a=r)
		return true, ""
	}

	// If it's a flag we don't recognize, be conservative and block it
	if strings.HasPrefix(option, "-") {
		// Check if it's a single dash (stdin) or double dash (end of options)
		if option == "-" || option == "--" {
			return true, "stdin or end of options"
		}
		return false, "unknown chmod option"
	}

	// For chmod, non-option arguments are typically filenames
	// We'll allow them but they won't do anything in read-only mode
	return true, "filename argument"
}

// IsChmodSafe checks if chmod arguments are safe for read-only operation
func IsChmodSafe(args []string) (bool, string) {
	if len(args) == 0 {
		return false, "no arguments provided"
	}

	// chmod requires at least a mode and optionally filenames
	// In read-only mode, we only allow informational options

	for _, arg := range args {
		if safe, reason := IsChmodOptionSafe(arg); !safe {
			return false, fmt.Sprintf("chmod argument '%s' %s", arg, reason)
		}
	}

	// Special case: if we have a mode that includes write permissions, block it
	for _, arg := range args {
		if (isNumericMode(arg) || isSymbolicMode(arg)) && containsWritePermission(arg) {
			return false, fmt.Sprintf("chmod mode '%s' attempts to set write permissions", arg)
		}
	}

	return true, ""
}
