package rosort

import (
	"fmt"
	"regexp"
	"strings"
)

// Dangerous sort options that should be blocked
var dangerousSortOptions = map[string]bool{
	"-o": true,      // Output to file (write operation)
	"--output": true, // Output to file (write operation)
	"-T": true,      // Use directory for temporaries (potential write)
	"--temporary-directory": true, // Use directory for temporaries (potential write)
	"--sort": true,  // Sort script (potential code execution)
}

// Safe sort options that are allowed
var safeSortOptions = map[string]bool{
	"-b": true, "--ignore-leading-blanks": true,
	"-d": true, "--dictionary-order": true,
	"-f": true, "--ignore-case": true,
	"-g": true, "--general-numeric-sort": true,
	"-h": true, "--human-numeric-sort": true,
	"-i": true, "--ignore-nonprinting": true,
	"-k": true, "--key": true,
	"-M": true, "--month-sort": true,
	"-n": true, "--numeric-sort": true,
	"-r": true, "--reverse": true,
	"-R": true, "--random-sort": true,
	"-s": true, "--stable": true,
	"-t": true, "--field-separator": true,
	"-u": true, "--unique": true,
	"-z": true, "--zero-terminated": true,
	"--help": true,
	"--version": true,
	"-c": true, "--check": true,           // Check if already sorted (read-only)
	"-m": true, "--merge": true,           // Merge already sorted files (read-only)
	"-S": true, "--buffer-size": true,     // Buffer size (read-only)
	"--batch-size": true,                  // Batch size (read-only)
	"--parallel": true,                    // Parallel processing (read-only)
	"--files0-from": true,                // Read input from files (read-only)
}

// Dangerous patterns to detect in sort arguments
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

// IsSortOptionSafe checks if a sort option is safe for read-only operation
func IsSortOptionSafe(option string) (bool, string) {
	// Check if it's explicitly dangerous
	if dangerousSortOptions[option] {
		return false, "dangerous sort option"
	}

	// Check if it's explicitly safe
	if safeSortOptions[option] {
		return true, ""
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(option) {
			return false, "contains dangerous pattern"
		}
	}

	// If it's a flag we don't recognize, check if it looks like a flag
	if strings.HasPrefix(option, "-") {
		// Unknown flag - be conservative and block it
		return false, "unknown sort option"
	}

	// If it's not a flag, it's probably a filename - allow it
	return true, ""
}

// AreSortArgsSafe checks if sort arguments are safe for read-only operation
func AreSortArgsSafe(args []string) (bool, string) {
	if len(args) == 0 {
		return true, "" // sort with no args is safe (reads from stdin)
	}

	for i, arg := range args {
		// Skip the first non-option argument (filename)
		if i > 0 && !strings.HasPrefix(arg, "-") {
			continue
		}

		if safe, reason := IsSortOptionSafe(arg); !safe {
			return false, fmt.Sprintf("sort option '%s' %s", arg, reason)
		}
	}

	return true, ""
}