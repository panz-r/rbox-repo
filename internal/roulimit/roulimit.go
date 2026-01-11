package roulimit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Safe ulimit options that are read-only (display only)
var safeUlimitOptions = map[string]bool{
	"-a":        true, // Display all current limits (read-only)
	"--all":     true, // Display all current limits (read-only)
	"-c":        true, // Display core file size limit (read-only)
	"-d":        true, // Display data seg size limit (read-only)
	"-e":        true, // Display scheduling priority limit (read-only)
	"-f":        true, // Display file size limit (read-only)
	"-i":        true, // Display pending signals limit (read-only)
	"-l":        true, // Display memory lock limit (read-only)
	"-m":        true, // Display max memory size limit (read-only)
	"-n":        true, // Display open files limit (read-only)
	"-p":        true, // Display pipe size limit (read-only)
	"-q":        true, // Display POSIX message queues limit (read-only)
	"-r":        true, // Display real-time priority limit (read-only)
	"-s":        true, // Display stack size limit (read-only)
	"-t":        true, // Display CPU time limit (read-only)
	"-u":        true, // Display processes/threads limit (read-only)
	"-v":        true, // Display virtual memory limit (read-only)
	"-x":        true, // Display file locks limit (read-only)
	"-H":        true, // Display hard limits (read-only)
	"-S":        true, // Display soft limits (read-only)
	"--help":    true, // Display help (read-only)
	"--version": true, // Display version (read-only)
}

// Dangerous patterns to detect in ulimit arguments
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

// IsUlimitOptionSafe checks if a ulimit option is safe for read-only operation
func IsUlimitOptionSafe(option string) (bool, string) {
	// Check if it's explicitly safe (read-only)
	if safeUlimitOptions[option] {
		return true, ""
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(option) {
			return false, "contains dangerous pattern"
		}
	}

	// Check if it's a numeric value (setting a limit - dangerous)
	if _, err := strconv.Atoi(option); err == nil {
		return false, "attempt to set limit (write operation)"
	}

	// Check if it looks like a limit setting (e.g., "unlimited")
	if strings.ToLower(option) == "unlimited" || strings.ToLower(option) == "hard" || strings.ToLower(option) == "soft" {
		return false, "attempt to set limit (write operation)"
	}

	// If it's a flag we don't recognize, be conservative and block it
	if strings.HasPrefix(option, "-") {
		return false, "unknown ulimit option"
	}

	// Non-option arguments are not expected for ulimit in read-only mode
	return false, "unexpected argument"
}

// IsUlimitSafe checks if ulimit arguments are safe for read-only operation
func IsUlimitSafe(args []string) (bool, string) {
	if len(args) == 0 {
		return false, "no arguments provided - ulimit requires options"
	}

	// ulimit typically takes one option at a time
	if len(args) > 1 {
		return false, "too many arguments for read-only ulimit"
	}

	option := args[0]

	// Check if the option is safe
	if safe, reason := IsUlimitOptionSafe(option); !safe {
		return false, fmt.Sprintf("ulimit option '%s' %s", option, reason)
	}

	return true, ""
}
