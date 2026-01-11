package rocp

import (
	"fmt"
	"regexp"
	"strings"
)

// Dangerous cp options that copy files
var dangerousCpOptions = map[string]bool{
	"-a": true, "--archive": true,           // Archive mode
	"-b": true, "--backup": true,           // Make backup before overwrite
	"-f": true, "--force": true,            // Force overwrite
	"-i": true, "--interactive": true,      // Prompt before overwrite
	"-l": true, "--link": true,             // Hard link instead of copy
	"-L": true, "--dereference": true,      // Always follow symbolic links
	"-H": true,                               // Follow symlinks on command line
	"-P": true,                               // Never follow symbolic links
	"-p": true, "--preserve": true,          // Preserve attributes
	"-R": true, "-r": true, "--recursive": true, // Recursive copy
	"-s": true, "--symbolic-link": true,    // Make symbolic links instead of copying
	"-S": true, "--suffix": true,           // Override backup suffix
	"-u": true, "--update": true,           // Copy only when source is newer
	"-v": true, "--verbose": true,          // Verbose output
	"-x": true, "--one-file-system": true,  // Stay on this file system
	"-Z": true, "--context": true,          // Set SELinux security context
	"-t": true, "--target-directory": true, // Specify target directory
	"-T": true, "--no-target-directory": true, // Treat destination as normal file
	"--attributes-only": true,              // Don't copy file data, just attributes
	"--no-preserve": true,                  // Don't preserve attributes
	"--parents": true,                      // Preserve parent directories
	"--sparse": true,                       // Control creation of sparse files
	"--strip-trailing-slashes": true,       // Remove trailing slashes from source
}

// Safe cp options that are informational only
var safeCpOptions = map[string]bool{
	"--help": true,                         // Display help
	"--version": true,                      // Display version
}

// Dangerous patterns to detect in cp arguments
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

// IsCopyOptionSafe checks if a cp option is safe for read-only operation
func IsCopyOptionSafe(option string) (bool, string) {
	// Check if it's explicitly dangerous
	if dangerousCpOptions[option] {
		return false, "dangerous cp option"
	}

	// Check if it's explicitly safe
	if safeCpOptions[option] {
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
		return false, "unknown cp option"
	}

	// For cp, non-option arguments are source/target files
	// In read-only mode, we block any file copying attempts
	return false, "file copying not allowed in read-only mode"
}

// IsCopySafe checks if cp arguments are safe for read-only operation
func IsCopySafe(args []string) (bool, string) {
	if len(args) == 0 {
		return false, "no arguments provided"
	}

	// cp requires at least source and target
	// In read-only mode, we only allow informational options

	for _, arg := range args {
		if safe, reason := IsCopyOptionSafe(arg); !safe {
			// Special case: if it's a file name (not an option), we can give a more specific message
			if !strings.HasPrefix(arg, "-") {
				return false, fmt.Sprintf("file copying '%s' not allowed in read-only mode", arg)
			}
			return false, fmt.Sprintf("cp argument '%s' %s", arg, reason)
		}
	}

	// The only safe cp commands are help and version
	for _, arg := range args {
		if arg != "--help" && arg != "--version" {
			return false, "cp file copying not allowed in read-only mode"
		}
	}

	return true, ""
}