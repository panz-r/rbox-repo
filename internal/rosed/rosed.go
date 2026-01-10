package rosed

import (
	"fmt"
	"regexp"
	"strings"
)

// For sed, we need to be extremely careful as it can execute arbitrary code
// and modify files. We'll only allow very specific safe operations.

// Safe sed options that don't modify files or execute code
var safeSedOptions = map[string]bool{
	"-n": true,      // Suppress automatic printing (safe)
	"--quiet": true, // Suppress automatic printing (safe)
	"--silent": true, // Suppress automatic printing (safe)
	"-e": true,      // Add script (but we'll validate the script)
	"--expression": true, // Add script (but we'll validate the script)
	"-f": true,      // Add script from file (but we'll validate the file)
	"--file": true,  // Add script from file (but we'll validate the file)
	"--help": true,  // Display help (safe)
	"--version": true, // Display version (safe)
}

// Dangerous sed options that should always be blocked
var dangerousSedOptions = map[string]bool{
	"-i": true,              // Edit files in place (very dangerous)
	"--in-place": true,      // Edit files in place (very dangerous)
	"--follow-symlinks": true, // Follow symlinks (potentially dangerous)
	"--debug": true,         // Debug mode (could expose sensitive info)
	"--posix": true,         // POSIX mode (could enable dangerous features)
}

// Dangerous sed commands and patterns
var dangerousSedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`s/.*/.*/`),           // Substitution commands (can modify content)
	regexp.MustCompile(`y/.*/.*/`),           // Transliteration commands (can modify content)
	regexp.MustCompile(`a\\`),               // Append text (can modify content)
	regexp.MustCompile(`i\\`),               // Insert text (can modify content)
	regexp.MustCompile(`c\\`),               // Change text (can modify content)
	regexp.MustCompile(`d`),                  // Delete line (can modify content)
	regexp.MustCompile(`D`),                  // Delete first part of pattern space (can modify content)
	regexp.MustCompile(`N`),                  // Append next line (can modify content)
	regexp.MustCompile(`P`),                  // Print first part of pattern space (usually safe)
	regexp.MustCompile(`h`),                  // Copy pattern space to hold space (usually safe)
	regexp.MustCompile(`H`),                  // Append pattern space to hold space (usually safe)
	regexp.MustCompile(`g`),                  // Copy hold space to pattern space (usually safe)
	regexp.MustCompile(`G`),                  // Append hold space to pattern space (usually safe)
	regexp.MustCompile(`x`),                  // Exchange pattern and hold spaces (usually safe)
	regexp.MustCompile(`q`),                  // Quit (can be used to bypass processing)
	regexp.MustCompile(`Q`),                  // Quit immediately (can be used to bypass processing)
	regexp.MustCompile(`w\s+[^\s]+`),       // Write to file (dangerous)
	regexp.MustCompile(`W\s+[^\s]+`),       // Write first line to file (dangerous)
	regexp.MustCompile(`r\s+[^\s]+`),       // Read file (could be dangerous if file contains malicious content)
	regexp.MustCompile(`R\s+[^\s]+`),       // Read file (could be dangerous if file contains malicious content)
	regexp.MustCompile(`e\s+[^\s]+`),       // Execute command (very dangerous)
	regexp.MustCompile(`e`),                  // Execute command (very dangerous)
	regexp.MustCompile(`l\s*[0-9]*`),        // Show non-printable characters (usually safe)
	regexp.MustCompile(`=`),                  // Print line number (usually safe)
	regexp.MustCompile(`n`),                  // Read next line (usually safe)
	regexp.MustCompile(`p`),                  // Print pattern space (usually safe)
	regexp.MustCompile(`v`),                  // Version (safe)
}

// Safe sed commands (very limited for security)
var safeSedCommands = []*regexp.Regexp{
	regexp.MustCompile(`^[0-9]+p$`),           // Print specific line (safe)
	regexp.MustCompile(`^[0-9]+,\$`),         // Print from line to end (safe) - escaped $
	regexp.MustCompile(`^[0-9]+,[0-9]+p$`),    // Print line range (safe)
	regexp.MustCompile(`^/[^/]+/p$`),        // Print lines matching pattern (safe)
	regexp.MustCompile(`^[0-9]+q$`),           // Quit after line (safe)
	regexp.MustCompile(`^/[^/]+/q$`),        // Quit after pattern match (safe)
}

// Dangerous patterns to detect in sed arguments
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

// IsSedOptionSafe checks if a sed option is safe for read-only operation
func IsSedOptionSafe(option string) (bool, string) {
	// Check if it's explicitly dangerous
	if dangerousSedOptions[option] {
		return false, "dangerous sed option"
	}

	// Check if it's explicitly safe
	if safeSedOptions[option] {
		return true, ""
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(option) {
			return false, "contains dangerous pattern"
		}
	}

	// If it's a flag we don't recognize, be very conservative and block it
	if strings.HasPrefix(option, "-") {
		return false, "unknown sed option"
	}

	// For non-option arguments, we need to be very careful
	// They could be filenames or sed scripts
	return true, "filename or script argument"
}

// IsSedScriptSafe checks if a sed script is safe for read-only operation
func IsSedScriptSafe(script string) (bool, string) {
	// Check if it matches any safe patterns first
	for _, pattern := range safeSedCommands {
		if pattern.MatchString(script) {
			return true, ""
		}
	}

	// Check for dangerous sed commands
	for _, pattern := range dangerousSedPatterns {
		if pattern.MatchString(script) {
			return false, fmt.Sprintf("contains dangerous sed command: %s", pattern.String())
		}
	}

	// If we don't recognize the script, be very conservative and block it
	return false, "unknown or potentially dangerous sed script"
}

// IsSedSafe checks if sed arguments are safe for read-only operation
func IsSedSafe(args []string) (bool, string) {
	if len(args) == 0 {
		return false, "no arguments provided"
	}

	// Parse arguments to separate options from scripts/files
	for _, arg := range args {
		// Check if it's an option
		if strings.HasPrefix(arg, "-") {
			if safe, reason := IsSedOptionSafe(arg); !safe {
				return false, fmt.Sprintf("sed option '%s' %s", arg, reason)
			}
			continue
		}

		// If it's not an option, it could be a script or filename
		// For security, we'll treat it as a script and validate it
		if safe, reason := IsSedScriptSafe(arg); !safe {
			return false, fmt.Sprintf("sed script '%s' %s", arg, reason)
		}
	}

	return true, ""
}