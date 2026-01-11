package rochown

import (
	"fmt"
	"regexp"
	"strings"
)

// Dangerous chown options that modify ownership
var dangerousChownOptions = map[string]bool{
	"-R": true, "--recursive": true, // Recursive changes
	"-v": true, "--verbose": true, // Verbose output
	"-c": true, "--changes": true, // Report changes
	"-f": true, "--silent": true, // Suppress errors
	"-h": true, "--no-dereference": true, // Affect symlinks instead of targets
	"--from":      true, // Change only if current owner/group matches
	"--reference": true, // Change ownership to match reference file
}

// Safe chown options that are informational only
var safeChownOptions = map[string]bool{
	"--help":    true, // Display help
	"--version": true, // Display version
}

// Dangerous patterns to detect in chown arguments
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
	if strings.Contains(spec, " ") {
		return false
	}

	// Check for file-like patterns that should not be owner specs
	// Filenames typically contain slashes or other file-specific characters
	// But dots are allowed in usernames (e.g., john.doe)
	fileLikePatterns := []string{"/", "\\", "~"}
	for _, pattern := range fileLikePatterns {
		if strings.Contains(spec, pattern) {
			return false
		}
	}

	// More restrictive character set for owner specs
	// Owner specs should generally be alphanumeric with limited special chars
	validOwnerChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:_-."
	for _, c := range spec {
		if !strings.Contains(validOwnerChars, string(c)) {
			return false
		}
	}

	// Additional checks for owner spec format
	colonCount := strings.Count(spec, ":")
	if colonCount > 1 {
		return false // More than one colon is invalid
	}

	// Check if it starts or ends with colon (valid for owner specs)
	if strings.HasPrefix(spec, ":") || strings.HasSuffix(spec, ":") {
		// Make sure there's something before/after the colon
		if spec == ":" {
			return false
		}
		if strings.HasPrefix(spec, ":") && len(spec) == 1 {
			return false
		}
		if strings.HasSuffix(spec, ":") && len(spec) == 1 {
			return false
		}
	}

	// Additional heuristic: if it contains a dot and looks like a filename, reject it
	// This is a heuristic to prevent common filenames from being treated as owner specs
	if strings.Contains(spec, ".") {
		// Check if it looks like a common filename pattern
		// Common filename extensions that should not be owner specs
		commonExtensions := []string{".txt", ".log", ".conf", ".sh", ".py", ".go", ".js", ".json", ".html", ".css", ".jpg", ".png", ".gif"}
		for _, ext := range commonExtensions {
			if strings.HasSuffix(strings.ToLower(spec), ext) {
				return false
			}
		}
		// If it has multiple dots or ends with a dot, it's probably a filename
		if strings.Count(spec, ".") > 1 || strings.HasSuffix(spec, ".") {
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

	// For chown, non-option arguments could be owner specs or filenames
	// We need to check if it looks like a valid owner spec
	if isValidOwnerSpec(option) {
		// In read-only mode, we block any actual ownership changes
		return false, "attempts to change ownership"
	}

	// If it doesn't look like a valid owner spec, it's probably a filename
	// We'll allow filename arguments but they won't do anything in read-only mode
	return true, "filename argument"
}

// parseChownCommand parses chown command arguments according to the proper syntax:
// chown [OPTION]... [OWNER][:[GROUP]] FILE...
// chown [OPTION]... --reference=RFILE FILE...
func parseChownCommand(args []string) (options []string, ownerSpec string, files []string, err error) {
	if len(args) == 0 {
		return nil, "", nil, fmt.Errorf("no arguments provided")
	}

	var referenceFile string
	i := 0

	// Parse options first
	for i < len(args) {
		arg := args[i]

		// Check for end of options marker
		if arg == "--" {
			i++
			break
		}

		// Check for long options
		if strings.HasPrefix(arg, "--") {
			if arg == "--reference" {
				// --reference requires an argument
				if i+1 >= len(args) {
					return nil, "", nil, fmt.Errorf("--reference requires a file argument")
				}
				referenceFile = args[i+1]
				i += 2
				continue
			} else if strings.HasPrefix(arg, "--reference=") {
				referenceFile = strings.TrimPrefix(arg, "--reference=")
				i++
				continue
			} else if arg == "--help" || arg == "--version" {
				options = append(options, arg)
				i++
				continue
			} else if dangerousChownOptions[arg] {
				options = append(options, arg)
				i++
				continue
			} else {
				// Unknown long option
				return nil, "", nil, fmt.Errorf("unknown option: %s", arg)
			}
		}

		// Check for short options
		if strings.HasPrefix(arg, "-") && arg != "-" {
			// Handle clustered short options (e.g., -Rv)
			for _, c := range arg[1:] {
				shortOpt := "-" + string(c)
				if dangerousChownOptions[shortOpt] {
					options = append(options, shortOpt)
				} else {
					return nil, "", nil, fmt.Errorf("unknown option: %s", shortOpt)
				}
			}
			i++
			continue
		}

		// End of options
		break
	}

	// If we have a reference file, the remaining arguments are target files
	if referenceFile != "" {
		if i >= len(args) {
			return nil, "", nil, fmt.Errorf("--reference requires target files")
		}
		// --reference changes ownership, so it's dangerous
		return options, "REFERENCE:" + referenceFile, args[i:], nil
	}

	// Parse owner specification and files
	if i >= len(args) {
		// No owner spec or files - this might be just options like --help
		return options, "", nil, nil
	}

	// The next argument could be owner spec
	potentialOwner := args[i]

	// Check if it looks like an owner specification
	if isValidOwnerSpec(potentialOwner) {
		ownerSpec = potentialOwner
		i++

		// Remaining arguments should be files
		if i < len(args) {
			files = args[i:]
		}
		return options, ownerSpec, files, nil
	}

	// If the first non-option doesn't look like an owner spec, treat everything as files
	// This handles cases like "chown file1 file2" where no ownership change is intended
	return options, "", args[i:], nil
}

// IsChownSafe checks if chown arguments are safe for read-only operation
func IsChownSafe(args []string) (bool, string) {
	if len(args) == 0 {
		return false, "no arguments provided"
	}

	// Parse the command according to chown syntax
	options, ownerSpec, files, err := parseChownCommand(args)
	if err != nil {
		return false, fmt.Sprintf("invalid chown command: %s", err)
	}

	// Check options for dangerous ones
	for _, opt := range options {
		if dangerousChownOptions[opt] {
			return false, fmt.Sprintf("dangerous chown option: %s", opt)
		}
	}

	// If there's an owner specification, this is an attempt to change ownership
	if ownerSpec != "" {
		return false, fmt.Sprintf("attempts to change ownership to: %s", ownerSpec)
	}

	// If we have files but no owner spec, this is safe (no ownership change)
	// This handles cases like "chown --help" or "chown file1 file2"
	_ = files // files variable is used in parsing but not in safety check
	return true, ""
}
