package rocd

import (
	"os"
	"path/filepath"
	"strings"
)

// IsDangerousCdOption checks if a cd option is dangerous
func IsDangerousCdOption(arg string) (bool, string) {
	// Check for options that could be dangerous
	switch arg {
	case "--help", "--version":
		return false, "" // Safe informational options
	case "-L":
		return false, "" // Safe - follow symbolic links
	case "-P":
		return false, "" // Safe - don't follow symbolic links
	case "-e":
		return false, "" // Safe - exit if directory doesn't exist
	}

	// Check for potential output redirection or dangerous patterns
	if strings.HasPrefix(arg, ">") || strings.HasPrefix(arg, ">>") || strings.HasPrefix(arg, "|") {
		return true, "appears to redirect output"
	}

	// Check for redirect patterns within the argument
	if strings.Contains(arg, ">") || strings.Contains(arg, "|") {
		return true, "appears to contain redirection"
	}

	// Check for command substitution patterns
	if strings.Contains(arg, "$") && strings.Contains(arg, "(") {
		return true, "appears to contain command substitution"
	}

	// Check for backticks (command substitution)
	if strings.Contains(arg, "`") {
		return true, "appears to contain command substitution"
	}

	// If it's a flag we don't recognize, be cautious but allow it
	if strings.HasPrefix(arg, "-") {
		return false, "unknown flag but likely safe"
	}

	// For cd, we need to validate the target directory
	// Check if it's a valid path (not a command or dangerous pattern)
	if !isSafePath(arg) {
		return true, "appears to be an unsafe path"
	}

	return false, ""
}

// isSafePath checks if a path is safe for cd operation
func isSafePath(path string) bool {
	// Empty path is not safe
	if path == "" {
		return false
	}

	// Check for path traversal attacks
	if strings.Contains(path, "..") && !strings.HasPrefix(path, "../") && !strings.HasSuffix(path, "/..") {
		// This is a bit lenient, but we'll allow relative paths with ..
		// A more strict approach would be to resolve the path first
		return true
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return false
	}

	// Check if path contains only valid characters
	for _, r := range path {
		if r == 0 {
			return false // null byte
		}
		// Allow basic path characters
		if !(r >= 32 && r <= 126) { // printable ASCII
			return false
		}
	}

	return true
}

// AreCdArgsSafe checks if cd arguments are safe for read-only operation
func AreCdArgsSafe(args []string) (bool, string) {
	// Count non-option arguments
	nonOptionCount := 0
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			nonOptionCount++
		}
	}

	// cd typically takes 0 or 1 non-option arguments (the target directory)
	if nonOptionCount > 1 {
		return false, "too many arguments"
	}

	for _, arg := range args {
		if dangerous, reason := IsDangerousCdOption(arg); dangerous {
			return false, reason
		}
	}
	return true, ""
}

// ChangeDirectory performs the actual directory change
func ChangeDirectory(args []string) error {
	// Parse arguments
	var target string
	var followLinks bool // default behavior

	for i, arg := range args {
		if arg == "-L" {
			followLinks = true
		} else if arg == "-P" {
			followLinks = false
		} else if !strings.HasPrefix(arg, "-") {
			target = arg
			// Remove this arg so we don't process it again
			if i < len(args)-1 {
				args = append(args[:i], args[i+1:]...)
			} else {
				args = args[:i]
			}
			break
		}
	}

	// If no target specified, use home directory
	if target == "" {
		homeDir := os.Getenv("HOME")
		if homeDir == "" {
			// Fallback to current user's home directory
			currentUser, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			homeDir = currentUser
		}
		target = homeDir
	}

	// Resolve the path
	var finalPath string
	var err error
	if followLinks {
		finalPath, err = filepath.EvalSymlinks(target)
		if err != nil {
			return err
		}
	} else {
		finalPath = target
	}

	// Change directory
	return os.Chdir(finalPath)
}