package rocat

import (
	"strings"
)

// IsDangerousCatOption checks if a cat option is dangerous
func IsDangerousCatOption(arg string) (bool, string) {
	// Check for options that could be dangerous
	switch arg {
	case "--help", "--version":
		return false, "" // These are safe informational options
	case "-A", "--show-all":
		return false, "" // Safe - show all characters
	case "-b", "--number-nonblank":
		return false, "" // Safe - number non-blank lines
	case "-e":
		return false, "" // Safe - equivalent to -vE
	case "-E", "--show-ends":
		return false, "" // Safe - show line ends
	case "-n", "--number":
		return false, "" // Safe - number all lines
	case "-s", "--squeeze-blank":
		return false, "" // Safe - squeeze blank lines
	case "-t":
		return false, "" // Safe - equivalent to -vT
	case "-T", "--show-tabs":
		return false, "" // Safe - show tabs
	case "-v", "--show-nonprinting":
		return false, "" // Safe - show non-printing characters
	}

	// Check for potential output redirection or dangerous patterns
	if strings.HasPrefix(arg, ">") || strings.HasPrefix(arg, ">>") || strings.HasPrefix(arg, "|") {
		return true, "appears to redirect output"
	}

	// Check for potential file writing patterns
	if strings.Contains(arg, ">") || strings.Contains(arg, "|") {
		return true, "appears to contain redirection"
	}

	// If it's a flag we don't recognize, be cautious but allow it
	// Most cat flags are safe (read-only by nature)
	if strings.HasPrefix(arg, "-") {
		return false, "unknown flag but likely safe"
	}

	// Regular arguments (files) are safe as long as they're not special devices
	// that could cause issues when read
	if arg == "/dev/null" || arg == "/dev/zero" || arg == "/dev/random" || arg == "/dev/urandom" {
		return false, "safe device file"
	}

	return false, ""
}

// AreCatArgsSafe checks if cat arguments are safe for read-only operation
func AreCatArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousCatOption(arg); dangerous {
			return false, reason
		}
	}
	return true, ""
}