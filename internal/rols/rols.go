package rols

import (
	"strings"
)

// IsDangerousLsOption checks if an ls option is dangerous
func IsDangerousLsOption(arg string) (bool, string) {
	// Check for options that could be dangerous
	switch arg {
	case "--help", "--version":
		return false, "" // These are safe informational options
	case "-w", "--width":
		return false, "" // Safe display option
	case "-l", "--format=long", "--format=verbose":
		return false, "" // Safe formatting
	case "-a", "--all":
		return false, "" // Safe - shows hidden files
	case "-A", "--almost-all":
		return false, "" // Safe
	case "-R", "--recursive":
		return false, "" // Safe - recursive listing
	case "-r", "--reverse":
		return false, "" // Safe - reverse order
	case "-S", "--sort=size":
		return false, "" // Safe - sort by size
	case "-t", "--sort=time":
		return false, "" // Safe - sort by time
	case "-U", "--sort=none":
		return false, "" // Safe - no sorting
	case "-X", "--sort=extension":
		return false, "" // Safe - sort by extension
	case "-1":
		return false, "" // Safe - one entry per line
	case "-m":
		return false, "" // Safe - comma-separated
	case "-x":
		return false, "" // Safe - horizontal listing
	case "-F", "--classify":
		return false, "" // Safe - append file type indicators
	case "--color", "--colour":
		return false, "" // Safe - color output
	case "-h", "--human-readable":
		return false, "" // Safe - human-readable sizes
	case "-i", "--inode":
		return false, "" // Safe - show inode numbers
	case "-n", "--numeric-uid-gid":
		return false, "" // Safe - numeric UID/GID
	case "-o":
		return false, "" // Safe - long format without group
	case "-p", "--file-type":
		return false, "" // Safe - append file type indicators
	case "-q", "--hide-control-chars":
		return false, "" // Safe - hide control characters
	case "-s", "--size":
		return false, "" // Safe - show file sizes
	case "-T", "--tabsize":
		return false, "" // Safe - set tab size
	case "-u":
		return false, "" // Safe - sort by access time
	case "-v":
		return false, "" // Safe - sort by version
	case "-Z", "--context":
		return false, "" // Safe - show SELinux context
	}

	// Check for potential output redirection or dangerous patterns
	if strings.HasPrefix(arg, ">") || strings.HasPrefix(arg, ">>") || strings.HasPrefix(arg, "|") {
		return true, "appears to redirect output"
	}

	// Check for redirect patterns within the argument
	if strings.Contains(arg, ">") || strings.Contains(arg, "|") {
		return true, "appears to contain redirection"
	}

	// If it's a flag we don't recognize, be cautious but allow it
	// Most ls flags are safe (read-only by nature)
	if strings.HasPrefix(arg, "-") {
		return false, "unknown flag but likely safe"
	}

	// Regular arguments (files/directories) are safe
	return false, ""
}

// AreLsArgsSafe checks if ls arguments are safe for read-only operation
func AreLsArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousLsOption(arg); dangerous {
			return false, reason
		}
	}
	return true, ""
}
