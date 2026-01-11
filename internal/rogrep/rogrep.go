package rogrep

import (
	"strings"
)

// IsDangerousGrepOption checks if a grep option is dangerous
func IsDangerousGrepOption(arg string) (bool, string) {
	// Check for options that could be dangerous
	switch arg {
	case "--help", "--version":
		return false, "" // These are safe informational options
	case "-E", "--extended-regexp":
		return false, "" // Safe - extended regex
	case "-F", "--fixed-strings":
		return false, "" // Safe - fixed strings
	case "-G", "--basic-regexp":
		return false, "" // Safe - basic regex
	case "-P", "--perl-regexp":
		return false, "" // Safe - perl regex
	case "-e", "--regexp":
		return false, "" // Safe - pattern
	case "-f", "--file":
		return false, "" // Safe - pattern file
	case "-i", "--ignore-case":
		return false, "" // Safe - ignore case
	case "-v", "--invert-match":
		return false, "" // Safe - invert match
	case "-w", "--word-regexp":
		return false, "" // Safe - word regexp
	case "-x", "--line-regexp":
		return false, "" // Safe - line regexp
	case "-A", "--after-context":
		return false, "" // Safe - after context
	case "-B", "--before-context":
		return false, "" // Safe - before context
	case "-C", "--context":
		return false, "" // Safe - context
	case "-c", "--count":
		return false, "" // Safe - count
	case "-l", "--files-with-matches":
		return false, "" // Safe - files with matches
	case "-L", "--files-without-match":
		return false, "" // Safe - files without matches
	case "-n", "--line-number":
		return false, "" // Safe - line numbers
	case "-o", "--only-matching":
		return false, "" // Safe - only matching
	case "-q", "--quiet", "--silent":
		return false, "" // Safe - quiet
	case "-s", "--no-messages":
		return false, "" // Safe - no messages
	case "-H", "--with-filename":
		return false, "" // Safe - with filename
	case "-h", "--no-filename":
		return false, "" // Safe - no filename
	case "-V":
		return false, "" // Safe - version
	case "-a", "--text":
		return false, "" // Safe - text
	case "-I":
		return false, "" // Safe - binary files without match
	case "-d", "--directories":
		return false, "" // Safe - directories
	case "-D", "--devices":
		return false, "" // Safe - devices
	case "-r", "--recursive":
		return false, "" // Safe - recursive
	case "-R", "--dereference-recursive":
		return false, "" // Safe - dereference recursive
	case "--include":
		return false, "" // Safe - include
	case "--exclude":
		return false, "" // Safe - exclude
	case "--exclude-dir":
		return false, "" // Safe - exclude directory
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
	// Most grep flags are safe (read-only by nature)
	if strings.HasPrefix(arg, "-") {
		return false, "unknown flag but likely safe"
	}

	// Regular arguments (patterns, files) are safe
	return false, ""
}

// AreGrepArgsSafe checks if grep arguments are safe for read-only operation
func AreGrepArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousGrepOption(arg); dangerous {
			return false, reason
		}
	}
	return true, ""
}
