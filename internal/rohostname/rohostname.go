package rohostname

import (
	"strings"
)

// IsDangerousHostnameOption checks if a hostname option is dangerous
// hostname can have write operations, so we need to be careful
func IsDangerousHostnameOption(arg string) (bool, string) {
	// Block write operations
	switch arg {
	case "--help", "--version", "-h", "-V":
		// These are safe informational options
		return false, ""
	case "-a", "--alias":
		// Alias - safe
		return false, ""
	case "-d", "--domain":
		// Domain - safe
		return false, ""
	case "-f", "--fqdn":
		// FQDN - safe
		return false, ""
	case "-i", "--ip-address":
		// IP address - safe
		return false, ""
	case "-s", "--short":
		// Short - safe
		return false, ""
	case "-y", "--yp", "--nis":
		// YP/NIS - safe
		return false, ""
	}

	// Block any option that looks like it could write
	if strings.HasPrefix(arg, "--set-") || strings.HasPrefix(arg, "--file") {
		return true, "hostname modification not allowed in read-only mode"
	}

	// Check for any suspicious patterns that might indicate
	// command injection or other dangerous behavior
	if strings.Contains(arg, "`") || strings.Contains(arg, "$") {
		return true, "contains potential command injection characters"
	}

	// Check for suspiciously long arguments (regardless of prefix)
	if len(arg) >= 50 {
		return true, "suspiciously long option"
	}

	if strings.HasPrefix(arg, "--") || strings.HasPrefix(arg, "-") {
		// Most hostname options are safe for reading
		return false, ""
	}

	// Non-option arguments (new hostname) are dangerous
	if !strings.HasPrefix(arg, "-") {
		return true, "hostname modification not allowed in read-only mode"
	}

	return false, ""
}

// AreHostnameArgsSafe checks if hostname arguments are safe for read-only operation
func AreHostnameArgsSafe(args []string) (bool, string) {
	for _, arg := range args {
		if dangerous, reason := IsDangerousHostnameOption(arg); dangerous {
			return false, reason
		}
	}

	return true, ""
}