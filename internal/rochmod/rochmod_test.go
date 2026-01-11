package rochmod

import (
	"testing"
)

// Test isNumericMode function
func TestIsNumericMode(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want bool
	}{
		{"valid 3-digit mode", "644", true},
		{"valid 4-digit mode", "0755", true},
		{"valid read-only mode", "444", true},
		{"valid execute-only mode", "111", true},
		{"invalid short mode", "44", false},
		{"invalid long mode", "12345", false},
		{"invalid hex mode", "64G", false},
		{"invalid letters", "abc", false},
		{"invalid symbols", "7-5", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNumericMode(tt.mode)
			if got != tt.want {
				t.Errorf("isNumericMode(%q) = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

// Test isSymbolicMode function
func TestIsSymbolicMode(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want bool
	}{
		{"simple symbolic mode", "u+r", true},
		{"complex symbolic mode", "a+rwx", true},
		{"remove permission", "g-w", true},
		{"set exact", "o=x", true},
		{"multiple changes", "ug+r,o-w", false}, // Conservative: block complex multi-ops
		{"invalid short", "+", false},
		{"invalid chars", "u+z", false},
		{"invalid format", "rwx", false}, // No operator, just permissions
		{"numeric not symbolic", "644", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSymbolicMode(tt.mode)
			if got != tt.want {
				t.Errorf("isSymbolicMode(%q) = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

// Test containsWritePermission function
func TestContainsWritePermission(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want bool
	}{
		// Numeric modes
		{"numeric with write", "644", true},    // 6 = 4+2 (read+write)
		{"numeric read-only", "444", false},    // 4 = read only
		{"numeric execute-only", "111", false}, // 1 = execute only
		{"numeric full", "755", true},          // 7 = 4+2+1 (read+write+execute)
		{"numeric no write", "555", false},     // 5 = 4+1 (read+execute)

		// Symbolic modes
		{"symbolic add write", "u+w", true},
		{"symbolic remove write", "g-w", false}, // This removes write, but doesn't add it
		{"symbolic set with write", "a=rwx", true},
		{"symbolic set without write", "a=rx", false},
		{"symbolic add read", "u+r", false},
		{"symbolic add execute", "u+x", false},

		// Edge cases
		{"invalid mode", "xyz", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsWritePermission(tt.mode)
			if got != tt.want {
				t.Errorf("containsWritePermission(%q) = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

// Test IsChmodOptionSafe function
func TestIsChmodOptionSafe(t *testing.T) {
	tests := []struct {
		name   string
		option string
		want   bool
	}{
		// Dangerous options that should be blocked
		{"recursive -R", "-R", false},
		{"recursive --recursive", "--recursive", false},
		{"verbose -v", "-v", false},
		{"verbose --verbose", "--verbose", false},
		{"changes -c", "-c", false},
		{"changes --changes", "--changes", false},
		{"reference --reference", "--reference", false},

		// Safe options that should be allowed
		{"help --help", "--help", true},
		{"version --version", "--version", true},

		// Numeric modes - some safe, some dangerous
		{"numeric read-only 444", "444", true},
		{"numeric read-only 555", "555", true},
		{"numeric with write 644", "644", false},
		{"numeric with write 755", "755", false},
		{"numeric full 777", "777", false},

		// Symbolic modes - some safe, some dangerous
		{"symbolic add read u+r", "u+r", true},
		{"symbolic add execute u+x", "u+x", true},
		{"symbolic add write u+w", "u+w", false},
		{"symbolic set with write a=rwx", "a=rwx", false},
		{"symbolic set without write a=rx", "a=rx", true},

		// Unknown options should be blocked
		{"symbolic remove execute -x", "-x", true}, // This is actually a valid symbolic mode
		{"unknown option --unknown", "--unknown", false},

		// Filename arguments should be allowed (they won't do anything)
		{"filename", "file.txt", true},
		{"filename with path", "/path/to/file", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsChmodOptionSafe(tt.option)
			if got != tt.want {
				t.Errorf("IsChmodOptionSafe(%q) = %v, want %v", tt.option, got, tt.want)
			}
		})
	}
}

// Test IsChmodSafe function
func TestIsChmodSafe(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		// Safe chmod commands (read-only or informational)
		{"help option", []string{"--help"}, true},
		{"version option", []string{"--version"}, true},
		{"read-only numeric mode", []string{"444", "file.txt"}, true},
		{"read-only symbolic mode", []string{"a=r", "file.txt"}, true},
		{"add read permission", []string{"u+r", "file.txt"}, true},
		{"add execute permission", []string{"a+x", "file.txt"}, true},

		// Dangerous chmod commands (attempt to modify permissions)
		{"numeric with write", []string{"644", "file.txt"}, false},
		{"symbolic add write", []string{"u+w", "file.txt"}, false},
		{"recursive mode change", []string{"-R", "755", "dir"}, false},
		{"verbose mode change", []string{"-v", "644", "file.txt"}, false},
		{"reference mode", []string{"--reference=ref", "file.txt"}, false},

		// Edge cases
		{"no arguments", []string{}, false},
		{"symbolic remove execute", []string{"-x"}, true}, // This is actually a valid symbolic mode
		{"multiple files with safe mode", []string{"444", "file1.txt", "file2.txt"}, true},
		{"multiple files with dangerous mode", []string{"644", "file1.txt", "file2.txt"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsChmodSafe(tt.args)
			if got != tt.want {
				t.Errorf("IsChmodSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
