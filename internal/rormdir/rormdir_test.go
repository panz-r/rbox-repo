package rormdir

import (
	"testing"
)

// Test IsRmdirOptionSafe function
func TestIsRmdirOptionSafe(t *testing.T) {
	tests := []struct {
		name   string
		option string
		want   bool
	}{
		// Dangerous options that should be blocked
		{"parents -p", "-p", false},
		{"parents --parents", "--parents", false},
		{"verbose -v", "-v", false},
		{"verbose --verbose", "--verbose", false},
		{"ignore fail on non-empty", "--ignore-fail-on-non-empty", false},

		// Safe options that should be allowed
		{"help --help", "--help", true},
		{"version --version", "--version", true},

		// Directory names should be blocked (they would remove directories)
		{"simple directory", "olddir", false},
		{"directory with path", "path/to/olddir", false},
		{"directory with spaces", "old directory", false},
		{"current directory", ".", false},
		{"parent directory", "..", false},

		// Unknown options should be blocked
		{"unknown option -x", "-x", false},
		{"unknown option --unknown", "--unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsRmdirOptionSafe(tt.option)
			if got != tt.want {
				t.Errorf("IsRmdirOptionSafe(%q) = %v, want %v", tt.option, got, tt.want)
			}
		})
	}
}

// Test IsRmdirSafe function
func TestIsRmdirSafe(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		// Safe rmdir commands (read-only or informational)
		{"help option", []string{"--help"}, true},
		{"version option", []string{"--version"}, true},

		// Dangerous rmdir commands (attempt to remove directories)
		{"simple directory", []string{"olddir"}, false},
		{"directory with path", []string{"path/to/olddir"}, false},
		{"multiple directories", []string{"dir1", "dir2"}, false},
		{"with parents option", []string{"-p", "olddir"}, false},
		{"with verbose option", []string{"-v", "olddir"}, false},
		{"with ignore option", []string{"--ignore-fail-on-non-empty", "olddir"}, false},

		// Edge cases
		{"no arguments", []string{}, false},
		{"unknown option", []string{"-x"}, false},
		{"mixed safe and dangerous", []string{"--help", "olddir"}, false},
		{"current directory", []string{"."}, false},
		{"parent directory", []string{".."}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsRmdirSafe(tt.args)
			if got != tt.want {
				t.Errorf("IsRmdirSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
