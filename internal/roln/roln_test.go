package roln

import (
	"testing"
)

// Test IsLnOptionSafe function
func TestIsLnOptionSafe(t *testing.T) {
	tests := []struct {
		name     string
		option   string
		want     bool
	}{
		// Dangerous options that should be blocked
		{"symbolic -s", "-s", false},
		{"symbolic --symbolic", "--symbolic", false},
		{"force -f", "-f", false},
		{"force --force", "--force", false},
		{"interactive -i", "-i", false},
		{"interactive --interactive", "--interactive", false},
		{"no-dereference -n", "-n", false},
		{"no-dereference --no-dereference", "--no-dereference", false},
		{"backup -b", "-b", false},
		{"backup --backup", "--backup", false},
		{"suffix -S", "-S", false},
		{"suffix --suffix", "--suffix", false},
		{"verbose -v", "-v", false},
		{"verbose --verbose", "--verbose", false},
		{"target-directory -t", "-t", false},
		{"target-directory --target-directory", "--target-directory", false},
		{"no-target-directory -T", "-T", false},
		{"no-target-directory --no-target-directory", "--no-target-directory", false},

		// Safe options that should be allowed
		{"help --help", "--help", true},
		{"version --version", "--version", true},

		// File arguments should be blocked (they would create links)
		{"source file", "source.txt", false},
		{"target file", "target.txt", false},
		{"multiple files", "file1.txt", false},

		// Unknown options should be blocked
		{"unknown option -x", "-x", false},
		{"unknown option --unknown", "--unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsLnOptionSafe(tt.option)
			if got != tt.want {
				t.Errorf("IsLnOptionSafe(%q) = %v, want %v", tt.option, got, tt.want)
			}
		})
	}
}

// Test IsLnSafe function
func TestIsLnSafe(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		want     bool
	}{
		// Safe ln commands (read-only or informational)
		{"help option", []string{"--help"}, true},
		{"version option", []string{"--version"}, true},

		// Dangerous ln commands (attempt to create links)
		{"hard link", []string{"source.txt", "link.txt"}, false},
		{"symbolic link", []string{"-s", "source.txt", "link.txt"}, false},
		{"force link", []string{"-f", "source.txt", "link.txt"}, false},
		{"verbose link", []string{"-v", "source.txt", "link.txt"}, false},
		{"symbolic with target", []string{"--symbolic", "source.txt", "link.txt"}, false},

		// Edge cases
		{"no arguments", []string{}, false},
		{"unknown option", []string{"-x"}, false},
		{"mixed safe and dangerous", []string{"--help", "source.txt"}, false},
		{"just source", []string{"source.txt"}, false},
		{"multiple sources", []string{"source1.txt", "source2.txt", "target"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsLnSafe(tt.args)
			if got != tt.want {
				t.Errorf("IsLnSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}