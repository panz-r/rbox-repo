package romv

import (
	"testing"
)

// Test IsMoveOptionSafe function
func TestIsMoveOptionSafe(t *testing.T) {
	tests := []struct {
		name     string
		option   string
		want     bool
	}{
		// Dangerous options that should be blocked
		{"force -f", "-f", false},
		{"force --force", "--force", false},
		{"interactive -i", "-i", false},
		{"interactive --interactive", "--interactive", false},
		{"no-clobber -n", "-n", false},
		{"no-clobber --no-clobber", "--no-clobber", false},
		{"update -u", "-u", false},
		{"update --update", "--update", false},
		{"verbose -v", "-v", false},
		{"verbose --verbose", "--verbose", false},
		{"backup -b", "-b", false},
		{"backup --backup", "--backup", false},
		{"suffix -S", "-S", false},
		{"suffix --suffix", "--suffix", false},
		{"target-directory -t", "-t", false},
		{"target-directory --target-directory", "--target-directory", false},
		{"no-target-directory -T", "-T", false},
		{"no-target-directory --no-target-directory", "--no-target-directory", false},
		{"strip-trailing-slashes", "--strip-trailing-slashes", false},

		// Safe options that should be allowed
		{"help --help", "--help", true},
		{"version --version", "--version", true},

		// File arguments should be blocked (they would move files)
		{"source file", "source.txt", false},
		{"target file", "target.txt", false},
		{"directory source", "source_dir", false},
		{"directory target", "target_dir", false},

		// Unknown options should be blocked
		{"unknown option -x", "-x", false},
		{"unknown option --unknown", "--unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsMoveOptionSafe(tt.option)
			if got != tt.want {
				t.Errorf("IsMoveOptionSafe(%q) = %v, want %v", tt.option, got, tt.want)
			}
		})
	}
}

// Test IsMoveSafe function
func TestIsMoveSafe(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		want     bool
	}{
		// Safe mv commands (read-only or informational)
		{"help option", []string{"--help"}, true},
		{"version option", []string{"--version"}, true},

		// Dangerous mv commands (attempt to move files)
		{"simple move", []string{"source.txt", "target.txt"}, false},
		{"move to directory", []string{"source.txt", "target_dir/"}, false},
		{"multiple files", []string{"file1.txt", "file2.txt", "target_dir/"}, false},
		{"with force option", []string{"-f", "source.txt", "target.txt"}, false},
		{"with verbose option", []string{"-v", "source.txt", "target.txt"}, false},
		{"with update option", []string{"-u", "source.txt", "target.txt"}, false},

		// Edge cases
		{"no arguments", []string{}, false},
		{"unknown option", []string{"-x"}, false},
		{"mixed safe and dangerous", []string{"--help", "source.txt"}, false},
		{"single file", []string{"source.txt"}, false}, // Missing target
		{"directory move", []string{"source_dir", "target_dir"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsMoveSafe(tt.args)
			if got != tt.want {
				t.Errorf("IsMoveSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}