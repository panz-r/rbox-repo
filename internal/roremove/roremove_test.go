package roremove

import (
	"testing"
)

// Test IsRemoveOptionSafe function
func TestIsRemoveOptionSafe(t *testing.T) {
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
		{"interactive once -I", "-I", false},
		{"interactive once --interactive=once", "--interactive=once", false},
		{"recursive -r", "-r", false},
		{"recursive -R", "-R", false},
		{"recursive --recursive", "--recursive", false},
		{"dir -d", "-d", false},
		{"dir --dir", "--dir", false},
		{"verbose -v", "-v", false},
		{"verbose --verbose", "--verbose", false},
		{"one-file-system", "--one-file-system", false},
		{"no-preserve-root", "--no-preserve-root", false},
		{"preserve-root", "--preserve-root", false},

		// Safe options that should be allowed
		{"help --help", "--help", true},
		{"version --version", "--version", true},

		// File arguments should be blocked (they would remove files)
		{"simple file", "file.txt", false},
		{"directory", "directory", false},
		{"multiple files", "file1.txt", false},
		{"path with wildcards", "*.txt", false},

		// Unknown options should be blocked
		{"unknown option -x", "-x", false},
		{"unknown option --unknown", "--unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsRemoveOptionSafe(tt.option)
			if got != tt.want {
				t.Errorf("IsRemoveOptionSafe(%q) = %v, want %v", tt.option, got, tt.want)
			}
		})
	}
}

// Test IsRemoveSafe function
func TestIsRemoveSafe(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		want     bool
	}{
		// Safe rm commands (read-only or informational)
		{"help option", []string{"--help"}, true},
		{"version option", []string{"--version"}, true},

		// Dangerous rm commands (attempt to remove files)
		{"simple file", []string{"file.txt"}, false},
		{"multiple files", []string{"file1.txt", "file2.txt"}, false},
		{"directory", []string{"directory"}, false},
		{"with force option", []string{"-f", "file.txt"}, false},
		{"with recursive option", []string{"-r", "directory"}, false},
		{"with verbose option", []string{"-v", "file.txt"}, false},
		{"with interactive option", []string{"-i", "file.txt"}, false},

		// Edge cases
		{"no arguments", []string{}, false},
		{"unknown option", []string{"-x"}, false},
		{"mixed safe and dangerous", []string{"--help", "file.txt"}, false},
		{"wildcard pattern", []string{"*.txt"}, false},
		{"directory with contents", []string{"dir/*"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsRemoveSafe(tt.args)
			if got != tt.want {
				t.Errorf("IsRemoveSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}