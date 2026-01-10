package rogrep

import (
	"testing"
)

// Test IsDangerousGrepOption function
func TestIsDangerousGrepOption(t *testing.T) {
	tests := []struct {
		name     string
		arg      string
		want     bool
		wantErr  string
	}{
		// Safe grep options
		{"help", "--help", false, ""},
		{"version", "--version", false, ""},
		{"extended regexp", "-E", false, ""},
		{"fixed strings", "-F", false, ""},
		{"basic regexp", "-G", false, ""},
		{"perl regexp", "-P", false, ""},
		{"regexp", "-e", false, ""},
		{"file", "-f", false, ""},
		{"ignore case", "-i", false, ""},
		{"invert match", "-v", false, ""},
		{"word regexp", "-w", false, ""},
		{"line regexp", "-x", false, ""},
		{"after context", "-A", false, ""},
		{"before context", "-B", false, ""},
		{"context", "-C", false, ""},
		{"count", "-c", false, ""},
		{"files with matches", "-l", false, ""},
		{"files without match", "-L", false, ""},
		{"line number", "-n", false, ""},
		{"only matching", "-o", false, ""},
		{"quiet", "-q", false, ""},
		{"no messages", "-s", false, ""},
		{"with filename", "-H", false, ""},
		{"no filename", "-h", false, ""},
		{"text", "-a", false, ""},
		{"binary files", "-I", false, ""},
		{"directories", "-d", false, ""},
		{"devices", "-D", false, ""},
		{"recursive", "-r", false, ""},
		{"dereference recursive", "-R", false, ""},
		{"include", "--include", false, ""},
		{"exclude", "--exclude", false, ""},
		{"exclude dir", "--exclude-dir", false, ""},

		// Regular arguments (safe)
		{"pattern", "test", false, ""},
		{"filename", "file.txt", false, ""},
		{"multiple files", "*.txt", false, ""},

		// Potentially dangerous patterns (should be blocked)
		{"output redirect", ">output.txt", true, "appears to redirect output"},
		{"append redirect", ">>output.txt", true, "appears to redirect output"},
		{"pipe", "| cat", true, "appears to redirect output"},
		{"contains redirect", "file > other", true, "appears to contain redirection"},
		{"contains pipe", "file | cmd", true, "appears to contain redirection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := IsDangerousGrepOption(tt.arg)
			if got != tt.want {
				t.Errorf("IsDangerousGrepOption(%q) dangerous = %v, want %v", tt.arg, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("IsDangerousGrepOption(%q) error = %q, want %q", tt.arg, gotErr, tt.wantErr)
			}
		})
	}
}

// Test AreGrepArgsSafe function
func TestAreGrepArgsSafe(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    bool
		wantErr string
	}{
		// Safe grep operations
		{"simple grep", []string{"test", "file.txt"}, true, ""},
		{"with options", []string{"-i", "test", "file.txt"}, true, ""},
		{"recursive", []string{"-r", "test", "."}, true, ""},
		{"extended regexp", []string{"-E", "test.*", "file.txt"}, true, ""},
		{"multiple files", []string{"test", "*.txt"}, true, ""},
		{"help", []string{"--help"}, true, ""},
		{"version", []string{"--version"}, true, ""},

		// Dangerous operations (should be blocked)
		{"output redirect", []string{">output.txt"}, false, "appears to redirect output"},
		{"append redirect", []string{">>output.txt"}, false, "appears to redirect output"},
		{"pipe", []string{"| cat"}, false, "appears to redirect output"},
		{"mixed safe and dangerous", []string{"-i", "test", ">output.txt"}, false, "appears to redirect output"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := AreGrepArgsSafe(tt.args)
			if got != tt.want {
				t.Errorf("AreGrepArgsSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("AreGrepArgsSafe(%v) error = %q, want %q", tt.args, gotErr, tt.wantErr)
			}
		})
	}
}