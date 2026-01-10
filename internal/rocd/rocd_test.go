package rocd

import (
	"testing"
)

// Test IsDangerousCdOption function
func TestIsDangerousCdOption(t *testing.T) {
	tests := []struct {
		name     string
		arg      string
		want     bool
		wantErr  string
	}{
		// Safe cd options
		{"help", "--help", false, ""},
		{"version", "--version", false, ""},
		{"follow links", "-L", false, ""},
		{"no follow links", "-P", false, ""},
		{"exit on error", "-e", false, ""},

		// Safe paths
		{"current dir", ".", false, ""},
		{"parent dir", "..", false, ""},
		{"home dir", "~", false, ""},
		{"absolute path", "/home/user", false, ""},
		{"relative path", "subdir", false, ""},
		{"path with dots", "../sibling", false, ""},

		// Potentially dangerous patterns (should be blocked)
		{"output redirect", ">output.txt", true, "appears to redirect output"},
		{"append redirect", ">>output.txt", true, "appears to redirect output"},
		{"pipe", "| cat", true, "appears to redirect output"},
		{"contains redirect", "file > other", true, "appears to contain redirection"},
		{"contains pipe", "file | cmd", true, "appears to contain redirection"},
		{"command substitution", "$(whoami)", true, "appears to contain command substitution"},
		{"backticks", "`whoami`", true, "appears to contain command substitution"},
		{"null byte", "path\x00with\x00null", true, "appears to be an unsafe path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := IsDangerousCdOption(tt.arg)
			if got != tt.want {
				t.Errorf("IsDangerousCdOption(%q) dangerous = %v, want %v", tt.arg, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("IsDangerousCdOption(%q) error = %q, want %q", tt.arg, gotErr, tt.wantErr)
			}
		})
	}
}

// Test AreCdArgsSafe function
func TestAreCdArgsSafe(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    bool
		wantErr string
	}{
		// Safe cd operations
		{"no args (home)", []string{}, true, ""},
		{"simple path", []string{"."}, true, ""},
		{"parent dir", []string{".."}, true, ""},
		{"absolute path", []string{"/home/user"}, true, ""},
		{"with follow links", []string{"-L", "/some/path"}, true, ""},
		{"with no follow", []string{"-P", "/some/path"}, true, ""},
		{"help", []string{"--help"}, true, ""},
		{"version", []string{"--version"}, true, ""},

		// Dangerous operations (should be blocked)
		{"output redirect", []string{">output.txt"}, false, "appears to redirect output"},
		{"append redirect", []string{">>output.txt"}, false, "appears to redirect output"},
		{"pipe", []string{"| cat"}, false, "appears to redirect output"},
		{"command substitution", []string{"$(whoami)"}, false, "appears to contain command substitution"},
		{"backticks", []string{"`whoami`"}, false, "appears to contain command substitution"},
		{"too many args", []string{"/path1", "/path2"}, false, "too many arguments"},
		{"mixed safe and dangerous", []string{"-L", ">output.txt"}, false, "appears to redirect output"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := AreCdArgsSafe(tt.args)
			if got != tt.want {
				t.Errorf("AreCdArgsSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("AreCdArgsSafe(%v) error = %q, want %q", tt.args, gotErr, tt.wantErr)
			}
		})
	}
}