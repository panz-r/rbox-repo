package rowc

import (
	"strings"
	"testing"
)

// Test IsDangerousWcOption function
func TestIsDangerousWcOption(t *testing.T) {
	tests := []struct {
		arg      string
		want     bool
		wantErr  string
	}{
		// Safe options
		{"--help", false, ""},
		{"--version", false, ""},
		{"-h", false, ""},
		{"-c", false, ""},
		{"--bytes", false, ""},
		{"-m", false, ""},
		{"--chars", false, ""},
		{"-l", false, ""},
		{"--lines", false, ""},
		{"-w", false, ""},
		{"--words", false, ""},
		{"-L", false, ""},
		{"--max-line-length", false, ""},
		{"file.txt", false, ""},
		{"/home/user/file.txt", false, ""},
		{".", false, ""},

		// Dangerous patterns
		{"`echo test`", true, "contains potential command injection characters"},
		{"$(whoami)", true, "contains potential command injection characters"},
		{strings.Repeat("a", 51), true, "suspiciously long option"},
		{"--" + strings.Repeat("a", 48), true, "suspiciously long option"},
	}

	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			got, gotErr := IsDangerousWcOption(tt.arg)
			if got != tt.want {
				t.Errorf("IsDangerousWcOption(%q) dangerous = %v, want %v", tt.arg, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("IsDangerousWcOption(%q) error = %q, want %q", tt.arg, gotErr, tt.wantErr)
			}
		})
	}
}

// Test AreWcArgsSafe function
func TestAreWcArgsSafe(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    bool
		wantErr string
	}{
		// Safe argument combinations
		{"count lines", []string{"-l", "file.txt"}, true, ""},
		{"count words", []string{"-w", "file.txt"}, true, ""},
		{"count bytes", []string{"-c", "file.txt"}, true, ""},
		{"help", []string{"--help"}, true, ""},
		{"multiple files", []string{"-l", "file1.txt", "file2.txt"}, true, ""},
		{"all counts", []string{"-lwc", "file.txt"}, true, ""},
		{"max line length", []string{"-L", "file.txt"}, true, ""},
		{"stdin only", []string{"-l"}, true, ""},
		{"complex", []string{"-lw", "--max-line-length", "file1.txt", "file2.txt"}, true, ""},

		// Dangerous argument combinations
		{"command injection", []string{"`rm -rf /`"}, false, "contains potential command injection characters"},
		{"variable expansion", []string{"$(whoami)"}, false, "contains potential command injection characters"},
		{"long option", []string{strings.Repeat("a", 51)}, false, "suspiciously long option"},
		{"mixed safe and dangerous", []string{"-l", "`echo test`"}, false, "contains potential command injection characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := AreWcArgsSafe(tt.args)
			if got != tt.want {
				t.Errorf("AreWcArgsSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("AreWcArgsSafe(%v) error = %q, want %q", tt.args, gotErr, tt.wantErr)
			}
		})
	}
}