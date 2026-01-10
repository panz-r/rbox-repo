package roecho

import (
	"testing"
)

// Test IsDangerousEchoOption function
func TestIsDangerousEchoOption(t *testing.T) {
	tests := []struct {
		name     string
		arg      string
		want     bool
		wantErr  string
	}{
		// Safe echo options
		{"help", "--help", false, ""},
		{"version", "--version", false, ""},
		{"no newline", "-n", false, ""},
		{"enable escapes", "-e", false, ""},
		{"disable escapes", "-E", false, ""},

		// Safe text arguments
		{"simple text", "hello world", false, ""},
		{"with spaces", "hello world", false, ""},
		{"with quotes", `"hello"`, false, ""},

		// Potentially dangerous patterns (should be blocked)
		{"output redirect", ">output.txt", true, "appears to redirect output"},
		{"append redirect", ">>output.txt", true, "appears to redirect output"},
		{"pipe", "| cat", true, "appears to redirect output"},
		{"contains redirect", "file > other", true, "appears to contain redirection"},
		{"contains pipe", "file | cmd", true, "appears to contain redirection"},
		{"command substitution", "$(whoami)", true, "appears to contain command substitution"},
		{"backticks", "`whoami`", true, "appears to contain command substitution"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := IsDangerousEchoOption(tt.arg)
			if got != tt.want {
				t.Errorf("IsDangerousEchoOption(%q) dangerous = %v, want %v", tt.arg, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("IsDangerousEchoOption(%q) error = %q, want %q", tt.arg, gotErr, tt.wantErr)
			}
		})
	}
}

// Test AreEchoArgsSafe function
func TestAreEchoArgsSafe(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    bool
		wantErr string
	}{
		// Safe echo operations
		{"simple echo", []string{"hello"}, true, ""},
		{"multiple words", []string{"hello", "world"}, true, ""},
		{"with newline", []string{"-n", "hello"}, true, ""},
		{"with escapes", []string{"-e", "hello\\nworld"}, true, ""},
		{"help", []string{"--help"}, true, ""},
		{"version", []string{"--version"}, true, ""},

		// Dangerous operations (should be blocked)
		{"output redirect", []string{">output.txt"}, false, "appears to redirect output"},
		{"append redirect", []string{">>output.txt"}, false, "appears to redirect output"},
		{"pipe", []string{"| cat"}, false, "appears to redirect output"},
		{"command substitution", []string{"$(whoami)"}, false, "appears to contain command substitution"},
		{"backticks", []string{"`whoami`"}, false, "appears to contain command substitution"},
		{"mixed safe and dangerous", []string{"hello", ">output.txt"}, false, "appears to redirect output"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := AreEchoArgsSafe(tt.args)
			if got != tt.want {
				t.Errorf("AreEchoArgsSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("AreEchoArgsSafe(%v) error = %q, want %q", tt.args, gotErr, tt.wantErr)
			}
		})
	}
}