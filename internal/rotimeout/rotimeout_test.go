package rotimeout

import (
	"testing"
)

// Test IsDangerousTimeoutOption function
func TestIsDangerousTimeoutOption(t *testing.T) {
	tests := []struct {
		name     string
		arg      string
		position int
		want     bool
		wantErr  string
	}{
		// Safe timeout options
		{"help", "--help", 0, false, ""},
		{"version", "--version", 0, false, ""},
		{"kill after", "-k", 0, false, ""},
		{"signal", "-s", 0, false, ""},
		{"foreground", "--foreground", 0, false, ""},
		{"preserve status", "--preserve-status", 0, false, ""},

		// Duration arguments (safe)
		{"seconds", "10", 0, false, "valid duration"},
		{"decimal", "2.5", 0, false, "valid duration"},
		{"with suffix s", "10s", 0, false, "valid duration with suffix"},
		{"with suffix m", "5m", 0, false, "valid duration with suffix"},
		{"with suffix h", "2h", 0, false, "valid duration with suffix"},
		{"with suffix d", "1d", 0, false, "valid duration with suffix"},

		// Command arguments (allowed with caution)
		{"simple command", "echo", 1, false, "command execution allowed (use with caution)"},
		{"command with arg", "hello", 2, false, "command execution allowed (use with caution)"},

		// Potentially dangerous patterns (should be blocked)
		{"output redirect", ">output.txt", 0, true, "appears to redirect output"},
		{"append redirect", ">>output.txt", 0, true, "appears to redirect output"},
		{"pipe", "| cat", 0, true, "appears to redirect output"},
		{"contains redirect", "file > other", 0, true, "appears to contain redirection"},
		{"contains pipe", "file | cmd", 0, true, "appears to contain redirection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := IsDangerousTimeoutOption(tt.arg, tt.position)
			if got != tt.want {
				t.Errorf("IsDangerousTimeoutOption(%q, %d) dangerous = %v, want %v", tt.arg, tt.position, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("IsDangerousTimeoutOption(%q, %d) error = %q, want %q", tt.arg, tt.position, gotErr, tt.wantErr)
			}
		})
	}
}

// Test AreTimeoutArgsSafe function
func TestAreTimeoutArgsSafe(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    bool
		wantErr string
	}{
		// Safe timeout operations
		{"simple timeout", []string{"10", "echo", "hello"}, true, ""},
		{"with signal", []string{"5", "-s", "TERM", "sleep", "10"}, true, ""},
		{"help", []string{"--help"}, true, ""},
		{"version", []string{"--version"}, true, ""},

		// Dangerous operations (should be blocked)
		{"output redirect", []string{">output.txt"}, false, "appears to redirect output"},
		{"append redirect", []string{">>output.txt"}, false, "appears to redirect output"},
		{"pipe", []string{"| cat"}, false, "appears to redirect output"},
		{"mixed safe and dangerous", []string{"10", "echo", ">output.txt"}, false, "appears to redirect output"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := AreTimeoutArgsSafe(tt.args)
			if got != tt.want {
				t.Errorf("AreTimeoutArgsSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("AreTimeoutArgsSafe(%v) error = %q, want %q", tt.args, gotErr, tt.wantErr)
			}
		})
	}
}
