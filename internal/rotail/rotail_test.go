package rotail

import (
	"testing"
)

// Test IsDangerousTailOption function
func TestIsDangerousTailOption(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		want    bool
		wantErr string
	}{
		// Safe tail options
		{"help", "--help", false, ""},
		{"version", "--version", false, ""},
		{"bytes", "-c", false, ""},
		{"lines", "-n", false, ""},
		{"follow", "-f", false, ""},
		{"retry", "-F", false, ""},
		{"quiet", "-q", false, ""},
		{"verbose", "-v", false, ""},
		{"sleep", "-s", false, ""},

		// Regular arguments (safe)
		{"filename", "file.txt", false, ""},
		{"log file", "/var/log/syslog", false, ""},

		// Potentially dangerous patterns (should be blocked)
		{"output redirect", ">output.txt", true, "appears to redirect output"},
		{"append redirect", ">>output.txt", true, "appears to redirect output"},
		{"pipe", "| grep test", true, "appears to redirect output"},
		{"contains redirect", "file > other", true, "appears to contain redirection"},
		{"contains pipe", "file | cmd", true, "appears to contain redirection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := IsDangerousTailOption(tt.arg)
			if got != tt.want {
				t.Errorf("IsDangerousTailOption(%q) dangerous = %v, want %v", tt.arg, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("IsDangerousTailOption(%q) error = %q, want %q", tt.arg, gotErr, tt.wantErr)
			}
		})
	}
}

// Test AreTailArgsSafe function
func TestAreTailArgsSafe(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    bool
		wantErr string
	}{
		// Safe tail operations
		{"simple tail", []string{"file.txt"}, true, ""},
		{"with lines", []string{"-n", "10", "file.txt"}, true, ""},
		{"with bytes", []string{"-c", "100", "file.txt"}, true, ""},
		{"follow mode", []string{"-f", "file.txt"}, true, ""},
		{"help", []string{"--help"}, true, ""},
		{"version", []string{"--version"}, true, ""},

		// Dangerous operations (should be blocked)
		{"output redirect", []string{">output.txt"}, false, "appears to redirect output"},
		{"append redirect", []string{">>output.txt"}, false, "appears to redirect output"},
		{"pipe", []string{"| cat"}, false, "appears to redirect output"},
		{"mixed safe and dangerous", []string{"-n", "10", ">output.txt"}, false, "appears to redirect output"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := AreTailArgsSafe(tt.args)
			if got != tt.want {
				t.Errorf("AreTailArgsSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("AreTailArgsSafe(%v) error = %q, want %q", tt.args, gotErr, tt.wantErr)
			}
		})
	}
}
