package rocat

import (
	"testing"
)

// Test IsDangerousCatOption function
func TestIsDangerousCatOption(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		want    bool
		wantErr string
	}{
		// Safe cat options
		{"help", "--help", false, ""},
		{"version", "--version", false, ""},
		{"show all", "-A", false, ""},
		{"number nonblank", "-b", false, ""},
		{"show ends", "-E", false, ""},
		{"number all", "-n", false, ""},
		{"squeeze blank", "-s", false, ""},
		{"show tabs", "-T", false, ""},
		{"show nonprinting", "-v", false, ""},

		// Safe device files
		{"dev null", "/dev/null", false, "safe device file"},
		{"dev zero", "/dev/zero", false, "safe device file"},
		{"dev random", "/dev/random", false, "safe device file"},
		{"dev urandom", "/dev/urandom", false, "safe device file"},

		// Regular files (safe)
		{"regular file", "filename.txt", false, ""},
		{"multiple files", "file1.txt", false, ""},
		{"current file", ".", false, ""},

		// Potentially dangerous patterns (should be blocked)
		{"output redirect", ">output.txt", true, "appears to redirect output"},
		{"append redirect", ">>output.txt", true, "appears to redirect output"},
		{"pipe", "| grep test", true, "appears to redirect output"},
		{"contains redirect", "file > other", true, "appears to contain redirection"},
		{"contains pipe", "file | cmd", true, "appears to contain redirection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := IsDangerousCatOption(tt.arg)
			if got != tt.want {
				t.Errorf("IsDangerousCatOption(%q) dangerous = %v, want %v", tt.arg, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("IsDangerousCatOption(%q) error = %q, want %q", tt.arg, gotErr, tt.wantErr)
			}
		})
	}
}

// Test AreCatArgsSafe function
func TestAreCatArgsSafe(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    bool
		wantErr string
	}{
		// Safe cat operations
		{"simple cat", []string{"file.txt"}, true, ""},
		{"multiple files", []string{"file1.txt", "file2.txt"}, true, ""},
		{"with options", []string{"-n", "file.txt"}, true, ""},
		{"show all", []string{"-A", "file.txt"}, true, ""},
		{"number lines", []string{"-n", "file.txt"}, true, ""},
		{"device file", []string{"/dev/null"}, true, ""},
		{"help", []string{"--help"}, true, ""},
		{"version", []string{"--version"}, true, ""},

		// Dangerous operations (should be blocked)
		{"output redirect", []string{">output.txt"}, false, "appears to redirect output"},
		{"append redirect", []string{">>output.txt"}, false, "appears to redirect output"},
		{"pipe", []string{"| grep test"}, false, "appears to redirect output"},
		{"mixed safe and dangerous", []string{"-n", ">output.txt"}, false, "appears to redirect output"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := AreCatArgsSafe(tt.args)
			if got != tt.want {
				t.Errorf("AreCatArgsSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("AreCatArgsSafe(%v) error = %q, want %q", tt.args, gotErr, tt.wantErr)
			}
		})
	}
}
