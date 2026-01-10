package rols

import (
	"testing"
)

// Test IsDangerousLsOption function
func TestIsDangerousLsOption(t *testing.T) {
	tests := []struct {
		name     string
		arg      string
		want     bool
		wantErr  string
	}{
		// Safe ls options
		{"help", "--help", false, ""},
		{"version", "--version", false, ""},
		{"long format", "-l", false, ""},
		{"all files", "-a", false, ""},
		{"recursive", "-R", false, ""},
		{"human readable", "-h", false, ""},
		{"reverse sort", "-r", false, ""},
		{"sort by size", "-S", false, ""},
		{"one per line", "-1", false, ""},
		{"classify", "-F", false, ""},
		{"color", "--color", false, ""},
		{"inode", "-i", false, ""},
		{"numeric uid", "-n", false, ""},
		{"file type", "-p", false, ""},
		{"hide control", "-q", false, ""},
		{"size", "-s", false, ""},
		{"access time", "-u", false, ""},
		{"version sort", "-v", false, ""},
		{"selinux context", "-Z", false, ""},

		// Regular arguments (safe)
		{"regular file", "filename.txt", false, ""},
		{"directory", "/home/user", false, ""},
		{"current dir", ".", false, ""},
		{"parent dir", "..", false, ""},

		// Potentially dangerous patterns (should be blocked)
		{"output redirect", ">output.txt", true, "appears to redirect output"},
		{"append redirect", ">>output.txt", true, "appears to redirect output"},
		{"pipe", "| grep test", true, "appears to redirect output"},
		{"contains redirect", "file > other", true, "appears to contain redirection"},
		{"contains pipe", "file | cmd", true, "appears to contain redirection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := IsDangerousLsOption(tt.arg)
			if got != tt.want {
				t.Errorf("IsDangerousLsOption(%q) dangerous = %v, want %v", tt.arg, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("IsDangerousLsOption(%q) error = %q, want %q", tt.arg, gotErr, tt.wantErr)
			}
		})
	}
}

// Test AreLsArgsSafe function
func TestAreLsArgsSafe(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    bool
		wantErr string
	}{
		// Safe ls operations
		{"simple list", []string{"."}, true, ""},
		{"long format", []string{"-l", "."}, true, ""},
		{"all files", []string{"-a", "."}, true, ""},
		{"recursive", []string{"-R", "/home"}, true, ""},
		{"multiple options", []string{"-l", "-a", "-h", "."}, true, ""},
		{"help", []string{"--help"}, true, ""},
		{"version", []string{"--version"}, true, ""},

		// Dangerous operations (should be blocked)
		{"output redirect", []string{">output.txt"}, false, "appears to redirect output"},
		{"append redirect", []string{">>output.txt"}, false, "appears to redirect output"},
		{"pipe", []string{"| grep test"}, false, "appears to redirect output"},
		{"mixed safe and dangerous", []string{"-l", ">output.txt"}, false, "appears to redirect output"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := AreLsArgsSafe(tt.args)
			if got != tt.want {
				t.Errorf("AreLsArgsSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("AreLsArgsSafe(%v) error = %q, want %q", tt.args, gotErr, tt.wantErr)
			}
		})
	}
}