package rofind

import (
	"testing"
)

// Test IsDangerousFindOption function
func TestIsDangerousFindOption(t *testing.T) {
	tests := []struct {
		name     string
		arg      string
		nextArg  string
		want     bool
		wantErr  string
	}{
		// Dangerous options that should be blocked
		{"exec", "-exec", "rm {} \\;", true, "can execute commands"},
		{"execdir", "-execdir", "rm {} \\;", true, "can execute commands"},
		{"ok", "-ok", "rm {} \\;", true, "can execute commands"},
		{"okdir", "-okdir", "rm {} \\;", true, "can execute commands"},
		{"delete", "-delete", "", true, "can delete files"},
		{"printf to file", "-printf", ">output.txt", true, "appears to write to a file"},
		{"fprintf to file", "-fprintf", ">output.txt", true, "appears to write to a file"},
		{"printf append", "-printf", ">>output.txt", true, "appears to write to a file"},

		// Safe options that should be allowed
		{"printf safe", "-printf", "%p\n", false, ""},
		{"fprintf safe", "-fprintf", "/dev/null", false, ""},
		{"name", "-name", "*.go", false, ""},
		{"type", "-type", "f", false, ""},
		{"size", "-size", "+1M", false, ""},
		{"mtime", "-mtime", "-7", false, ""},
		{"path", "-path", "*/test/*", false, ""},
		{"regex", "-regex", ".*\\.go$", false, ""},
		{"empty next", "-name", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := IsDangerousFindOption(tt.arg, tt.nextArg)
			if got != tt.want {
				t.Errorf("IsDangerousFindOption(%q, %q) dangerous = %v, want %v", tt.arg, tt.nextArg, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("IsDangerousFindOption(%q, %q) error = %q, want %q", tt.arg, tt.nextArg, gotErr, tt.wantErr)
			}
		})
	}
}

// Test AreFindArgsSafe function
func TestAreFindArgsSafe(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    bool
		wantErr string
	}{
		// Safe find operations
		{"simple name search", []string{".", "-name", "*.go"}, true, ""},
		{"type search", []string{".", "-type", "f"}, true, ""},
		{"size search", []string{".", "-size", "+1M"}, true, ""},
		{"mtime search", []string{".", "-mtime", "-7"}, true, ""},
		{"complex search", []string{".", "-name", "*.go", "-type", "f", "-size", "+1k"}, true, ""},
		{"printf safe", []string{".", "-printf", "%p\n"}, true, ""},
		{"fprintf to dev null", []string{".", "-fprintf", "/dev/null", "%p\n"}, true, ""},

		// Dangerous operations that should be blocked
		{"exec rm", []string{".", "-name", "*.tmp", "-exec", "rm", "{}", "\\;"}, false, "can execute commands"},
		{"execdir rm", []string{".", "-execdir", "rm", "{}", "\\;"}, false, "can execute commands"},
		{"ok rm", []string{".", "-ok", "rm", "{}", "\\;"}, false, "can execute commands"},
		{"delete files", []string{".", "-name", "*.tmp", "-delete"}, false, "can delete files"},
		{"printf to file", []string{".", "-printf", ">output.txt", "%p\n"}, false, "appears to write to a file"},
		{"fprintf append", []string{".", "-fprintf", ">>output.txt", "%p\n"}, false, "appears to write to a file"},

		// Edge cases
		{"empty args", []string{}, true, ""},
		{"single path", []string{"."}, true, ""},
		{"multiple exec", []string{".", "-exec", "echo", "{}", "\\;", "-exec", "rm", "{}", "\\;"}, false, "can execute commands"},
		{"exec in middle", []string{".", "-name", "*.go", "-exec", "cat", "{}", "\\;", "-type", "f"}, false, "can execute commands"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := AreFindArgsSafe(tt.args)
			if got != tt.want {
				t.Errorf("AreFindArgsSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("AreFindArgsSafe(%v) error = %q, want %q", tt.args, gotErr, tt.wantErr)
			}
		})
	}
}