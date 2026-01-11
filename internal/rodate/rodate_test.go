package rodate

import (
	"testing"
)

// Test IsDangerousDateOption function
func TestIsDangerousDateOption(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		want    bool
		wantErr string
	}{
		// Safe date options
		{"help", "--help", false, ""},
		{"version", "--version", false, ""},
		{"utc", "-u", false, ""},
		{"rfc-2822", "-R", false, ""},
		{"rfc-3339", "--rfc-3339", false, ""},
		{"rfc-email", "--rfc-email", false, ""},
		{"rfc-3339ns", "--rfc-3339ns", false, ""},
		{"iso-8601", "--iso-8601", false, ""},
		{"reference", "-r", false, ""},
		{"date", "-d", false, ""},
		{"file", "-f", false, ""},
		{"debug", "--debug", false, ""},

		// Safe format strings and files
		{"format string", "+%Y-%m-%d", false, ""},
		{"reference file", "file.txt", false, ""},

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
			got, gotErr := IsDangerousDateOption(tt.arg)
			if got != tt.want {
				t.Errorf("IsDangerousDateOption(%q) dangerous = %v, want %v", tt.arg, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("IsDangerousDateOption(%q) error = %q, want %q", tt.arg, gotErr, tt.wantErr)
			}
		})
	}
}

// Test AreDateArgsSafe function
func TestAreDateArgsSafe(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    bool
		wantErr string
	}{
		// Safe date operations
		{"simple date", []string{}, true, ""},
		{"with format", []string{"+%Y-%m-%d"}, true, ""},
		{"utc time", []string{"-u"}, true, ""},
		{"rfc format", []string{"-R"}, true, ""},
		{"help", []string{"--help"}, true, ""},
		{"version", []string{"--version"}, true, ""},

		// Dangerous operations (should be blocked)
		{"output redirect", []string{">output.txt"}, false, "appears to redirect output"},
		{"append redirect", []string{">>output.txt"}, false, "appears to redirect output"},
		{"pipe", []string{"| cat"}, false, "appears to redirect output"},
		{"command substitution", []string{"$(whoami)"}, false, "appears to contain command substitution"},
		{"backticks", []string{"`whoami`"}, false, "appears to contain command substitution"},
		{"mixed safe and dangerous", []string{"+%Y-%m-%d", ">output.txt"}, false, "appears to redirect output"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := AreDateArgsSafe(tt.args)
			if got != tt.want {
				t.Errorf("AreDateArgsSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("AreDateArgsSafe(%v) error = %q, want %q", tt.args, gotErr, tt.wantErr)
			}
		})
	}
}
