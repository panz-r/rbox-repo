package rouname

import (
	"strings"
	"testing"
)

// Test IsDangerousUnameOption function
func TestIsDangerousUnameOption(t *testing.T) {
	tests := []struct {
		arg      string
		want     bool
		wantErr  string
	}{
		// Safe options
		{"--help", false, ""},
		{"--version", false, ""},
		{"-h", false, ""},
		{"-a", false, ""},
		{"--all", false, ""},
		{"-s", false, ""},
		{"--kernel-name", false, ""},
		{"-n", false, ""},
		{"--nodename", false, ""},
		{"-r", false, ""},
		{"--kernel-release", false, ""},
		{"-v", false, ""},
		{"--kernel-version", false, ""},
		{"-m", false, ""},
		{"--machine", false, ""},
		{"-p", false, ""},
		{"--processor", false, ""},
		{"-i", false, ""},
		{"--hardware-platform", false, ""},
		{"-o", false, ""},
		{"--operating-system", false, ""},

		// Dangerous patterns
		{"`echo test`", true, "contains potential command injection characters"},
		{"$(whoami)", true, "contains potential command injection characters"},
		{strings.Repeat("a", 51), true, "suspiciously long option"},
		{"--" + strings.Repeat("a", 48), true, "suspiciously long option"},
	}

	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			got, gotErr := IsDangerousUnameOption(tt.arg)
			if got != tt.want {
				t.Errorf("IsDangerousUnameOption(%q) dangerous = %v, want %v", tt.arg, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("IsDangerousUnameOption(%q) error = %q, want %q", tt.arg, gotErr, tt.wantErr)
			}
		})
	}
}

// Test AreUnameArgsSafe function
func TestAreUnameArgsSafe(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    bool
		wantErr string
	}{
		// Safe argument combinations
		{"empty", []string{}, true, ""},
		{"all info", []string{"-a"}, true, ""},
		{"kernel name", []string{"-s"}, true, ""},
		{"kernel release", []string{"-r"}, true, ""},
		{"machine", []string{"-m"}, true, ""},
		{"processor", []string{"-p"}, true, ""},
		{"help", []string{"--help"}, true, ""},
		{"multiple options", []string{"-s", "-r", "-m"}, true, ""},
		{"all options", []string{"-a", "--kernel-name", "--nodename"}, true, ""},

		// Dangerous argument combinations
		{"command injection", []string{"`rm -rf /`"}, false, "contains potential command injection characters"},
		{"variable expansion", []string{"$(whoami)"}, false, "contains potential command injection characters"},
		{"long option", []string{strings.Repeat("a", 51)}, false, "suspiciously long option"},
		{"mixed safe and dangerous", []string{"-a", "`echo test`"}, false, "contains potential command injection characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := AreUnameArgsSafe(tt.args)
			if got != tt.want {
				t.Errorf("AreUnameArgsSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("AreUnameArgsSafe(%v) error = %q, want %q", tt.args, gotErr, tt.wantErr)
			}
		})
	}
}