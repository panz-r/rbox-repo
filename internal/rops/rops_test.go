package rops

import (
	"strings"
	"testing"
)

// Test IsDangerousPsOption function
func TestIsDangerousPsOption(t *testing.T) {
	tests := []struct {
		arg      string
		want     bool
		wantErr  string
	}{
		// Safe options
		{"--format", false, ""},
		{"--no-headers", false, ""},
		{"--headers", false, ""},
		{"--sort", false, ""},
		{"-o", false, ""},
		{"-f", false, ""},
		{"aux", false, ""},
		{"ef", false, ""},
		{"-p", false, ""},
		{"1234", false, ""},
		{"user", false, ""},

		// Dangerous patterns
		{"`echo test`", true, "contains potential command injection characters"},
		{"$(whoami)", true, "contains potential command injection characters"},
		{strings.Repeat("a", 51), true, "suspiciously long option"},
		{"--" + strings.Repeat("a", 48), true, "suspiciously long option"},
	}

	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			got, gotErr := IsDangerousPsOption(tt.arg)
			if got != tt.want {
				t.Errorf("IsDangerousPsOption(%q) dangerous = %v, want %v", tt.arg, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("IsDangerousPsOption(%q) error = %q, want %q", tt.arg, gotErr, tt.wantErr)
			}
		})
	}
}

// Test ArePsArgsSafe function
func TestArePsArgsSafe(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    bool
		wantErr string
	}{
		// Safe argument combinations
		{"empty", []string{}, true, ""},
		{"simple aux", []string{"aux"}, true, ""},
		{"format with args", []string{"--format", "pid,ppid,cmd"}, true, ""},
		{"process by id", []string{"--pid", "1234"}, true, ""},
		{"user processes", []string{"--user", "john"}, true, ""},
		{"full format", []string{"ef"}, true, ""},
		{"multiple options", []string{"--no-headers", "--sort", "-pcpu"}, true, ""},

		// Dangerous argument combinations
		{"command injection", []string{"`rm -rf /`"}, false, "contains potential command injection characters"},
		{"variable expansion", []string{"$(whoami)"}, false, "contains potential command injection characters"},
		{"long option", []string{strings.Repeat("a", 51)}, false, "suspiciously long option"},
		{"mixed safe and dangerous", []string{"aux", "`echo test`"}, false, "contains potential command injection characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := ArePsArgsSafe(tt.args)
			if got != tt.want {
				t.Errorf("ArePsArgsSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("ArePsArgsSafe(%v) error = %q, want %q", tt.args, gotErr, tt.wantErr)
			}
		})
	}
}