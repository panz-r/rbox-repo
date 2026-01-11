package rodf

import (
	"strings"
	"testing"
)

// Test IsDangerousDfOption function
func TestIsDangerousDfOption(t *testing.T) {
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
		{"-i", false, ""},
		{"--inodes", false, ""},
		{"-k", false, ""},
		{"-m", false, ""},
		{"-g", false, ""},
		{"-T", false, ""},
		{"-t", false, ""},
		{"--type", false, ""},
		{"-x", false, ""},
		{"--exclude-type", false, ""},
		{"/home", false, ""},
		{"/", false, ""},
		{".", false, ""},

		// Dangerous patterns
		{"`echo test`", true, "contains potential command injection characters"},
		{"$(whoami)", true, "contains potential command injection characters"},
		{strings.Repeat("a", 51), true, "suspiciously long option"},
		{"--" + strings.Repeat("a", 48), true, "suspiciously long option"},
	}

	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			got, gotErr := IsDangerousDfOption(tt.arg)
			if got != tt.want {
				t.Errorf("IsDangerousDfOption(%q) dangerous = %v, want %v", tt.arg, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("IsDangerousDfOption(%q) error = %q, want %q", tt.arg, gotErr, tt.wantErr)
			}
		})
	}
}

// Test AreDfArgsSafe function
func TestAreDfArgsSafe(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    bool
		wantErr string
	}{
		// Safe argument combinations
		{"empty", []string{}, true, ""},
		{"simple", []string{"/home"}, true, ""},
		{"help", []string{"--help"}, true, ""},
		{"all filesystems", []string{"-a"}, true, ""},
		{"inodes", []string{"-i"}, true, ""},
		{"human readable", []string{"-h"}, true, ""},
		{"type filter", []string{"-t", "ext4"}, true, ""},
		{"exclude type", []string{"--exclude-type", "tmpfs"}, true, ""},
		{"multiple paths", []string{"/", "/home"}, true, ""},
		{"complex", []string{"-h", "-T", "--exclude-type=tmpfs", "/"}, true, ""},

		// Dangerous argument combinations
		{"command injection", []string{"`rm -rf /`"}, false, "contains potential command injection characters"},
		{"variable expansion", []string{"$(whoami)"}, false, "contains potential command injection characters"},
		{"long option", []string{strings.Repeat("a", 51)}, false, "suspiciously long option"},
		{"mixed safe and dangerous", []string{"-h", "`echo test`"}, false, "contains potential command injection characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := AreDfArgsSafe(tt.args)
			if got != tt.want {
				t.Errorf("AreDfArgsSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("AreDfArgsSafe(%v) error = %q, want %q", tt.args, gotErr, tt.wantErr)
			}
		})
	}
}