package rodu

import (
	"strings"
	"testing"
)

// Test IsDangerousDuOption function
func TestIsDangerousDuOption(t *testing.T) {
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
		{"--summarize", false, ""},
		{"-k", false, ""},
		{"-m", false, ""},
		{"-g", false, ""},
		{"-d", false, ""},
		{"--max-depth", false, ""},
		{"-c", false, ""},
		{"--total", false, ""},
		{"--human-readable", false, ""},
		{"--si", false, ""},
		{"--apparent-size", false, ""},
		{"--block-size", false, ""},
		{"/home", false, ""},
		{"/", false, ""},
		{".", false, ""},
		{"1", false, ""},
		{"10", false, ""},

		// Dangerous patterns
		{"`echo test`", true, "contains potential command injection characters"},
		{"$(whoami)", true, "contains potential command injection characters"},
		{strings.Repeat("a", 51), true, "suspiciously long option"},
		{"--" + strings.Repeat("a", 48), true, "suspiciously long option"},
	}

	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			got, gotErr := IsDangerousDuOption(tt.arg)
			if got != tt.want {
				t.Errorf("IsDangerousDuOption(%q) dangerous = %v, want %v", tt.arg, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("IsDangerousDuOption(%q) error = %q, want %q", tt.arg, gotErr, tt.wantErr)
			}
		})
	}
}

// Test AreDuArgsSafe function
func TestAreDuArgsSafe(t *testing.T) {
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
		{"all files", []string{"-a"}, true, ""},
		{"summarize", []string{"-s"}, true, ""},
		{"human readable", []string{"-h"}, true, ""},
		{"max depth", []string{"--max-depth=1"}, true, ""},
		{"total", []string{"-c"}, true, ""},
		{"block size", []string{"--block-size=1M"}, true, ""},
		{"multiple paths", []string{"/", "/home"}, true, ""},
		{"complex", []string{"-h", "--max-depth=2", "--apparent-size", "/home"}, true, ""},

		// Dangerous argument combinations
		{"command injection", []string{"`rm -rf /`"}, false, "contains potential command injection characters"},
		{"variable expansion", []string{"$(whoami)"}, false, "contains potential command injection characters"},
		{"long option", []string{strings.Repeat("a", 51)}, false, "suspiciously long option"},
		{"mixed safe and dangerous", []string{"-h", "`echo test`"}, false, "contains potential command injection characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := AreDuArgsSafe(tt.args)
			if got != tt.want {
				t.Errorf("AreDuArgsSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("AreDuArgsSafe(%v) error = %q, want %q", tt.args, gotErr, tt.wantErr)
			}
		})
	}
}