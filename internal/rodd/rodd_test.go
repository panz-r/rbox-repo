package rodd

import (
	"testing"
)

// Test IsDdOptionSafe function
func TestIsDdOptionSafe(t *testing.T) {
	tests := []struct {
		name     string
		option   string
		want     bool
	}{
		// Dangerous options that should be blocked
		{"input file if", "if", false},
		{"output file of", "of", false},
		{"block size bs", "bs", false},
		{"input block size ibs", "ibs", false},
		{"output block size obs", "obs", false},
		{"conversion block size cbs", "cbs", false},
		{"skip blocks skip", "skip", false},
		{"seek blocks seek", "seek", false},
		{"count blocks count", "count", false},
		{"conversion conv", "conv", false},
		{"status level status", "status", false},

		// Safe options that should be allowed
		{"help --help", "--help", true},
		{"version --version", "--version", true},

		// Parameter formats should be blocked
		{"input file parameter", "if=/dev/sda", false},
		{"output file parameter", "of=output.txt", false},
		{"block size parameter", "bs=512", false},
		{"count parameter", "count=100", false},

		// File/device arguments should be blocked
		{"device file", "/dev/sda", false},
		{"output file", "output.txt", false},
		{"input file", "input.txt", false},

		// Unknown options should be blocked
		{"unknown option -x", "-x", false},
		{"unknown option --unknown", "--unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsDdOptionSafe(tt.option)
			if got != tt.want {
				t.Errorf("IsDdOptionSafe(%q) = %v, want %v", tt.option, got, tt.want)
			}
		})
	}
}

// Test IsDdSafe function
func TestIsDdSafe(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		want     bool
	}{
		// Safe dd commands (read-only or informational)
		{"help option", []string{"--help"}, true},
		{"version option", []string{"--version"}, true},

		// Dangerous dd commands (attempt to perform data operations)
		{"simple copy", []string{"if=input.txt", "of=output.txt"}, false},
		{"device copy", []string{"if=/dev/sda", "of=/dev/sdb"}, false},
		{"with block size", []string{"if=input.txt", "of=output.txt", "bs=512"}, false},
		{"with count", []string{"if=input.txt", "of=output.txt", "count=100"}, false},
		{"with skip", []string{"if=input.txt", "of=output.txt", "skip=10"}, false},
		{"with seek", []string{"if=input.txt", "of=output.txt", "seek=20"}, false},

		// Edge cases
		{"no arguments", []string{}, false},
		{"unknown option", []string{"-x"}, false},
		{"mixed safe and dangerous", []string{"--help", "if=input.txt"}, false},
		{"just input file", []string{"if=input.txt"}, false},
		{"just output file", []string{"of=output.txt"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsDdSafe(tt.args)
			if got != tt.want {
				t.Errorf("IsDdSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}