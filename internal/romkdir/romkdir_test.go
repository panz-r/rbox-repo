package romkdir

import (
	"testing"
)

// Test IsMkdirOptionSafe function
func TestIsMkdirOptionSafe(t *testing.T) {
	tests := []struct {
		name   string
		option string
		want   bool
	}{
		// Dangerous options that should be blocked
		{"parents -p", "-p", false},
		{"parents --parents", "--parents", false},
		{"verbose -v", "-v", false},
		{"verbose --verbose", "--verbose", false},
		{"mode -m", "-m", false},
		{"mode --mode", "--mode", false},
		{"context -Z", "-Z", false},
		{"context --context", "--context", false},

		// Safe options that should be allowed
		{"help --help", "--help", true},
		{"version --version", "--version", true},

		// Directory names should be blocked (they would create directories)
		{"simple directory", "newdir", false},
		{"directory with path", "path/to/newdir", false},
		{"directory with spaces", "new directory", false},
		{"current directory", ".", false},
		{"parent directory", "..", false},

		// Unknown options should be blocked
		{"unknown option -x", "-x", false},
		{"unknown option --unknown", "--unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsMkdirOptionSafe(tt.option)
			if got != tt.want {
				t.Errorf("IsMkdirOptionSafe(%q) = %v, want %v", tt.option, got, tt.want)
			}
		})
	}
}

// Test IsMkdirSafe function
func TestIsMkdirSafe(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		// Safe mkdir commands (read-only or informational)
		{"help option", []string{"--help"}, true},
		{"version option", []string{"--version"}, true},

		// Dangerous mkdir commands (attempt to create directories)
		{"simple directory", []string{"newdir"}, false},
		{"directory with path", []string{"path/to/newdir"}, false},
		{"multiple directories", []string{"dir1", "dir2"}, false},
		{"with parents option", []string{"-p", "newdir"}, false},
		{"with verbose option", []string{"-v", "newdir"}, false},
		{"with mode option", []string{"-m", "755", "newdir"}, false},

		// Edge cases
		{"no arguments", []string{}, false},
		{"unknown option", []string{"-x"}, false},
		{"mixed safe and dangerous", []string{"--help", "newdir"}, false},
		{"current directory", []string{"."}, false},
		{"parent directory", []string{".."}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsMkdirSafe(tt.args)
			if got != tt.want {
				t.Errorf("IsMkdirSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
