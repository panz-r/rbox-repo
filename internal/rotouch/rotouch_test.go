package rotouch

import (
	"testing"
)

// Test IsTouchOptionSafe function
func TestIsTouchOptionSafe(t *testing.T) {
	tests := []struct {
		name   string
		option string
		want   bool
	}{
		// Dangerous options that should be blocked
		{"access time -a", "-a", false},
		{"access time --time=atime", "--time=atime", false},
		{"no-create -c", "-c", false},
		{"no-create --no-create", "--no-create", false},
		{"date -d", "-d", false},
		{"date --date", "--date", false},
		{"force -f", "-f", false},
		{"modification time -m", "-m", false},
		{"modification time --time=mtime", "--time=mtime", false},
		{"reference -r", "-r", false},
		{"reference --reference", "--reference", false},
		{"time format -t", "-t", false},
		{"time --time", "--time", false},

		// Safe options that should be allowed
		{"help --help", "--help", true},
		{"version --version", "--version", true},

		// Date formats should be blocked
		{"date format YYYY-MM-DD", "2023-01-01", false},
		{"date format MM/DD/YYYY", "01/01/2023", false},
		{"date format with time", "2023-01-01 12:00:00", false},

		// File arguments should be blocked (they would create/modify files)
		{"simple file", "file.txt", false},
		{"multiple files", "file1.txt", false},
		{"new file", "newfile.txt", false},

		// Unknown options should be blocked
		{"unknown option -x", "-x", false},
		{"unknown option --unknown", "--unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsTouchOptionSafe(tt.option)
			if got != tt.want {
				t.Errorf("IsTouchOptionSafe(%q) = %v, want %v", tt.option, got, tt.want)
			}
		})
	}
}

// Test IsTouchSafe function
func TestIsTouchSafe(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		// Safe touch commands (read-only or informational)
		{"help option", []string{"--help"}, true},
		{"version option", []string{"--version"}, true},

		// Dangerous touch commands (attempt to create/modify files)
		{"simple file", []string{"file.txt"}, false},
		{"multiple files", []string{"file1.txt", "file2.txt"}, false},
		{"with access time", []string{"-a", "file.txt"}, false},
		{"with modification time", []string{"-m", "file.txt"}, false},
		{"with specific date", []string{"-d", "2023-01-01", "file.txt"}, false},
		{"with reference file", []string{"-r", "reference.txt", "file.txt"}, false},
		{"no-create option", []string{"-c", "file.txt"}, false},

		// Edge cases
		{"no arguments", []string{}, false},
		{"unknown option", []string{"-x"}, false},
		{"mixed safe and dangerous", []string{"--help", "file.txt"}, false},
		{"date only", []string{"2023-01-01"}, false},
		{"wildcard pattern", []string{"*.txt"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsTouchSafe(tt.args)
			if got != tt.want {
				t.Errorf("IsTouchSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
