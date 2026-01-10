package rosort

import (
	"testing"
)

// Test IsSortOptionSafe function
func TestIsSortOptionSafe(t *testing.T) {
	tests := []struct {
		name     string
		option   string
		want     bool
	}{
		// Dangerous options that should be blocked
		{"output option -o", "-o", false},
		{"output option --output", "--output", false},
		{"temporary directory -T", "-T", false},
		{"temporary directory --temporary-directory", "--temporary-directory", false},
		{"sort script --sort", "--sort", false},

		// Safe options that should be allowed
		{"ignore leading blanks -b", "-b", true},
		{"ignore leading blanks --ignore-leading-blanks", "--ignore-leading-blanks", true},
		{"dictionary order -d", "-d", true},
		{"ignore case -f", "-f", true},
		{"general numeric sort -g", "-g", true},
		{"human numeric sort -h", "-h", true},
		{"ignore nonprinting -i", "-i", true},
		{"key -k", "-k", true},
		{"month sort -M", "-M", true},
		{"numeric sort -n", "-n", true},
		{"reverse -r", "-r", true},
		{"random sort -R", "-R", true},
		{"stable -s", "-s", true},
		{"field separator -t", "-t", true},
		{"unique -u", "-u", true},
		{"zero terminated -z", "-z", true},
		{"help --help", "--help", true},
		{"version --version", "--version", true},
		{"check -c", "-c", true},
		{"check --check", "--check", true},
		{"merge -m", "-m", true},
		{"merge --merge", "--merge", true},
		{"buffer size -S", "-S", true},
		{"buffer size --buffer-size", "--buffer-size", true},
		{"parallel --parallel", "--parallel", true},
		{"files0-from --files0-from", "--files0-from", true},

		// Unknown options should be blocked
		{"unknown option -x", "-x", false},
		{"unknown option --unknown", "--unknown", false},

		// Filenames should be allowed (not options)
		{"filename", "input.txt", true},
		{"filename with path", "/path/to/file.txt", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsSortOptionSafe(tt.option)
			if got != tt.want {
				t.Errorf("IsSortOptionSafe(%q) = %v, want %v", tt.option, got, tt.want)
			}
		})
	}
}

// Test AreSortArgsSafe function
func TestAreSortArgsSafe(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		want     bool
	}{
		// Safe sort commands
		{"no args", []string{}, true},
		{"simple sort", []string{"file.txt"}, true},
		{"sort with reverse", []string{"-r", "file.txt"}, true},
		{"sort with numeric", []string{"-n", "file.txt"}, true},
		{"sort with multiple safe options", []string{"-r", "-n", "-u", "file.txt"}, true},
		{"sort with key", []string{"-k", "2", "file.txt"}, true},
		{"sort with field separator", []string{"-t", ",", "file.txt"}, true},

		// Dangerous sort commands
		{"sort with output option", []string{"-o", "output.txt", "file.txt"}, false},
		{"sort with long output option", []string{"--output", "output.txt", "file.txt"}, false},
		{"sort with temporary directory", []string{"-T", "/tmp", "file.txt"}, false},
		{"sort with sort script", []string{"--sort", "script.sh", "file.txt"}, false},

		// Mixed safe and dangerous
		{"safe then dangerous", []string{"-r", "-o", "output.txt", "file.txt"}, false},

		// Unknown options
		{"unknown option", []string{"-x", "file.txt"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := AreSortArgsSafe(tt.args)
			if got != tt.want {
				t.Errorf("AreSortArgsSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}