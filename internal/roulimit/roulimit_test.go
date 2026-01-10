package roulimit

import (
	"testing"
)

// Test IsUlimitOptionSafe function
func TestIsUlimitOptionSafe(t *testing.T) {
	tests := []struct {
		name     string
		option   string
		want     bool
	}{
		// Safe read-only options that should be allowed
		{"display all -a", "-a", true},
		{"display all --all", "--all", true},
		{"display core file size -c", "-c", true},
		{"display data seg size -d", "-d", true},
		{"display scheduling priority -e", "-e", true},
		{"display file size -f", "-f", true},
		{"display pending signals -i", "-i", true},
		{"display memory lock -l", "-l", true},
		{"display max memory -m", "-m", true},
		{"display open files -n", "-n", true},
		{"display pipe size -p", "-p", true},
		{"display POSIX queues -q", "-q", true},
		{"display real-time priority -r", "-r", true},
		{"display stack size -s", "-s", true},
		{"display CPU time -t", "-t", true},
		{"display processes -u", "-u", true},
		{"display virtual memory -v", "-v", true},
		{"display file locks -x", "-x", true},
		{"display hard limits -H", "-H", true},
		{"display soft limits -S", "-S", true},
		{"help --help", "--help", true},
		{"version --version", "--version", true},

		// Dangerous options that should be blocked
		{"set numeric limit", "1024", false},
		{"set unlimited", "unlimited", false},
		{"set hard", "hard", false},
		{"set soft", "soft", false},
		{"set UNLIMITED", "UNLIMITED", false},

		// Unknown options should be blocked
		{"unknown option -z", "-z", false},
		{"unknown option --unknown", "--unknown", false},

		// Non-option arguments should be blocked
		{"filename argument", "file.txt", false},
		{"random argument", "random", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsUlimitOptionSafe(tt.option)
			if got != tt.want {
				t.Errorf("IsUlimitOptionSafe(%q) = %v, want %v", tt.option, got, tt.want)
			}
		})
	}
}

// Test IsUlimitSafe function
func TestIsUlimitSafe(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		want     bool
	}{
		// Safe ulimit commands (read-only)
		{"display all limits", []string{"-a"}, true},
		{"display file size limit", []string{"-f"}, true},
		{"display open files limit", []string{"-n"}, true},
		{"display processes limit", []string{"-u"}, true},
		{"display help", []string{"--help"}, true},
		{"display version", []string{"--version"}, true},

		// Dangerous ulimit commands (attempt to set limits)
		{"set core file size", []string{"1024"}, false},
		{"set unlimited", []string{"unlimited"}, false},
		{"set with option", []string{"-f", "1024"}, false},

		// Edge cases
		{"no arguments", []string{}, false},
		{"too many arguments", []string{"-a", "-f"}, false},
		{"unknown option", []string{"-z"}, false},
		{"filename argument", []string{"file.txt"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsUlimitSafe(tt.args)
			if got != tt.want {
				t.Errorf("IsUlimitSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}