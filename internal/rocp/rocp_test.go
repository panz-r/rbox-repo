package rocp

import (
	"testing"
)

// Test IsCopyOptionSafe function
func TestIsCopyOptionSafe(t *testing.T) {
	tests := []struct {
		name   string
		option string
		want   bool
	}{
		// Dangerous options that should be blocked
		{"archive -a", "-a", false},
		{"archive --archive", "--archive", false},
		{"backup -b", "-b", false},
		{"backup --backup", "--backup", false},
		{"force -f", "-f", false},
		{"force --force", "--force", false},
		{"interactive -i", "-i", false},
		{"interactive --interactive", "--interactive", false},
		{"link -l", "-l", false},
		{"link --link", "--link", false},
		{"dereference -L", "-L", false},
		{"dereference --dereference", "--dereference", false},
		{"preserve -p", "-p", false},
		{"preserve --preserve", "--preserve", false},
		{"recursive -r", "-r", false},
		{"recursive -R", "-R", false},
		{"recursive --recursive", "--recursive", false},
		{"symbolic-link -s", "-s", false},
		{"symbolic-link --symbolic-link", "--symbolic-link", false},
		{"suffix -S", "-S", false},
		{"suffix --suffix", "--suffix", false},
		{"update -u", "-u", false},
		{"update --update", "--update", false},
		{"verbose -v", "-v", false},
		{"verbose --verbose", "--verbose", false},
		{"one-file-system -x", "-x", false},
		{"one-file-system --one-file-system", "--one-file-system", false},
		{"context -Z", "-Z", false},
		{"context --context", "--context", false},
		{"target-directory -t", "-t", false},
		{"target-directory --target-directory", "--target-directory", false},
		{"no-target-directory -T", "-T", false},
		{"no-target-directory --no-target-directory", "--no-target-directory", false},

		// Safe options that should be allowed
		{"help --help", "--help", true},
		{"version --version", "--version", true},

		// File arguments should be blocked (they would copy files)
		{"source file", "source.txt", false},
		{"target file", "target.txt", false},
		{"directory source", "source_dir", false},
		{"directory target", "target_dir", false},

		// Unknown options should be blocked
		{"unknown option -y", "-y", false},
		{"unknown option --unknown", "--unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsCopyOptionSafe(tt.option)
			if got != tt.want {
				t.Errorf("IsCopyOptionSafe(%q) = %v, want %v", tt.option, got, tt.want)
			}
		})
	}
}

// Test IsCopySafe function
func TestIsCopySafe(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		// Safe cp commands (read-only or informational)
		{"help option", []string{"--help"}, true},
		{"version option", []string{"--version"}, true},

		// Dangerous cp commands (attempt to copy files)
		{"simple copy", []string{"source.txt", "target.txt"}, false},
		{"copy to directory", []string{"source.txt", "target_dir/"}, false},
		{"multiple files", []string{"file1.txt", "file2.txt", "target_dir/"}, false},
		{"with archive option", []string{"-a", "source.txt", "target.txt"}, false},
		{"with recursive option", []string{"-r", "source_dir", "target_dir"}, false},
		{"with verbose option", []string{"-v", "source.txt", "target.txt"}, false},
		{"with force option", []string{"-f", "source.txt", "target.txt"}, false},

		// Edge cases
		{"no arguments", []string{}, false},
		{"unknown option", []string{"-y"}, false},
		{"mixed safe and dangerous", []string{"--help", "source.txt"}, false},
		{"single file", []string{"source.txt"}, false}, // Missing target
		{"directory copy", []string{"source_dir", "target_dir"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsCopySafe(tt.args)
			if got != tt.want {
				t.Errorf("IsCopySafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
