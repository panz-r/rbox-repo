package rosed

import (
	"testing"
)

// Test IsSedOptionSafe function
func TestIsSedOptionSafe(t *testing.T) {
	tests := []struct {
		name   string
		option string
		want   bool
	}{
		// Safe options that should be allowed
		{"suppress printing -n", "-n", true},
		{"suppress printing --quiet", "--quiet", true},
		{"suppress printing --silent", "--silent", true},
		{"add script -e", "-e", true},
		{"add script --expression", "--expression", true},
		{"add script from file -f", "-f", true},
		{"add script from file --file", "--file", true},
		{"help --help", "--help", true},
		{"version --version", "--version", true},

		// Dangerous options that should be blocked
		{"edit in place -i", "-i", false},
		{"edit in place --in-place", "--in-place", false},
		{"follow symlinks --follow-symlinks", "--follow-symlinks", false},
		{"debug --debug", "--debug", false},
		{"posix --posix", "--posix", false},

		// Unknown options should be blocked
		{"unknown option -x", "-x", false},
		{"unknown option --unknown", "--unknown", false},

		// Non-option arguments (filenames/scripts) should be allowed for further validation
		{"filename argument", "file.txt", true},
		{"script argument", "s/old/new/g", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsSedOptionSafe(tt.option)
			if got != tt.want {
				t.Errorf("IsSedOptionSafe(%q) = %v, want %v", tt.option, got, tt.want)
			}
		})
	}
}

// Test IsSedScriptSafe function
func TestIsSedScriptSafe(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   bool
	}{
		// Safe sed scripts that should be allowed
		{"print specific line", "5p", true},
		{"print from line to end", "10,$", true},
		{"print line range", "5,10p", true},
		{"print lines matching pattern", "/error/p", true},
		{"quit after line", "10q", true},
		{"quit after pattern", "/success/q", true},

		// Dangerous sed scripts that should be blocked
		{"substitution command", "s/old/new/g", false},
		{"transliteration command", "y/abc/XYZ/", false},
		{"append text", "a\\new text", false},
		{"insert text", "i\\new text", false},
		{"change text", "c\\new text", false},
		{"delete line", "d", false},
		{"delete first part", "D", false},
		{"append next line", "N", false},
		{"write to file", "w output.txt", false},
		{"write first line to file", "W output.txt", false},
		{"read file", "r input.txt", false},
		{"execute command", "e date", false},
		{"execute command short", "e", false},

		// Complex dangerous scripts
		{"multiple dangerous commands", "s/a/b/;d", false},
		{"substitution with pattern", "/pattern/s/old/new/", false},
		{"write with pattern", "/error/w errors.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsSedScriptSafe(tt.script)
			if got != tt.want {
				t.Errorf("IsSedScriptSafe(%q) safe = %v, want %v", tt.script, got, tt.want)
			}
		})
	}
}

// Test IsSedSafe function
func TestIsSedSafe(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		// Safe sed commands
		{"print specific line", []string{"5p"}, true},
		{"print lines matching pattern", []string{"/error/p"}, true},
		{"print with quiet option", []string{"-n", "5p"}, true},
		{"print range with expression", []string{"-e", "5,10p"}, true},
		{"help option", []string{"--help"}, true},
		{"version option", []string{"--version"}, true},

		// Dangerous sed commands
		{"substitution command", []string{"s/old/new/g"}, false},
		{"substitution with options", []string{"-e", "s/old/new/g"}, false},
		{"delete command", []string{"d"}, false},
		{"write to file", []string{"w output.txt"}, false},
		{"read from file", []string{"r input.txt"}, false},
		{"execute command", []string{"e date"}, false},

		// Dangerous options
		{"edit in place", []string{"-i", "s/old/new/g"}, false},
		{"edit in place long", []string{"--in-place", "s/old/new/g"}, false},

		// Edge cases
		{"no arguments", []string{}, false},
		{"unknown option", []string{"-x"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsSedSafe(tt.args)
			if got != tt.want {
				t.Errorf("IsSedSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
