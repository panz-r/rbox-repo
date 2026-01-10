package rochown

import (
	"testing"
)

// Test isValidOwnerSpec function
func TestIsValidOwnerSpec(t *testing.T) {
	tests := []struct {
		name     string
		spec     string
		want     bool
	}{
		// Valid owner specifications
		{"simple username", "john", true},
		{"username with dots", "john.doe", true},
		{"username with underscores", "john_doe", true},
		{"username and group", "john:developers", true},
		{"just group", ":developers", true},
		{"username with trailing colon", "john:", true},
		{"numeric uid", "1000", true},
		{"numeric uid and gid", "1000:1000", true},

		// Invalid owner specifications
		{"empty string", "", false},
		{"with space", "john doe", false},
		{"with dangerous pattern", "john; rm -rf /", false},
		{"with pipe", "john|whoami", false},
		{"with redirect", "john>file", false},
		{"with command substitution", "$(whoami)", false},
		{"with special chars", "john<test>", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidOwnerSpec(tt.spec)
			if got != tt.want {
				t.Errorf("isValidOwnerSpec(%q) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

// Test IsChownOptionSafe function
func TestIsChownOptionSafe(t *testing.T) {
	tests := []struct {
		name     string
		option   string
		want     bool
	}{
		// Dangerous options that should be blocked
		{"recursive -R", "-R", false},
		{"recursive --recursive", "--recursive", false},
		{"verbose -v", "-v", false},
		{"verbose --verbose", "--verbose", false},
		{"changes -c", "-c", false},
		{"changes --changes", "--changes", false},
		{"silent -f", "-f", false},
		{"silent --silent", "--silent", false},
		{"no-dereference -h", "-h", false},
		{"no-dereference --no-dereference", "--no-dereference", false},
		{"from --from", "--from", false},
		{"reference --reference", "--reference", false},

		// Safe options that should be allowed
		{"help --help", "--help", true},
		{"version --version", "--version", true},

		// Owner specifications should be blocked (they change ownership)
		{"username only", "john", false},
		{"username:group", "john:developers", false},
		{"just group", ":developers", false},
		{"numeric uid", "1000", false},
		{"numeric uid:gid", "1000:1000", false},

		// Unknown options should be blocked
		{"unknown option -x", "-x", false},
		{"unknown option --unknown", "--unknown", false},

		// Filename arguments should be allowed (they won't do anything)
		{"filename", "file.txt", true},
		{"filename with path", "/path/to/file", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsChownOptionSafe(tt.option)
			if got != tt.want {
				t.Errorf("IsChownOptionSafe(%q) = %v, want %v", tt.option, got, tt.want)
			}
		})
	}
}

// Test IsChownSafe function
func TestIsChownSafe(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		want     bool
	}{
		// Safe chown commands (read-only or informational)
		{"help option", []string{"--help"}, true},
		{"version option", []string{"--version"}, true},

		// Dangerous chown commands (attempt to modify ownership)
		{"simple ownership change", []string{"john", "file.txt"}, false},
		{"username:group change", []string{"john:developers", "file.txt"}, false},
		{"numeric uid change", []string{"1000", "file.txt"}, false},
		{"recursive ownership change", []string{"-R", "john", "dir"}, false},
		{"verbose ownership change", []string{"-v", "john", "file.txt"}, false},
		{"reference ownership", []string{"--reference=ref", "file.txt"}, false},

		// Edge cases
		{"no arguments", []string{}, false},
		{"unknown option", []string{"-x"}, false},
		{"multiple files", []string{"john", "file1.txt", "file2.txt"}, false},
		{"just filenames", []string{"file.txt"}, true}, // No owner spec = safe
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsChownSafe(tt.args)
			if got != tt.want {
				t.Errorf("IsChownSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}