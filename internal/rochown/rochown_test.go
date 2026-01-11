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

		// Filename arguments should be allowed as they're not valid options or owner specs
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

// Test parseChownCommand function
func TestParseChownCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantOptions []string
		wantOwner   string
		wantFiles   []string
		wantErr     bool
	}{
		// Basic cases
		{"simple ownership change", []string{"john", "file.txt"}, nil, "john", []string{"file.txt"}, false},
		{"username:group change", []string{"john:developers", "file.txt"}, nil, "john:developers", []string{"file.txt"}, false},
		{"numeric uid change", []string{"1000", "file.txt"}, nil, "1000", []string{"file.txt"}, false},
		{"multiple files", []string{"john", "file1.txt", "file2.txt"}, nil, "john", []string{"file1.txt", "file2.txt"}, false},

		// Options
		{"recursive ownership change", []string{"-R", "john", "dir"}, []string{"-R"}, "john", []string{"dir"}, false},
		{"verbose ownership change", []string{"-v", "john", "file.txt"}, []string{"-v"}, "john", []string{"file.txt"}, false},
		{"clustered options", []string{"-Rv", "john", "file.txt"}, []string{"-R", "-v"}, "john", []string{"file.txt"}, false},
		{"long option", []string{"--recursive", "john", "dir"}, []string{"--recursive"}, "john", []string{"dir"}, false},

		// Reference file (should be treated as ownership change)
		{"reference ownership", []string{"--reference=ref", "file.txt"}, nil, "REFERENCE:ref", []string{"file.txt"}, false},
		{"reference with separate arg", []string{"--reference", "ref", "file.txt"}, nil, "REFERENCE:ref", []string{"file.txt"}, false},

		// Safe cases (no owner spec)
		{"help option", []string{"--help"}, []string{"--help"}, "", nil, false},
		{"version option", []string{"--version"}, []string{"--version"}, "", nil, false},
		{"just filenames", []string{"file.txt"}, nil, "", []string{"file.txt"}, false},
		{"multiple filenames", []string{"file1.txt", "file2.txt"}, nil, "", []string{"file1.txt", "file2.txt"}, false},

		// Error cases
		{"no arguments", []string{}, nil, "", nil, true},
		{"unknown option", []string{"-x"}, nil, "", nil, true},
		{"reference without files", []string{"--reference=ref"}, nil, "", nil, true},
		{"reference missing arg", []string{"--reference"}, nil, "", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOptions, gotOwner, gotFiles, err := parseChownCommand(tt.args)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseChownCommand(%v) expected error, got none", tt.args)
				}
				return
			} else if err != nil {
				t.Errorf("parseChownCommand(%v) unexpected error: %v", tt.args, err)
				return
			}

			// Check options
			if len(gotOptions) != len(tt.wantOptions) {
				t.Errorf("parseChownCommand(%v) options = %v, want %v", tt.args, gotOptions, tt.wantOptions)
			} else {
				for i, opt := range gotOptions {
					if opt != tt.wantOptions[i] {
						t.Errorf("parseChownCommand(%v) options[%d] = %v, want %v", tt.args, i, opt, tt.wantOptions[i])
					}
				}
			}

			// Check owner
			if gotOwner != tt.wantOwner {
				t.Errorf("parseChownCommand(%v) owner = %v, want %v", tt.args, gotOwner, tt.wantOwner)
			}

			// Check files
			if len(gotFiles) != len(tt.wantFiles) {
				t.Errorf("parseChownCommand(%v) files = %v, want %v", tt.args, gotFiles, tt.wantFiles)
			} else {
				for i, file := range gotFiles {
					if file != tt.wantFiles[i] {
						t.Errorf("parseChownCommand(%v) files[%d] = %v, want %v", tt.args, i, file, tt.wantFiles[i])
					}
				}
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
		{"just filenames", []string{"file.txt"}, true},
		{"multiple filenames", []string{"file1.txt", "file2.txt"}, true},

		// Dangerous chown commands (attempt to modify ownership)
		{"simple ownership change", []string{"john", "file.txt"}, false},
		{"username:group change", []string{"john:developers", "file.txt"}, false},
		{"numeric uid change", []string{"1000", "file.txt"}, false},
		{"recursive ownership change", []string{"-R", "john", "dir"}, false},
		{"verbose ownership change", []string{"-v", "john", "file.txt"}, false},
		{"reference ownership", []string{"--reference=ref", "file.txt"}, false},
		{"multiple files", []string{"john", "file1.txt", "file2.txt"}, false},

		// Edge cases
		{"no arguments", []string{}, false},
		{"unknown option", []string{"-x"}, false},

		// New test cases for proper parsing
		{"single username without files", []string{"john"}, false}, // Looks like ownership change attempt
		{"owner with colon in filename", []string{"john:developers", "file:with:colons.txt"}, false}, // Should detect owner spec
		{"single numeric uid without files", []string{"1000"}, false}, // Looks like ownership change attempt
		{"complex case", []string{"-Rv", "john:dev", "file1", "file2"}, false},
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