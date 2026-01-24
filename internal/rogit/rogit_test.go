package rogit

import (
	"testing"
)

// Test IsWriteCommand function
func TestIsWriteCommand(t *testing.T) {
	tests := []struct {
		command string
		want    bool
	}{
		// Write commands that should be blocked
		{"add", true},
		{"commit", true},
		{"push", true},
		{"pull", true},
		{"merge", true},
		{"rebase", true},
		{"reset", true},
		{"rm", true},
		{"mv", true},
		{"tag", true},
		{"stash", true},
		{"checkout", true},
		{"fetch", true},
		{"clone", true},
		{"init", true},
		{"submodule", true},
		{"config", false}, // config needs special handling

		// Read commands that should be allowed
		{"branch", false}, // git branch is a read operation
		{"remote", false}, // git remote is a read operation

		// Read commands that should be allowed
		{"log", false},
		{"show", false},
		{"diff", false},
		{"status", false},
		{"grep", false},
		{"blame", false},
		{"help", false},
		{"version", false},
		{"check-attr", false},
		{"check-ignore", false},
		{"check-mailmap", false},
		{"check-ref-format", false},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := IsWriteCommand(tt.command)
			if got != tt.want {
				t.Errorf("IsWriteCommand(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// Test IsConfigWriteOperation function
func TestIsConfigWriteOperation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		// Read operations - should be allowed
		{"list all", []string{"--list"}, false},
		{"get single", []string{"--get", "user.name"}, false},
		{"show all", []string{"--show"}, false},
		{"get with value", []string{"--get", "user.email"}, false},
		{"list with pattern", []string{"--list", "*.url"}, false},

		// Write operations - should be blocked
		{"set value", []string{"user.name", "John"}, true},
		{"set with spaces", []string{"user.name", "John Doe"}, true},
		{"add new", []string{"--add", "remote.origin", "git@github.com:user/repo.git"}, true},
		{"replace existing", []string{"--replace-all", "user.email", "john@example.com"}, true},
		{"unset config", []string{"--unset", "user.password"}, true},
		{"unset all", []string{"--unset-all", "http.proxy"}, true},
		{"multiple values", []string{"user.name", "John", "Doe"}, true},

		// Edge cases
		{"empty args", []string{}, false},
		{"single arg no dash", []string{"user.name"}, false}, // This is actually a get operation
		{"mixed flags", []string{"--list", "--add", "key", "value"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsConfigWriteOperation(tt.args)
			if got != tt.want {
				t.Errorf("IsConfigWriteOperation(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

// Test IsAllowedCommand function
func TestIsAllowedCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		want    bool
		wantErr string
	}{
		// Safe commands
		{"log", "log", []string{"--oneline"}, true, ""},
		{"show", "show", []string{"HEAD"}, true, ""},
		{"diff", "diff", []string{"HEAD~1"}, true, ""},
		{"status", "status", []string{}, true, ""},
		{"help", "help", []string{}, true, ""},
		{"version", "version", []string{}, true, ""},

		// Blocked write commands
		{"add", "add", []string{"."}, false, "write operation not allowed"},
		{"commit", "commit", []string{"-m", "test"}, false, "write operation not allowed"},
		{"push", "push", []string{"origin", "main"}, false, "write operation not allowed"},
		{"pull", "pull", []string{}, false, "write operation not allowed"},
		{"merge", "merge", []string{"feature"}, false, "write operation not allowed"},
		{"rebase", "rebase", []string{"main"}, false, "write operation not allowed"},

		// Config read operations (allowed)
		{"config list", "config", []string{"--list"}, true, ""},
		{"config get", "config", []string{"--get", "user.name"}, true, ""},
		{"config show", "config", []string{"--show"}, true, ""},

		// Config write operations (blocked)
		{"config set", "config", []string{"user.name", "John"}, false, "config modification not allowed"},
		{"config add", "config", []string{"--add", "remote.origin", "git@github.com:user/repo.git"}, false, "config modification not allowed"},
		{"config replace", "config", []string{"--replace-all", "user.email", "john@example.com"}, false, "config modification not allowed"},
		{"config unset", "config", []string{"--unset", "user.password"}, false, "config modification not allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := IsAllowedCommand(tt.command, tt.args)
			if got != tt.want {
				t.Errorf("IsAllowedCommand(%q, %v) allowed = %v, want %v", tt.command, tt.args, got, tt.want)
			}
			if gotErr != tt.wantErr {
				t.Errorf("IsAllowedCommand(%q, %v) error = %q, want %q", tt.command, tt.args, gotErr, tt.wantErr)
			}
		})
	}
}
