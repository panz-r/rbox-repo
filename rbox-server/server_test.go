//go:build cgo
// +build cgo

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSocketPath(t *testing.T) {
	tests := []struct {
		name        string
		cmdSocket   string
		forceSystem bool
		forceUser   bool
		envSocket   string
		xdgRuntime  string
		expected    string
	}{
		{
			name:        "Explicit socket path",
			cmdSocket:   "/tmp/custom.sock",
			forceSystem: false,
			forceUser:   false,
			envSocket:   "",
			xdgRuntime:  "",
			expected:    "/tmp/custom.sock",
		},
		{
			name:        "System socket",
			cmdSocket:   "",
			forceSystem: true,
			forceUser:   false,
			envSocket:   "",
			xdgRuntime:  "",
			expected:    SystemSocketPath,
		},
		{
			name:        "User socket with XDG_RUNTIME_DIR",
			cmdSocket:   "",
			forceSystem: false,
			forceUser:   true,
			envSocket:   "",
			xdgRuntime:  "/run/user/1000",
			expected:    "/run/user/1000/readonlybox.sock",
		},
		{
			name:        "Env socket takes priority over XDG_RUNTIME_DIR",
			cmdSocket:   "",
			forceSystem: false,
			forceUser:   false,
			envSocket:   "/var/run/my.sock",
			xdgRuntime:  "/run/user/1000",
			expected:    "/var/run/my.sock",
		},
		{
			name:        "User socket falls back to system when XDG_RUNTIME_DIR not set",
			cmdSocket:   "",
			forceSystem: false,
			forceUser:   true,
			envSocket:   "",
			xdgRuntime:  "",
			expected:    SystemSocketPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.xdgRuntime != "" {
				t.Setenv("XDG_RUNTIME_DIR", tt.xdgRuntime)
			} else {
				t.Setenv("XDG_RUNTIME_DIR", "")
			}
			if tt.envSocket != "" {
				t.Setenv(EnvSocket, tt.envSocket)
			} else {
				t.Setenv(EnvSocket, "")
			}

			result := getSocketPath(tt.cmdSocket, tt.forceSystem, tt.forceUser)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMakeNoninteractiveDecision(t *testing.T) {
	tests := []struct {
		name     string
		cmd      string
		args     []string
		autoDeny bool
		expected uint8
		reason   string
	}{
		// Empty command
		{
			name:     "Empty command",
			cmd:      "",
			args:     []string{},
			autoDeny: false,
			expected: DecisionDeny,
			reason:   "empty command",
		},

		// System file modification
		{
			name:     "Tries to modify /etc/passwd",
			cmd:      "cp",
			args:     []string{"/etc/passwd", "/tmp/passwd.bak"},
			autoDeny: false,
			expected: DecisionDeny,
			reason:   "tries to modify system file",
		},
		{
			name:     "Tries to modify /etc/shadow",
			cmd:      "cat",
			args:     []string{"/etc/shadow"},
			autoDeny: false,
			expected: DecisionDeny,
			reason:   "tries to modify system file",
		},
		{
			name:     "Tries to modify /etc/group",
			cmd:      "ls",
			args:     []string{"/etc/group"},
			autoDeny: false,
			expected: DecisionDeny,
			reason:   "tries to modify system file",
		},

		// Read-only commands (should always be allowed regardless of autoDeny)
		{
			name:     "ls allowed",
			cmd:      "ls",
			args:     []string{"-l"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "ls allowed even with autoDeny",
			cmd:      "ls",
			args:     []string{"-l"},
			autoDeny: true,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "pwd allowed",
			cmd:      "pwd",
			args:     nil,
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "cd allowed",
			cmd:      "cd",
			args:     []string{"/tmp"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "echo allowed",
			cmd:      "echo",
			args:     []string{"hello"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "cat allowed",
			cmd:      "cat",
			args:     []string{"/tmp/file.txt"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "head allowed",
			cmd:      "head",
			args:     []string{"-n", "10", "/var/log/messages"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "tail allowed",
			cmd:      "tail",
			args:     []string{"-f", "/var/log/syslog"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "less allowed",
			cmd:      "less",
			args:     []string{"/var/log/messages"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "more allowed",
			cmd:      "more",
			args:     []string{"/var/log/messages"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "grep allowed",
			cmd:      "grep",
			args:     []string{"error", "/var/log/messages"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "find allowed",
			cmd:      "find",
			args:     []string{"/home", "-name", "*.txt"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "xargs allowed",
			cmd:      "xargs",
			args:     []string{"echo"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "tr allowed",
			cmd:      "tr",
			args:     []string{"a-z", "A-Z"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "cut allowed",
			cmd:      "cut",
			args:     []string{"-d:", "-f1", "/tmp/users.txt"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "join allowed",
			cmd:      "join",
			args:     []string{"file1.txt", "file2.txt"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "paste allowed",
			cmd:      "paste",
			args:     []string{"file1.txt", "file2.txt"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "comm allowed",
			cmd:      "comm",
			args:     []string{"file1.txt", "file2.txt"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "diff allowed",
			cmd:      "diff",
			args:     []string{"file1.txt", "file2.txt"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "nl allowed",
			cmd:      "nl",
			args:     []string{"file.txt"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "od allowed",
			cmd:      "od",
			args:     []string{"-c", "file.txt"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "base64 allowed",
			cmd:      "base64",
			args:     []string{"file.txt"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "strings allowed",
			cmd:      "strings",
			args:     []string{"binary"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "env allowed",
			cmd:      "env",
			args:     nil,
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "printenv allowed",
			cmd:      "printenv",
			args:     []string{"HOME"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},

		// Dangerous commands (should always be denied regardless of autoDeny)
		{
			name:     "rm denied",
			cmd:      "rm",
			args:     []string{"file.txt"},
			autoDeny: false,
			expected: DecisionDeny,
			reason:   "dangerous command",
		},
		{
			name:     "rm denied even with autoDeny",
			cmd:      "rm",
			args:     []string{"file.txt"},
			autoDeny: true,
			expected: DecisionDeny,
			reason:   "dangerous command",
		},
		{
			name:     "mv denied",
			cmd:      "mv",
			args:     []string{"old.txt", "new.txt"},
			autoDeny: false,
			expected: DecisionDeny,
			reason:   "dangerous command",
		},
		{
			name:     "cp denied",
			cmd:      "cp",
			args:     []string{"file.txt", "/tmp/"},
			autoDeny: false,
			expected: DecisionDeny,
			reason:   "dangerous command",
		},
		{
			name:     "mkdir denied",
			cmd:      "mkdir",
			args:     []string{"/tmp/newdir"},
			autoDeny: false,
			expected: DecisionDeny,
			reason:   "dangerous command",
		},
		{
			name:     "rmdir denied",
			cmd:      "rmdir",
			args:     []string{"/tmp/emptydir"},
			autoDeny: false,
			expected: DecisionDeny,
			reason:   "dangerous command",
		},
		{
			name:     "ln denied",
			cmd:      "ln",
			args:     []string{"file.txt", "link.txt"},
			autoDeny: false,
			expected: DecisionDeny,
			reason:   "dangerous command",
		},
		{
			name:     "chmod denied",
			cmd:      "chmod",
			args:     []string{"755", "file.txt"},
			autoDeny: false,
			expected: DecisionDeny,
			reason:   "dangerous command",
		},
		{
			name:     "chown denied",
			cmd:      "chown",
			args:     []string{"user:group", "file.txt"},
			autoDeny: false,
			expected: DecisionDeny,
			reason:   "dangerous command",
		},
		{
			name:     "touch denied",
			cmd:      "touch",
			args:     []string{"newfile.txt"},
			autoDeny: false,
			expected: DecisionDeny,
			reason:   "dangerous command",
		},
		{
			name:     "dd denied",
			cmd:      "dd",
			args:     []string{"if=/dev/zero", "of=/tmp/file"},
			autoDeny: false,
			expected: DecisionDeny,
			reason:   "dangerous command",
		},

		// Unknown commands
		{
			name:     "Unknown command allowed when autoDeny is false",
			cmd:      "curl",
			args:     []string{"https://example.com"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "unknown command",
		},
		{
			name:     "Unknown command denied when autoDeny is true",
			cmd:      "curl",
			args:     []string{"https://example.com"},
			autoDeny: true,
			expected: DecisionDeny,
			reason:   "unknown command",
		},
		{
			name:     "git allowed when autoDeny is false",
			cmd:      "git",
			args:     []string{"status"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "unknown command",
		},
		{
			name:     "git denied when autoDeny is true",
			cmd:      "git",
			args:     []string{"status"},
			autoDeny: true,
			expected: DecisionDeny,
			reason:   "unknown command",
		},

		// Case insensitivity
		{
			name:     "LS (uppercase) allowed",
			cmd:      "LS",
			args:     []string{"-l"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
		{
			name:     "RM (uppercase) denied",
			cmd:      "RM",
			args:     []string{"file.txt"},
			autoDeny: false,
			expected: DecisionDeny,
			reason:   "dangerous command",
		},
		{
			name:     "Ls (mixed case) allowed",
			cmd:      "Ls",
			args:     []string{"-l"},
			autoDeny: false,
			expected: DecisionAllow,
			reason:   "read-only command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason := makeNoninteractiveDecision(tt.cmd, tt.args, tt.autoDeny)
			assert.Equal(t, tt.expected, decision, "decision mismatch")
			assert.Equal(t, tt.reason, reason, "reason mismatch")
		})
	}
}
