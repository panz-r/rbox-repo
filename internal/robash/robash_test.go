package robash

import (
	"testing"
)

// Test IsCommandAllowed function
func TestIsCommandAllowed(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		// Dangerous commands that should be blocked
		{"rm", "rm", false},
		{"mv", "mv", false},
		{"cp", "cp", false},
		{"dd", "dd", false},
		{"chmod", "chmod", false},
		{"chown", "chown", false},
		{"mkdir", "mkdir", false},
		{"rmdir", "rmdir", false},
		{"ln", "ln", false},
		{"touch", "touch", false},
		{"wget", "wget", false},
		{"curl", "curl", false},
		{"scp", "scp", false},
		{"rsync", "rsync", false},
		{"ssh", "ssh", false},
		{"git", "git", false},
		{"apt", "apt", false},
		{"yum", "yum", false},
		{"make", "make", false},
		{"gcc", "gcc", false},
		{"go", "go", false},
		{"docker", "docker", false},
		{"systemctl", "systemctl", false},
		{"kill", "kill", false},
		{"sudo", "sudo", false},
		{"reboot", "reboot", false},
		{"mount", "mount", false},
		{"iptables", "iptables", false},
		{"gdb", "gdb", false},
		{"tar", "tar", false},
		{"zip", "zip", false},
		{"find", "find", false},
		{"xargs", "xargs", false},
		{"timeout", "timeout", false},
		{"mysql", "mysql", false},
		{"nginx", "nginx", false},
		{"vim", "vim", false},
		{"bash", "bash", false},
		{"sh", "sh", false},

		// Safe commands that should be allowed
		{"ls", "ls", true},
		{"cd", "cd", true},
		{"pwd", "pwd", true},
		{"whoami", "whoami", true},
		{"date", "date", true},
		{"echo", "echo", true},
		{"cat", "cat", true},
		{"head", "head", true},
		{"tail", "tail", true},
		{"grep", "grep", true},
		{"less", "less", true},
		{"man", "man", true},
		{"test", "test", true},
		{"wc", "wc", true},
		{"sort", "sort", true},
		{"uniq", "uniq", true},
		{"cut", "cut", true},
		{"tr", "tr", true},

		// Unknown commands should be blocked (conservative approach)
		{"unknown_command", "unknown_command", false},
		{"custom_script", "custom_script", false},
		{"my_command", "my_command", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsCommandAllowed(tt.command)
			if got != tt.want {
				t.Errorf("IsCommandAllowed(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// Test ContainsDangerousPattern function
func TestContainsDangerousPattern(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   bool
	}{
		// Safe scripts
		{"simple echo", "echo hello", false},
		{"simple ls", "ls -la", false},
		{"simple cat", "cat file.txt", false},
		{"comment only", "# This is a comment", false},
		{"empty line", "", false},
		{"whitespace", "   ", false},

		// Dangerous patterns - output redirection
		{"output redirect", "echo hello > file.txt", true},
		{"append redirect", "echo hello >> file.txt", true},
		{"pipe", "ls -la | grep test", true},

		// Dangerous patterns - command substitution
		{"command substitution parens", "echo $(whoami)", true},
		{"command substitution backticks", "echo `whoami`", true},

		// Dangerous patterns - variable expansion
		{"variable expansion", "echo ${USER}", true},
		{"simple variable", "echo $USER", true},

		// Dangerous patterns - command chaining
		{"semicolon chaining", "ls; rm -rf /", true},
		{"and chaining", "ls && rm -rf /", true},
		{"or chaining", "ls || rm -rf /", true},

		// Dangerous patterns - background processes
		{"background ampersand", "sleep 10 &", true},
		{"background space", "sleep 10 & ", true},

		// Dangerous patterns - line continuation
		{"line continuation", "echo hello \\", true},

		// Complex dangerous scripts
		{"complex dangerous", "rm -rf / > /dev/null 2>&1 &", true},
		{"multiple dangers", "echo $(whoami) > file.txt | cat", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := ContainsDangerousPattern(tt.script)
			if got != tt.want {
				t.Errorf("ContainsDangerousPattern(%q) dangerous = %v, want %v", tt.script, got, tt.want)
			}
		})
	}
}

// Test IsScriptSafe function
func TestIsScriptSafe(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   bool
	}{
		// Safe scripts
		{"simple safe script", "ls -la\necho hello\npwd", true},
		{"comments and safe commands", "# This is a comment\necho hello\n# Another comment\npwd", true},
		{"empty script", "", true},
		{"only comments", "# Comment 1\n# Comment 2", true},

		// Scripts with dangerous commands
		{"dangerous command", "rm -rf /", false},
		{"mixed safe and dangerous", "ls -la\nrm file.txt\necho done", false},

		// Scripts with dangerous patterns
		{"output redirect", "echo hello > file.txt", false},
		{"command substitution", "echo $(whoami)", false},
		{"command chaining", "ls; rm file.txt", false},

		// Complex scripts
		{"complex safe script", "# Script header\necho \"Starting...\"\ncd /tmp\npwd\necho \"Done.\"", true},
		{"complex dangerous script", "echo \"Starting...\"\nrm -rf /tmp/*\necho \"Done.\"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsScriptSafe(tt.script)
			if got != tt.want {
				t.Errorf("IsScriptSafe(%q) safe = %v, want %v", tt.script, got, tt.want)
			}
		})
	}
}

// Test IsCommandLineSafe function
func TestIsCommandLineSafe(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		// Safe command lines
		{"simple echo", []string{"echo", "hello"}, true},
		{"simple ls", []string{"ls", "-la"}, true},
		{"simple cat", []string{"cat", "file.txt"}, true},

		// Dangerous command lines - dangerous commands
		{"dangerous command", []string{"rm", "file.txt"}, false},
		{"another dangerous", []string{"mv", "old.txt", "new.txt"}, false},

		// Dangerous command lines - dangerous patterns
		{"output redirect", []string{"echo", "hello", ">", "file.txt"}, false},
		{"command substitution", []string{"echo", "$(whoami)"}, false},
		{"pipe", []string{"ls", "-la", "|", "grep", "test"}, false},

		// Edge cases
		{"no args", []string{}, false},
		{"empty command", []string{"", "arg"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsCommandLineSafe(tt.args)
			if got != tt.want {
				t.Errorf("IsCommandLineSafe(%v) safe = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

// Test IsInteractiveCommandSafe function
func TestIsInteractiveCommandSafe(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		// Safe interactive commands
		{"simple ls", "ls", true},
		{"ls with args", "ls -la", true},
		{"cd", "cd /tmp", true},
		{"pwd", "pwd", true},
		{"echo", "echo hello", true},
		{"cat", "cat file.txt", true},
		{"head", "head -n 10 file.txt", true},
		{"tail", "tail -f log.txt", true},
		{"grep", "grep test file.txt", true},
		{"less", "less file.txt", true},
		{"man", "man ls", true},
		{"help", "help", true},
		{"exit", "exit", true},
		{"clear", "clear", true},

		// Dangerous interactive commands
		{"rm", "rm file.txt", false},
		{"mv", "mv old.txt new.txt", false},
		{"cp", "cp src.txt dst.txt", false},

		// Dangerous patterns in interactive commands
		{"output redirect", "echo hello > file.txt", false},
		{"command substitution", "echo $(whoami)", false},
		{"pipe", "ls -la | grep test", false},
		{"command chaining", "ls; rm file.txt", false},

		// Unknown commands should be blocked in interactive mode
		{"unknown command", "unknown_cmd arg", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := IsInteractiveCommandSafe(tt.command)
			if got != tt.want {
				t.Errorf("IsInteractiveCommandSafe(%q) safe = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}
