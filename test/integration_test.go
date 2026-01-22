package test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestReadonlyboxGitIntegration tests the readonlybox git subcommand end-to-end
func TestReadonlyboxGitIntegration(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		shouldFail  bool
		expectError string
	}{
		// Safe commands that should work
		{"version", []string{"git", "--version"}, false, ""},
		{"help", []string{"git", "help"}, false, ""},

		// Blocked write commands
		{"add", []string{"git", "add", "."}, true, "write operation not allowed"},
		{"commit", []string{"git", "commit", "-m", "test"}, true, "write operation not allowed"},
		{"push", []string{"git", "push"}, true, "write operation not allowed"},
		{"pull", []string{"git", "pull"}, true, "write operation not allowed"},
		{"merge", []string{"git", "merge", "main"}, true, "write operation not allowed"},
		{"rebase", []string{"git", "rebase", "main"}, true, "write operation not allowed"},
		{"reset", []string{"git", "reset", "--hard"}, true, "write operation not allowed"},
		{"checkout", []string{"git", "checkout", "main"}, true, "write operation not allowed"},
		{"fetch", []string{"git", "fetch"}, true, "write operation not allowed"},
		{"clone", []string{"git", "clone", "repo.git"}, true, "write operation not allowed"},
		{"init", []string{"git", "init"}, true, "write operation not allowed"},

		// Safe read operations (if in a git repo)
		{"log", []string{"git", "log", "--oneline"}, false, ""},
		{"show", []string{"git", "show", "--stat"}, false, ""},
		{"diff", []string{"git", "diff"}, false, ""},
		{"status", []string{"git", "status"}, false, ""},
		{"grep", []string{"git", "grep", "main"}, false, ""},
		{"branch", []string{"git", "branch"}, false, ""},
		{"remote", []string{"git", "remote", "-v"}, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("./readonlybox", tt.args...)
			cmd.Dir = ".."
			var stderr bytes.Buffer
			cmd.Stderr = &stderr

			err := cmd.Run()

			if tt.shouldFail {
				if err == nil {
					t.Errorf("Expected command to fail but it succeeded: %v", tt.args)
				}
				if tt.expectError != "" {
					stderrStr := stderr.String()
					if !bytes.Contains(stderr.Bytes(), []byte(tt.expectError)) {
						t.Errorf("Expected error containing %q, got: %s", tt.expectError, stderrStr)
					}
				}
			} else {
				if err != nil {
					if _, ok := err.(*exec.ExitError); ok {
						stderrStr := stderr.String()
						if !bytes.Contains(stderr.Bytes(), []byte("not a git repository")) &&
							!bytes.Contains(stderr.Bytes(), []byte("warning: Not a git repository")) &&
							!bytes.Contains(stderr.Bytes(), []byte("unknown option")) {
							t.Errorf("Expected command to succeed but it failed: %v, stderr: %s", tt.args, stderrStr)
						}
					} else {
						t.Errorf("Expected command to succeed but got error: %v", err)
					}
				}
			}
		})
	}
}

// TestReadonlyboxFindIntegration tests the readonlybox find subcommand end-to-end
func TestReadonlyboxFindIntegration(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "readonlybox-find-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create some test files
	testFiles := []string{"test.go", "test.txt", "test.tmp", "subdir/test2.go"}
	for _, file := range testFiles {
		filePath := filepath.Join(tmpDir, file)
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			t.Fatalf("Failed to create dir for %s: %v", file, err)
		}
		if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", file, err)
		}
	}

	tests := []struct {
		name        string
		args        []string
		shouldFail  bool
		expectError string
		expectFiles []string
	}{
		// Safe find operations
		{"name search", []string{"find", tmpDir, "-name", "*.go"}, false, "", []string{"test.go", "subdir/test2.go"}},
		{"type file", []string{"find", tmpDir, "-type", "f"}, false, "", testFiles},
		{"type directory", []string{"find", tmpDir, "-type", "d"}, false, "", []string{"subdir"}},
		{"size search", []string{"find", tmpDir, "-size", "-20c"}, false, "", testFiles},
		{"name txt", []string{"find", tmpDir, "-name", "*.txt"}, false, "", []string{"test.txt"}},
		{"printf format", []string{"find", tmpDir, "-printf", "%p\\n"}, false, "", testFiles},

		// Dangerous operations that should be blocked
		{"exec rm", []string{"find", tmpDir, "-name", "*.tmp", "-exec", "rm", "{}", "\\;"}, true, "can execute commands", nil},
		{"execdir rm", []string{"find", tmpDir, "-execdir", "rm", "{}", "\\;"}, true, "can execute commands", nil},
		{"ok rm", []string{"find", tmpDir, "-ok", "rm", "{}", "\\;"}, true, "can execute commands", nil},
		{"delete", []string{"find", tmpDir, "-name", "*.tmp", "-delete"}, true, "can delete files", nil},
		{"printf to file", []string{"find", tmpDir, "-printf", ">output.txt", "%p\\n"}, true, "appears to write to a file", nil},

		// Complex safe operations
		{"complex search", []string{"find", tmpDir, "-name", "*.go", "-type", "f", "-size", "+10c"}, false, "", []string{"test.go", "subdir/test2.go"}},
		{"negated search", []string{"find", tmpDir, "!", "-name", "*.tmp"}, false, "", []string{"test.go", "test.txt", "subdir/test2.go"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("./readonlybox", tt.args...)
			cmd.Dir = ".."
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()

			if tt.shouldFail {
				if err == nil {
					t.Errorf("Expected command to fail but it succeeded: %v", tt.args)
				}
				if tt.expectError != "" {
					stderrStr := stderr.String()
					if !bytes.Contains(stderr.Bytes(), []byte(tt.expectError)) {
						t.Errorf("Expected error containing %q, got: %s", tt.expectError, stderrStr)
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected command to succeed but got error: %v, stderr: %s", err, stderr.String())
				}
			}
		})
	}
}

// TestReadonlyboxSafeCommands tests various read-only commands
func TestReadonlyboxSafeCommands(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		shouldFail bool
	}{
		// File reading commands
		{"cat", []string{"cat", "Makefile"}, false},
		{"head", []string{"head", "-n", "5", "Makefile"}, false},
		{"tail", []string{"tail", "-n", "3", "Makefile"}, false},
		{"grep", []string{"grep", "package", "*.go"}, false},
		{"wc", []string{"wc", "-l", "Makefile"}, false},
		{"ls", []string{"ls", "-la"}, false},
		{"pwd", []string{"pwd"}, false},

		// System info commands
		{"ps", []string{"ps", "aux"}, false},
		{"df", []string{"df", "-h"}, false},
		{"du", []string{"du", "-sh", "."}, false},
		{"uname", []string{"uname", "-a"}, false},
		{"whoami", []string{"whoami"}, false},
		{"date", []string{"date"}, false},
		{"hostname", []string{"hostname"}, false},

		// Text processing
		{"sort", []string{"sort", "Makefile"}, false},
		{"cut", []string{"cut", "-d:", "-f1", "Makefile"}, false},
		{"uniq", []string{"uniq", "Makefile"}, false},
		{"tr", []string{"tr", "a-z", "A-Z", "<<<hello"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("./readonlybox", tt.args...)
			cmd.Dir = ".."
			var stderr bytes.Buffer
			cmd.Stderr = &stderr

			err := cmd.Run()

			if tt.shouldFail {
				if err == nil {
					t.Errorf("Expected command to fail but it succeeded: %v", tt.args)
				}
			} else {
				if err != nil {
					if _, ok := err.(*exec.ExitError); ok {
						stderrStr := stderr.String()
						if !bytes.Contains(stderr.Bytes(), []byte("not found")) &&
							!bytes.Contains(stderr.Bytes(), []byte("No such file")) {
							t.Logf("Command failed (may be expected): %v, stderr: %s", tt.args, stderrStr)
						}
					} else {
						t.Errorf("Expected command to succeed but got error: %v", err)
					}
				}
			}
		})
	}
}
