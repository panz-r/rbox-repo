package test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestRoGitIntegration tests the ro-git wrapper end-to-end
func TestRoGitIntegration(t *testing.T) {
	// Build the ro-git binary first
	buildCmd := exec.Command("go", "build", "-o", "ro-git", "./cmd/ro-git")
	buildCmd.Dir = ".."
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build ro-git: %v", err)
	}

	tests := []struct {
		name        string
		args        []string
		shouldFail  bool
		expectError string
	}{
		// Safe commands that should work
		{"version", []string{"--version"}, false, ""},
		{"help", []string{"help"}, false, ""},

		// Blocked write commands
		{"add", []string{"add", "."}, true, "write operation not allowed"},
		{"commit", []string{"commit", "-m", "test"}, true, "write operation not allowed"},
		{"push", []string{"push"}, true, "write operation not allowed"},
		{"pull", []string{"pull"}, true, "write operation not allowed"},
		{"merge", []string{"merge", "main"}, true, "write operation not allowed"},
		{"rebase", []string{"rebase", "main"}, true, "write operation not allowed"},
		{"reset", []string{"reset", "--hard"}, true, "write operation not allowed"},
		{"rm", []string{"rm", "file.txt"}, true, "write operation not allowed"},
		{"mv", []string{"mv", "old.txt", "new.txt"}, true, "write operation not allowed"},
		{"branch", []string{"branch", "new-feature"}, true, "write operation not allowed"},
		{"tag", []string{"tag", "v1.0.0"}, true, "write operation not allowed"},
		{"stash", []string{"stash"}, true, "write operation not allowed"},
		{"checkout", []string{"checkout", "main"}, true, "write operation not allowed"},
		{"fetch", []string{"fetch"}, true, "write operation not allowed"},
		{"clone", []string{"clone", "repo.git"}, true, "write operation not allowed"},
		{"init", []string{"init"}, true, "write operation not allowed"},

		// Config operations
		{"config list", []string{"config", "--list"}, false, ""},
		{"config get", []string{"config", "--get", "user.name"}, false, ""},
		{"config set", []string{"config", "user.name", "test"}, true, "config modification not allowed"},
		{"config add", []string{"config", "--add", "remote.origin", "git@github.com:user/repo.git"}, true, "config modification not allowed"},
		{"config replace", []string{"config", "--replace-all", "user.email", "test@example.com"}, true, "config modification not allowed"},
		{"config unset", []string{"config", "--unset", "user.password"}, true, "config modification not allowed"},

		// Safe read operations (if in a git repo)
		{"log", []string{"log", "--oneline"}, false, ""},
		{"show", []string{"show", "--stat"}, false, ""},
		{"diff", []string{"diff"}, false, ""}, // We're in a git repo, so diff should work
		{"status", []string{"status"}, false, ""},
		{"grep", []string{"grep", "main"}, false, ""},
		{"blame", []string{"blame", "--", "CLAUDE.md"}, false, ""}, // Use existing file instead of README.md
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("./ro-git", tt.args...)
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
						// Command failed, but it might be because we're not in a git repo
						// or the specific command requires certain conditions
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

// TestRoFindIntegration tests the ro-find wrapper end-to-end
func TestRoFindIntegration(t *testing.T) {
	// Build the ro-find binary first
	buildCmd := exec.Command("go", "build", "-o", "ro-find", "./cmd/ro-find")
	buildCmd.Dir = ".."
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build ro-find: %v", err)
	}

	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "ro-find-test-*")
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
		expectFiles []string // files we expect to find (if not failing)
	}{
		// Safe find operations
		{"name search", []string{tmpDir, "-name", "*.go"}, false, "", []string{"test.go", "subdir/test2.go"}},
		{"type file", []string{tmpDir, "-type", "f"}, false, "", testFiles},
		{"type directory", []string{tmpDir, "-type", "d"}, false, "", []string{"subdir"}},
		{"size search", []string{tmpDir, "-size", "-20c"}, false, "", testFiles},
		{"name txt", []string{tmpDir, "-name", "*.txt"}, false, "", []string{"test.txt"}},
		{"printf format", []string{tmpDir, "-printf", "%p\n"}, false, "", testFiles},

		// Dangerous operations that should be blocked
		{"exec rm", []string{tmpDir, "-name", "*.tmp", "-exec", "rm", "{}", "\\;"}, true, "can execute commands", nil},
		{"execdir rm", []string{tmpDir, "-execdir", "rm", "{}", "\\;"}, true, "can execute commands", nil},
		{"ok rm", []string{tmpDir, "-ok", "rm", "{}", "\\;"}, true, "can execute commands", nil},
		{"delete", []string{tmpDir, "-name", "*.tmp", "-delete"}, true, "can delete files", nil},
		{"printf to file", []string{tmpDir, "-printf", ">output.txt", "%p\n"}, true, "appears to write to a file", nil},
		{"fprintf append", []string{tmpDir, "-fprintf", ">>output.txt", "%p\n"}, true, "appears to write to a file", nil},

		// Complex safe operations
		{"complex search", []string{tmpDir, "-name", "*.go", "-type", "f", "-size", "+10c"}, false, "", []string{"test.go", "subdir/test2.go"}},
		{"negated search", []string{tmpDir, "!", "-name", "*.tmp"}, false, "", []string{"test.go", "test.txt", "subdir/test2.go"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("./ro-find", tt.args...)
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
				} else if tt.expectFiles != nil {
					// Check if expected files are in the output
					output := stdout.String()
					for _, expectedFile := range tt.expectFiles {
						expectedPath := filepath.Join(tmpDir, expectedFile)
						if !bytes.Contains(stdout.Bytes(), []byte(expectedPath)) {
							t.Errorf("Expected output to contain %s, got: %s", expectedPath, output)
						}
					}
				}
			}
		})
	}
}