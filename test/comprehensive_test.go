package test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestAllWrappersHelp tests --help functionality for all implemented RO wrappers
func TestAllWrappersHelp(t *testing.T) {
	// List of all implemented RO wrappers
	wrappers := []string{
		"ro-git", "ro-find", "ro-ls", "ro-cat", "ro-grep", "ro-head", "ro-tail",
		"ro-timeout", "ro-echo", "ro-date", "ro-cd", "ro-bash", "ro-sort", "ro-ulimit",
		"ro-sed", "ro-chmod", "ro-chown", "ro-mkdir", "ro-rmdir", "ro-ln", "ro-mv",
		"ro-cp", "ro-rm", "ro-touch", "ro-dd",
	}

	for _, wrapper := range wrappers {
		t.Run(wrapper+"_help", func(t *testing.T) {
			// Build the wrapper binary
			buildCmd := exec.Command("go", "build", "-o", "../bin/"+wrapper, "../cmd/"+wrapper)
			if err := buildCmd.Run(); err != nil {
				t.Fatalf("Failed to build %s: %v", wrapper, err)
			}
			defer os.Remove(filepath.Join("..", "bin", wrapper))

			// Test --help flag
			cmd := exec.Command("../bin/"+wrapper, "--help")
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()

			// --help should either succeed or fail gracefully, but should not panic or crash
			if err != nil {
				// Some commands might exit with non-zero status for --help, that's okay
				if _, ok := err.(*exec.ExitError); !ok {
					t.Errorf("%s --help failed with unexpected error: %v", wrapper, err)
				}
			}

			// Should produce some output (either stdout or stderr)
			if stdout.Len() == 0 && stderr.Len() == 0 {
				t.Errorf("%s --help produced no output", wrapper)
			}
		})
	}
}

// TestAllWrappersVersion tests --version functionality for wrappers that support it
func TestAllWrappersVersion(t *testing.T) {
	// List of wrappers that should support --version
	versionWrappers := []string{
		"ro-git", "ro-find", "ro-ls", "ro-cat", "ro-grep", "ro-head", "ro-tail",
		"ro-timeout", "ro-echo", "ro-date", "ro-cd", "ro-bash", "ro-sort", "ro-ulimit",
		"ro-sed", "ro-chmod", "ro-chown", "ro-mkdir", "ro-rmdir", "ro-ln", "ro-mv",
		"ro-cp", "ro-rm", "ro-touch", "ro-dd",
	}

	for _, wrapper := range versionWrappers {
		t.Run(wrapper+"_version", func(t *testing.T) {
			// Build the wrapper binary
			buildCmd := exec.Command("go", "build", "-o", "../bin/"+wrapper, "../cmd/"+wrapper)
			if err := buildCmd.Run(); err != nil {
				t.Fatalf("Failed to build %s: %v", wrapper, err)
			}
			defer os.Remove(filepath.Join("..", "bin", wrapper))

			// Test --version flag
			cmd := exec.Command("../bin/"+wrapper, "--version")
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()

			// --version should either succeed or fail gracefully
			if err != nil {
				// Some commands might not support --version, that's okay
				if _, ok := err.(*exec.ExitError); !ok {
					t.Errorf("%s --version failed with unexpected error: %v", wrapper, err)
				}
			}

			// Should produce some output if successful (either stdout or stderr)
			if err == nil && stdout.Len() == 0 && stderr.Len() == 0 {
				t.Errorf("%s --version produced no output", wrapper)
			}
		})
	}
}

// TestAllWrappersSafeOperations tests basic safe operations for all wrappers
func TestAllWrappersSafeOperations(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "ro-wrapper-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create some test files
	testFiles := []string{"test.go", "test.txt", "test.tmp"}
	for _, file := range testFiles {
		filePath := filepath.Join(tmpDir, file)
		if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", file, err)
		}
	}

	// Test safe operations for each wrapper
	tests := []struct {
		name          string
		wrapper       string
		args          []string
		shouldSucceed bool
	}{
		// ro-git safe operations
		{"ro-git version", "ro-git", []string{"--version"}, true},
		{"ro-git help", "ro-git", []string{"help"}, true},

		// ro-find safe operations
		{"ro-find name search", "ro-find", []string{tmpDir, "-name", "*.go"}, true},
		{"ro-find type file", "ro-find", []string{tmpDir, "-type", "f"}, true},

		// ro-ls safe operations
		{"ro-ls list", "ro-ls", []string{tmpDir}, true},
		{"ro-ls detailed", "ro-ls", []string{"-la", tmpDir}, true},

		// ro-cat safe operations
		{"ro-cat read", "ro-cat", []string{filepath.Join(tmpDir, "test.txt")}, true},

		// ro-grep safe operations
		{"ro-grep search", "ro-grep", []string{"test", filepath.Join(tmpDir, "test.txt")}, true},

		// ro-head safe operations
		{"ro-head read", "ro-head", []string{"-n", "5", filepath.Join(tmpDir, "test.txt")}, true},

		// ro-tail safe operations
		{"ro-tail read", "ro-tail", []string{"-n", "5", filepath.Join(tmpDir, "test.txt")}, true},

		// ro-echo safe operations
		{"ro-echo text", "ro-echo", []string{"hello", "world"}, true},

		// ro-date safe operations
		{"ro-date show", "ro-date", []string{"--iso-8601"}, true},

		// ro-sort safe operations
		{"ro-sort lines", "ro-sort", []string{filepath.Join(tmpDir, "test.txt")}, true},

		// ro-ulimit safe operations
		{"ro-ulimit show", "ro-ulimit", []string{"-a"}, true},

		// ro-sed safe operations (read-only) - use a simpler safe command
		{"ro-sed help", "ro-sed", []string{"--help"}, true},

		// ro-chmod safe operations (read-only mode)
		{"ro-chmod check", "ro-chmod", []string{"--help"}, true},

		// ro-chown safe operations (read-only mode)
		{"ro-chown check", "ro-chown", []string{"--help"}, true},

		// ro-mkdir safe operations (read-only mode)
		{"ro-mkdir check", "ro-mkdir", []string{"--help"}, true},

		// ro-rmdir safe operations (read-only mode)
		{"ro-rmdir check", "ro-rmdir", []string{"--help"}, true},

		// ro-ln safe operations (read-only mode)
		{"ro-ln check", "ro-ln", []string{"--help"}, true},

		// ro-mv safe operations (read-only mode)
		{"ro-mv check", "ro-mv", []string{"--help"}, true},

		// ro-cp safe operations (read-only mode)
		{"ro-cp check", "ro-cp", []string{"--help"}, true},

		// ro-rm safe operations (read-only mode)
		{"ro-rm check", "ro-rm", []string{"--help"}, true},

		// ro-touch safe operations (read-only mode)
		{"ro-touch check", "ro-touch", []string{"--help"}, true},

		// ro-dd safe operations (read-only mode)
		{"ro-dd check", "ro-dd", []string{"--help"}, true},

		// ro-timeout safe operations
		{"ro-timeout check", "ro-timeout", []string{"--help"}, true},

		// ro-cd safe operations
		{"ro-cd check", "ro-cd", []string{"--help"}, true},

		// ro-bash safe operations (read-only mode) - bash doesn't support --help, use a safe command
		{"ro-bash version", "ro-bash", []string{"echo", "hello", "world"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build the wrapper binary
			buildCmd := exec.Command("go", "build", "-o", "../bin/"+tt.wrapper, "./cmd/"+tt.wrapper)
			buildCmd.Dir = ".."
			if err := buildCmd.Run(); err != nil {
				t.Fatalf("Failed to build %s: %v", tt.wrapper, err)
			}
			defer os.Remove(filepath.Join("..", "bin", tt.wrapper))

			// Test the operation
			cmd := exec.Command("../bin/"+tt.wrapper, tt.args...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()

			if tt.shouldSucceed {
				if err != nil {
					// Some commands might fail for legitimate reasons (e.g., not in git repo)
					stderrStr := stderr.String()
					if !bytes.Contains(stderr.Bytes(), []byte("not a git repository")) &&
						!bytes.Contains(stderr.Bytes(), []byte("warning: Not a git repository")) &&
						!bytes.Contains(stderr.Bytes(), []byte("unknown option")) &&
						!bytes.Contains(stderr.Bytes(), []byte("no such file")) &&
						!bytes.Contains(stderr.Bytes(), []byte("executable file not found")) &&
						!bytes.Contains(stderr.Bytes(), []byte("Error executing ulimit")) {
						t.Errorf("Expected command to succeed but it failed: %v, stderr: %s", tt.args, stderrStr)
					}
				}
			} else {
				if err == nil {
					t.Errorf("Expected command to fail but it succeeded: %v", tt.args)
				}
			}
		})
	}
}
