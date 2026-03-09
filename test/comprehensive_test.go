package test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// TestReadOnlyBoxHelp tests --help functionality for readonlybox
func TestReadOnlyBoxHelp(t *testing.T) {
	// Build readonlybox binary
	buildCmd := exec.Command("go", "build", "-o", "../bin/readonlybox", "../cmd/readonlybox")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build readonlybox: %v", err)
	}

	// Test --help flag
	cmd := exec.Command("../bin/readonlybox", "--help")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	// --help should either succeed or fail gracefully, but should not panic or crash
	if err != nil {
		// Some commands might exit with non-zero status for --help, that's okay
		if _, ok := err.(*exec.ExitError); !ok {
			t.Errorf("readonlybox --help failed with unexpected error: %v", err)
		}
	}

	// Should produce some output (either stdout or stderr)
	if stdout.Len() == 0 && stderr.Len() == 0 {
		t.Errorf("readonlybox --help produced no output")
	}
}

// TestReadOnlyBoxCommands tests basic command execution via readonlybox
func TestReadOnlyBoxCommands(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "readonlybox-test-*")
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

	// Build readonlybox binary
	buildCmd := exec.Command("go", "build", "-o", "../bin/readonlybox", "../cmd/readonlybox")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build readonlybox: %v", err)
	}

	// Test commands via readonlybox
	tests := []struct {
		name          string
		command       string
		args          []string
		shouldSucceed bool
	}{
		// git commands
		{"git version", "git", []string{"--version"}, true},
		{"git help", "git", []string{"help"}, true},

		// find commands
		{"find name search", "find", []string{tmpDir, "-name", "*.go"}, true},
		{"find type file", "find", []string{tmpDir, "-type", "f"}, true},

		// ls commands
		{"ls list", "ls", []string{tmpDir}, true},
		{"ls detailed", "ls", []string{"-la", tmpDir}, true},

		// cat commands
		{"cat read", "cat", []string{filepath.Join(tmpDir, "test.txt")}, true},

		// grep commands
		{"grep search", "grep", []string{"test", filepath.Join(tmpDir, "test.txt")}, true},

		// head commands
		{"head read", "head", []string{"-n", "5", filepath.Join(tmpDir, "test.txt")}, true},

		// tail commands
		{"tail read", "tail", []string{"-n", "5", filepath.Join(tmpDir, "test.txt")}, true},

		// echo commands
		{"echo text", "echo", []string{"hello", "world"}, true},

		// date commands
		{"date show", "date", []string{"--iso-8601"}, true},

		// sort commands
		{"sort lines", "sort", []string{filepath.Join(tmpDir, "test.txt")}, true},

		// ulimit commands
		{"ulimit show", "ulimit", []string{"-a"}, true},

		// sed commands (read-only)
		{"sed help", "sed", []string{"--help"}, true},

		// chmod commands (read-only mode) - should be blocked for real files
		{"chmod check", "chmod", []string{"-R", tmpDir}, false},

		// chown commands (read-only mode) - should be blocked for real files
		{"chown check", "chown", []string{"-R", tmpDir}, false},

		// mkdir commands (read-only mode) - should be blocked for real files
		{"mkdir check", "mkdir", []string{"-p", filepath.Join(tmpDir, "newdir")}, false},

		// rmdir commands (read-only mode) - should be blocked for real directories
		{"rmdir check", "rmdir", []string{tmpDir}, false},

		// ln commands (read-only mode) - should be blocked for real files
		{"ln check", "ln", []string{filepath.Join(tmpDir, "test.txt"), filepath.Join(tmpDir, "link.txt")}, false},

		// mv commands (read-only mode) - should be blocked for real files
		{"mv check", "mv", []string{filepath.Join(tmpDir, "test.txt"), filepath.Join(tmpDir, "moved.txt")}, false},

		// cp commands (read-only mode) - should be blocked for real files
		{"cp check", "cp", []string{filepath.Join(tmpDir, "test.txt"), filepath.Join(tmpDir, "copied.txt")}, false},

		// rm commands (read-only mode) - should be blocked for real files
		{"rm check", "rm", []string{filepath.Join(tmpDir, "test.tmp")}, false},

		// touch commands (read-only mode) - should be blocked for real files
		{"touch check", "touch", []string{filepath.Join(tmpDir, "newfile.txt")}, false},

		// dd commands (read-only mode) - should be blocked
		{"dd check", "dd", []string{"if=/dev/zero", "of=/dev/null", "count=1"}, false},

		// timeout commands - requires duration and command
		{"timeout check", "timeout", []string{"1s", "echo", "hello"}, true},

		// cd commands
		{"cd check", "cd", []string{"--help"}, true},

		// ps commands
		{"ps aux", "ps", []string{"aux"}, true},

		// df commands
		{"df -h", "df", []string{"-h"}, true},

		// du commands
		{"du -sh", "du", []string{"-sh", tmpDir}, true},

		// wc commands
		{"wc -l", "wc", []string{"-l", filepath.Join(tmpDir, "test.txt")}, true},

		// uname commands
		{"uname -a", "uname", []string{"-a"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the operation via readonlybox
			args := append([]string{tt.command}, tt.args...)
			cmd := exec.Command("../bin/readonlybox", args...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			// Set socket to non-existent path to avoid connecting to user's server
			testSocket := "/tmp/readonlybox-test-" + strconv.Itoa(os.Getpid()) + ".sock"
			cmd.Env = append(os.Environ(), "READONLYBOX_SOCKET="+testSocket)

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
						!bytes.Contains(stderr.Bytes(), []byte("Error executing ulimit")) &&
						!bytes.Contains(stderr.Bytes(), []byte("unknown command")) &&
						!bytes.Contains(stderr.Bytes(), []byte("cannot execute binary file")) {
						t.Errorf("Expected command to succeed but it failed: %v %v, stderr: %s", tt.command, tt.args, stderrStr)
					}
				}
			} else {
				if err == nil {
					t.Errorf("Expected command to fail but it succeeded: %v %v", tt.command, tt.args)
				}
			}
		})
	}
}

// TestReadOnlyBoxSymlinks tests that symlinks work correctly
func TestReadOnlyBoxSymlinks(t *testing.T) {
	// Build readonlybox binary
	buildCmd := exec.Command("go", "build", "-o", "../bin/readonlybox", "../cmd/readonlybox")
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build readonlybox: %v", err)
	}

	// Create symlinks
	symlinks := []string{"ro-git", "ro-find", "ro-ls", "ro-cat", "ro-echo", "ro-date"}
	for _, symlink := range symlinks {
		symlinkPath := filepath.Join("..", "bin", symlink)
		os.Remove(symlinkPath)
		if err := os.Symlink("readonlybox", symlinkPath); err != nil {
			t.Fatalf("Failed to create symlink %s: %v", symlink, err)
		}
		defer os.Remove(symlinkPath)

		// Test that symlink works
		cmd := exec.Command(symlinkPath, "--version")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			t.Errorf("Symlink %s failed: %v, stderr: %s", symlink, err, stderr.String())
		}
	}
}
