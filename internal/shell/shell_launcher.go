package readonlybox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ShellLauncher provides functionality to launch shells with readonlybox interception
type ShellLauncher struct {
	readonlyboxPath string
	wrapperPath     string
}

// NewShellLauncher creates a new shell launcher
func NewShellLauncher(readonlyboxPath string) (*ShellLauncher, error) {
	absPath, err := filepath.Abs(readonlyboxPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	return &ShellLauncher{
		readonlyboxPath: absPath,
		wrapperPath:     absPath + "_wrapper",
	}, nil
}

// LaunchShell launches a shell with readonlybox in PATH
func (sl *ShellLauncher) LaunchShell(shellPath string, args ...string) error {
	env := sl.createEnvironment()

	cmd := exec.Command(shellPath, args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// LaunchBash launches bash with readonlybox interception
func (sl *ShellLauncher) LaunchBash(args ...string) error {
	return sl.LaunchShell("/bin/bash", args...)
}

// LaunchSh launches sh with readonlybox interception
func (sl *ShellLauncher) LaunchSh(args ...string) error {
	return sl.LaunchShell("/bin/sh", args...)
}

// LaunchDash launches dash with readonlybox interception
func (sl *ShellLauncher) LaunchDash(args ...string) error {
	return sl.LaunchShell("/bin/dash", args...)
}

// createEnvironment creates environment with readonlybox in PATH
func (sl *ShellLauncher) createEnvironment() []string {
	env := os.Environ()

	// Build new PATH with readonlybox first
	pathDirs := []string{filepath.Dir(sl.readonlyboxPath)}
	currentPath := os.Getenv("PATH")
	if currentPath != "" {
		pathDirs = append(pathDirs, strings.Split(currentPath, string(os.PathListSeparator))...)
	}
	newPath := strings.Join(pathDirs, string(os.PathListSeparator))

	// Update PATH in environment
	newEnv := make([]string, 0, len(env))
	for _, e := range env {
		if !strings.HasPrefix(e, "PATH=") {
			newEnv = append(newEnv, e)
		}
	}
	newEnv = append(newEnv, "PATH="+newPath)

	// Add readonlybox-specific environment variables
	newEnv = append(newEnv, "READONLYBOX_PATH="+sl.readonlyboxPath)
	newEnv = append(newEnv, "READONLYBOX_ENABLED=1")

	return newEnv
}

// CreateWrapperScript creates a shell wrapper script
func (sl *ShellLauncher) CreateWrapperScript(shellPath string) error {
	script := fmt.Sprintf(`#!/bin/bash
# readonlybox wrapper script
# This script intercepts all commands and routes them through readonlybox

readonlybox_path="%s"
shell_path="%s"

# Add readonlybox to PATH
export PATH="$(dirname "$readonlybox_path"):$PATH"

# Mark that we're in readonlybox mode
export READONLYBOX_WRAPPER=1
export READONLYBOX_PATH="$readonlybox_path"

# Execute the actual shell
exec "$shell_path" "$@"
`, sl.readonlyboxPath, shellPath)

	if err := os.WriteFile(sl.wrapperPath, []byte(script), 0755); err != nil {
		return fmt.Errorf("failed to write wrapper script: %w", err)
	}

	return nil
}

// GetInterceptedEnvironment returns environment variables for command interception
func GetInterceptedEnvironment(readonlyboxPath string) []string {
	env := os.Environ()

	// Get current PATH and prepend readonlybox directory
	pathDirs := []string{filepath.Dir(readonlyboxPath)}
	currentPath := os.Getenv("PATH")
	if currentPath != "" {
		pathDirs = append(pathDirs, strings.Split(currentPath, string(os.PathListSeparator))...)
	}
	newPath := strings.Join(pathDirs, string(os.PathListSeparator))

	// Update PATH
	newEnv := make([]string, 0, len(env))
	for _, e := range env {
		if !strings.HasPrefix(e, "PATH=") {
			newEnv = append(newEnv, e)
		}
	}
	newEnv = append(newEnv, "PATH="+newPath)
	newEnv = append(newEnv, "READONLYBOX_ENABLED=1")
	newEnv = append(newEnv, "READONLYBOX_PATH="+readonlyboxPath)

	return newEnv
}

// RunWithInterception runs a command with readonlybox interception
func RunWithInterception(cmd string, args []string, readonlyboxPath string) error {
	env := GetInterceptedEnvironment(readonlyboxPath)

	executable, err := lookupExecutable(cmd, readonlyboxPath)
	if err != nil {
		return err
	}

	command := exec.Command(executable, args...)
	command.Env = env
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr

	return command.Run()
}

// lookupExecutable looks up the executable in readonlybox PATH order
func lookupExecutable(cmd string, readonlyboxPath string) (string, error) {
	// Check if it's an absolute path
	if filepath.IsAbs(cmd) {
		return cmd, nil
	}

	// Check if it's a relative path
	if strings.HasPrefix(cmd, "./") || strings.HasPrefix(cmd, "../") {
		return filepath.Join(".", cmd), nil
	}

	// Look in readonlybox directory first
	readonlyboxDir := filepath.Dir(readonlyboxPath)
	absPath := filepath.Join(readonlyboxDir, cmd)
	if _, err := os.Stat(absPath); err == nil {
		return absPath, nil
	}

	// Fall back to regular lookup
	return exec.LookPath(cmd)
}
