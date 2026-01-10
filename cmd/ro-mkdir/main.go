package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/command"
	"github.com/panz/openroutertest/internal/romkdir"
)

// ro-mkdir - Read-only mkdir wrapper
// This program prevents any actual directory creation while allowing safe operations

func main() {
	args := os.Args[1:]

	// Check if mkdir command is safe (read-only)
	if safe, reason := romkdir.IsMkdirSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-mkdir: Error - %s\n", reason)
		os.Exit(1)
	}

	// For mkdir, we need to use the executor pattern
	executor := command.GetRealExecutor()
	cmd := executor.Command("mkdir", args...)
	executor.SetStdout(cmd, os.Stdout)
	executor.SetStderr(cmd, os.Stderr)
	executor.SetStdin(cmd, os.Stdin)

	if err := executor.Run(cmd); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-mkdir: Error executing mkdir: %v\n", err)
		os.Exit(1)
	}
}