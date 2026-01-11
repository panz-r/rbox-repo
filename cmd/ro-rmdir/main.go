package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/command"
	"github.com/panz/openroutertest/internal/rormdir"
)

// ro-rmdir - Read-only rmdir wrapper
// This program prevents any actual directory removal while allowing safe operations

func main() {
	args := os.Args[1:]

	// Check if rmdir command is safe (read-only)
	if safe, reason := rormdir.IsRmdirSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-rmdir: Error - %s\n", reason)
		os.Exit(1)
	}

	// For rmdir, we need to use the executor pattern
	executor := command.GetRealExecutor()
	cmd := executor.Command("rmdir", args...)
	executor.SetStdout(cmd, os.Stdout)
	executor.SetStderr(cmd, os.Stderr)
	executor.SetStdin(cmd, os.Stdin)

	if err := executor.Run(cmd); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-rmdir: Error executing rmdir: %v\n", err)
		os.Exit(1)
	}
}
