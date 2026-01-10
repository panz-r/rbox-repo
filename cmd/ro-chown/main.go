package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/command"
	"github.com/panz/openroutertest/internal/rochown"
)

// ro-chown - Read-only chown wrapper
// This program prevents any actual ownership changes while allowing safe operations

func main() {
	args := os.Args[1:]

	// Check if chown command is safe (read-only)
	if safe, reason := rochown.IsChownSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-chown: Error - %s\n", reason)
		os.Exit(1)
	}

	// For chown, we need to use the executor pattern
	executor := command.GetRealExecutor()
	cmd := executor.Command("chown", args...)
	executor.SetStdout(cmd, os.Stdout)
	executor.SetStderr(cmd, os.Stderr)
	executor.SetStdin(cmd, os.Stdin)

	if err := executor.Run(cmd); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-chown: Error executing chown: %v\n", err)
		os.Exit(1)
	}
}