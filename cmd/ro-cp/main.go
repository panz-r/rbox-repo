package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/command"
	"github.com/panz/openroutertest/internal/rocp"
)

// ro-cp - Read-only cp wrapper
// This program prevents any actual file copying while allowing safe operations

func main() {
	args := os.Args[1:]

	// Check if cp command is safe (read-only)
	if safe, reason := rocp.IsCopySafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-cp: Error - %s\n", reason)
		os.Exit(1)
	}

	// For cp, we need to use the executor pattern
	executor := command.GetRealExecutor()
	cmd := executor.Command("cp", args...)
	executor.SetStdout(cmd, os.Stdout)
	executor.SetStderr(cmd, os.Stderr)
	executor.SetStdin(cmd, os.Stdin)

	if err := executor.Run(cmd); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-cp: Error executing cp: %v\n", err)
		os.Exit(1)
	}
}