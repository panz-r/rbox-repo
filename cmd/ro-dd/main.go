package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/command"
	"github.com/panz/openroutertest/internal/rodd"
)

// ro-dd - Read-only dd wrapper
// This program prevents any actual data copying while allowing safe operations

func main() {
	args := os.Args[1:]

	// Check if dd command is safe (read-only)
	if safe, reason := rodd.IsDdSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-dd: Error - %s\n", reason)
		os.Exit(1)
	}

	// For dd, we need to use the executor pattern
	executor := command.GetRealExecutor()
	cmd := executor.Command("dd", args...)
	executor.SetStdout(cmd, os.Stdout)
	executor.SetStderr(cmd, os.Stderr)
	executor.SetStdin(cmd, os.Stdin)

	if err := executor.Run(cmd); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-dd: Error executing dd: %v\n", err)
		os.Exit(1)
	}
}
