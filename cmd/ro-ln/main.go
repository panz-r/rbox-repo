package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/command"
	"github.com/panz/openroutertest/internal/roln"
)

// ro-ln - Read-only ln wrapper
// This program prevents any actual link creation while allowing safe operations

func main() {
	args := os.Args[1:]

	// Check if ln command is safe (read-only)
	if safe, reason := roln.IsLnSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-ln: Error - %s\n", reason)
		os.Exit(1)
	}

	// For ln, we need to use the executor pattern
	executor := command.GetRealExecutor()
	cmd := executor.Command("ln", args...)
	executor.SetStdout(cmd, os.Stdout)
	executor.SetStderr(cmd, os.Stderr)
	executor.SetStdin(cmd, os.Stdin)

	if err := executor.Run(cmd); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-ln: Error executing ln: %v\n", err)
		os.Exit(1)
	}
}