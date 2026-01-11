package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/command"
	"github.com/panz/openroutertest/internal/romv"
)

// ro-mv - Read-only mv wrapper
// This program prevents any actual file movement while allowing safe operations

func main() {
	args := os.Args[1:]

	// Check if mv command is safe (read-only)
	if safe, reason := romv.IsMoveSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-mv: Error - %s\n", reason)
		os.Exit(1)
	}

	// For mv, we need to use the executor pattern
	executor := command.GetRealExecutor()
	cmd := executor.Command("mv", args...)
	executor.SetStdout(cmd, os.Stdout)
	executor.SetStderr(cmd, os.Stderr)
	executor.SetStdin(cmd, os.Stdin)

	if err := executor.Run(cmd); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-mv: Error executing mv: %v\n", err)
		os.Exit(1)
	}
}
