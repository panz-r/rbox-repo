package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/command"
	"github.com/panz/openroutertest/internal/rochmod"
)

// ro-chmod - Read-only chmod wrapper
// This program prevents any actual permission changes while allowing safe operations

func main() {
	args := os.Args[1:]

	// Check if chmod command is safe (read-only)
	if safe, reason := rochmod.IsChmodSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-chmod: Error - %s\n", reason)
		os.Exit(1)
	}

	// For chmod, we need to use the executor pattern
	executor := command.GetRealExecutor()
	cmd := executor.Command("chmod", args...)
	executor.SetStdout(cmd, os.Stdout)
	executor.SetStderr(cmd, os.Stderr)
	executor.SetStdin(cmd, os.Stdin)

	if err := executor.Run(cmd); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-chmod: Error executing chmod: %v\n", err)
		os.Exit(1)
	}
}
