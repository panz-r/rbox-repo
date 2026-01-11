package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/command"
	"github.com/panz/openroutertest/internal/roremove"
)

// ro-rm - Read-only rm wrapper
// This program prevents any actual file removal while allowing safe operations

func main() {
	args := os.Args[1:]

	// Check if rm command is safe (read-only)
	if safe, reason := roremove.IsRemoveSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-rm: Error - %s\n", reason)
		os.Exit(1)
	}

	// For rm, we need to use the executor pattern
	executor := command.GetRealExecutor()
	cmd := executor.Command("rm", args...)
	executor.SetStdout(cmd, os.Stdout)
	executor.SetStderr(cmd, os.Stderr)
	executor.SetStdin(cmd, os.Stdin)

	if err := executor.Run(cmd); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-rm: Error executing rm: %v\n", err)
		os.Exit(1)
	}
}