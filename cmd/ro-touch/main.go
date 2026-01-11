package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/command"
	"github.com/panz/openroutertest/internal/rotouch"
)

// ro-touch - Read-only touch wrapper
// This program prevents any actual file creation/timestamp modification while allowing safe operations

func main() {
	args := os.Args[1:]

	// Check if touch command is safe (read-only)
	if safe, reason := rotouch.IsTouchSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-touch: Error - %s\n", reason)
		os.Exit(1)
	}

	// For touch, we need to use the executor pattern
	executor := command.GetRealExecutor()
	cmd := executor.Command("touch", args...)
	executor.SetStdout(cmd, os.Stdout)
	executor.SetStderr(cmd, os.Stderr)
	executor.SetStdin(cmd, os.Stdin)

	if err := executor.Run(cmd); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-touch: Error executing touch: %v\n", err)
		os.Exit(1)
	}
}
