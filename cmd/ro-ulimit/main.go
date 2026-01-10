package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/roulimit"
)

// ro-ulimit - Read-only ulimit wrapper
// This program validates ulimit commands and only allows safe read-only operations

func main() {
	args := os.Args[1:]

	// Check if ulimit command is safe
	if safe, reason := roulimit.IsUlimitSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-ulimit: Error - %s\n", reason)
		os.Exit(1)
	}

	// Execute the ulimit command
	cmd := exec.Command("ulimit", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-ulimit: Error executing ulimit: %v\n", err)
		os.Exit(1)
	}
}