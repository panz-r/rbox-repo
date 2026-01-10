package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rotimeout"
)

// ro-timeout - Read-only timeout wrapper
// This program prevents timeout operations that could write files
// NOTE: timeout can still execute commands, so use with caution

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "ro-timeout: No duration specified\n")
		fmt.Fprintf(os.Stderr, "Usage: ro-timeout <duration> <command> [args...]\n")
		os.Exit(1)
	}

	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rotimeout.AreTimeoutArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-timeout: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the timeout command with all arguments
	cmd := exec.Command("timeout", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-timeout: Error executing timeout: %v\n", err)
		os.Exit(1)
	}
}