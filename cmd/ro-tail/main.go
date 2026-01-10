package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rotail"
)

// ro-tail - Read-only tail wrapper
// This program prevents any tail operations that could write files

func main() {
	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rotail.AreTailArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-tail: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the tail command with all arguments
	cmd := exec.Command("tail", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-tail: Error executing tail: %v\n", err)
		os.Exit(1)
	}
}