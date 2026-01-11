package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rocat"
)

// ro-cat - Read-only cat wrapper
// This program prevents any cat operations that could write files

func main() {
	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rocat.AreCatArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-cat: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the cat command with all arguments
	cmd := exec.Command("cat", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-cat: Error executing cat: %v\n", err)
		os.Exit(1)
	}
}
