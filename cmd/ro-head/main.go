package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rohead"
)

// ro-head - Read-only head wrapper
// This program prevents any head operations that could write files

func main() {
	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rohead.AreHeadArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-head: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the head command with all arguments
	cmd := exec.Command("head", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-head: Error executing head: %v\n", err)
		os.Exit(1)
	}
}
