package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rodate"
)

// ro-date - Read-only date wrapper
// This program prevents date operations that could write files

func main() {
	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rodate.AreDateArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-date: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the date command with all arguments
	cmd := exec.Command("date", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-date: Error executing date: %v\n", err)
		os.Exit(1)
	}
}