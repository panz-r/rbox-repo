package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rosed"
)

// ro-sed - Read-only sed wrapper
// This program validates sed commands and only allows safe read-only operations

func main() {
	args := os.Args[1:]

	// Check if sed command is safe
	if safe, reason := rosed.IsSedSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-sed: Error - %s\n", reason)
		os.Exit(1)
	}

	// Execute the sed command
	cmd := exec.Command("sed", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-sed: Error executing sed: %v\n", err)
		os.Exit(1)
	}
}