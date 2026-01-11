package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rosort"
)

// ro-sort - Read-only sort wrapper
// This program validates sort commands and only allows safe read-only operations

func main() {
	args := os.Args[1:]

	// Check if sort command is safe
	if safe, reason := rosort.AreSortArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-sort: Error - %s\n", reason)
		os.Exit(1)
	}

	// Execute the sort command
	cmd := exec.Command("sort", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-sort: Error executing sort: %v\n", err)
		os.Exit(1)
	}
}
