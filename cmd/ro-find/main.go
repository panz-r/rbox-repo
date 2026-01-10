package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rofind"
)

// ro-find - Read-only find wrapper
// This program prevents any find commands that could execute or modify files

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "ro-find: No path provided\n")
		fmt.Fprintf(os.Stderr, "Usage: ro-find <path> [expression...]\n")
		os.Exit(1)
	}

	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rofind.AreFindArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-find: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the find command with all arguments
	cmd := exec.Command("find", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-find: Error executing find: %v\n", err)
		os.Exit(1)
	}
}