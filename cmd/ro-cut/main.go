package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rocut"
)

// ro-cut - Read-only cut wrapper
// This program executes cut command with read-only security checks

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "ro-cut: At least list and file arguments required\n")
		fmt.Fprintf(os.Stderr, "Usage: ro-cut -f <list> <file>\n")
		os.Exit(1)
	}

	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rocut.AreCutArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-cut: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the cut command with all arguments
	runCutCommand(args)
}

func runCutCommand(args []string) {
	cmd := exec.Command("cut", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-cut: Error executing cut: %v\n", err)
		os.Exit(1)
	}
}