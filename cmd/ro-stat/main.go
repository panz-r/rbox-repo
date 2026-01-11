package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rostat"
)

// ro-stat - Read-only stat wrapper
// This program prevents any stat commands that could potentially be dangerous

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "ro-stat: No file provided\n")
		fmt.Fprintf(os.Stderr, "Usage: ro-stat <file>\n")
		os.Exit(1)
	}

	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rostat.AreStatArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-stat: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the stat command with all arguments
	runStatCommand(args)
}

func runStatCommand(args []string) {
	cmd := exec.Command("stat", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-stat: Error executing stat: %v\n", err)
		os.Exit(1)
	}
}