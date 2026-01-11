package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rogrep"
)

// ro-grep - Read-only grep wrapper
// This program prevents any grep operations that could write files

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "ro-grep: No pattern provided\n")
		fmt.Fprintf(os.Stderr, "Usage: ro-grep <pattern> [files...]\n")
		os.Exit(1)
	}

	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rogrep.AreGrepArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-grep: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the grep command with all arguments
	cmd := exec.Command("grep", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-grep: Error executing grep: %v\n", err)
		os.Exit(1)
	}
}
