package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rols"
)

// ro-ls - Read-only ls wrapper
// This program prevents any ls operations that could write or execute files

func main() {
	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rols.AreLsArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-ls: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the ls command with all arguments
	cmd := exec.Command("ls", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-ls: Error executing ls: %v\n", err)
		os.Exit(1)
	}
}