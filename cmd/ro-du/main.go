package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rodu"
)

// ro-du - Read-only du wrapper
// This program prevents any du commands that could potentially be dangerous

func main() {
	if len(os.Args) < 2 {
		// du can be called without arguments, so we allow this
		// Execute du with no arguments
		runDuCommand([]string{})
		return
	}

	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rodu.AreDuArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-du: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the du command with all arguments
	runDuCommand(args)
}

func runDuCommand(args []string) {
	cmd := exec.Command("du", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-du: Error executing du: %v\n", err)
		os.Exit(1)
	}
}