package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rops"
)

// ro-ps - Read-only ps wrapper
// This program prevents any ps commands that could potentially be dangerous

func main() {
	if len(os.Args) < 2 {
		// ps can be called without arguments, so we allow this
		// Execute ps with no arguments
		runPsCommand([]string{})
		return
	}

	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rops.ArePsArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-ps: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the ps command with all arguments
	runPsCommand(args)
}

func runPsCommand(args []string) {
	cmd := exec.Command("ps", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-ps: Error executing ps: %v\n", err)
		os.Exit(1)
	}
}