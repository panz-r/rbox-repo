package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rodf"
)

// ro-df - Read-only df wrapper
// This program prevents any df commands that could potentially be dangerous

func main() {
	if len(os.Args) < 2 {
		// df can be called without arguments, so we allow this
		// Execute df with no arguments
		runDfCommand([]string{})
		return
	}

	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rodf.AreDfArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-df: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the df command with all arguments
	runDfCommand(args)
}

func runDfCommand(args []string) {
	cmd := exec.Command("df", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-df: Error executing df: %v\n", err)
		os.Exit(1)
	}
}