package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rowhoami"
)

// ro-whoami - Read-only whoami wrapper
// This program executes whoami command with read-only security checks

func main() {
	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rowhoami.AreWhoamiArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-whoami: Error - %s and is not allowed in read-only mode\n", reason)
		os.Exit(1)
	}

	// Execute the whoami command with all arguments
	runWhoamiCommand(args)
}

func runWhoamiCommand(args []string) {
	cmd := exec.Command("whoami", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-whoami: Error executing whoami: %v\n", err)
		os.Exit(1)
	}
}