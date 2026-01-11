package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rohostname"
)

// ro-hostname - Read-only hostname wrapper
// This program executes hostname command with read-only security checks

func main() {
	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rohostname.AreHostnameArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-hostname: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the hostname command with all arguments
	runHostnameCommand(args)
}

func runHostnameCommand(args []string) {
	cmd := exec.Command("hostname", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-hostname: Error executing hostname: %v\n", err)
		os.Exit(1)
	}
}