package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rosleep"
)

// ro-sleep - Read-only sleep wrapper
// This program executes sleep command with read-only security checks

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "ro-sleep: No duration provided\n")
		fmt.Fprintf(os.Stderr, "Usage: ro-sleep <duration>\n")
		os.Exit(1)
	}

	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rosleep.AreSleepArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-sleep: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the sleep command with all arguments
	runSleepCommand(args)
}

func runSleepCommand(args []string) {
	cmd := exec.Command("sleep", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-sleep: Error executing sleep: %v\n", err)
		os.Exit(1)
	}
}