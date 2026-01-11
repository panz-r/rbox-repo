package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/roman"
)

// ro-man - Read-only man wrapper
// This program executes man command with read-only security checks
// Note: This is a simplified version that shows man pages without paging

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "ro-man: No manual page specified\n")
		fmt.Fprintf(os.Stderr, "Usage: ro-man <command>\n")
		os.Exit(1)
	}

	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := roman.AreManArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-man: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the man command with all arguments
	runManCommand(args)
}

func runManCommand(args []string) {
	// Use man with cat for non-interactive display
	// This avoids paging and makes it truly read-only
	manArgs := append([]string{"--local-file", "-P", "cat"}, args...)
	cmd := exec.Command("man", manArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-man: Error executing man: %v\n", err)
		os.Exit(1)
	}
}