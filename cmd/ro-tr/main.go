package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rotr"
)

// ro-tr - Read-only tr wrapper
// This program executes tr command with read-only security checks

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "ro-tr: At least one argument required\n")
		fmt.Fprintf(os.Stderr, "Usage: ro-tr <set1> <set2>\n")
		os.Exit(1)
	}

	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rotr.AreTrArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-tr: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the tr command with all arguments
	runTrCommand(args)
}

func runTrCommand(args []string) {
	cmd := exec.Command("tr", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitCode()); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-tr: Error executing tr: %v\n", err)
		os.Exit(1)
	}
}