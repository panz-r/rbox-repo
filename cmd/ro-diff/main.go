package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rodiff"
)

// ro-diff - Read-only diff wrapper
// This program executes diff command with read-only security checks

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "ro-diff: At least two files required\n")
		fmt.Fprintf(os.Stderr, "Usage: ro-diff <file1> <file2>\n")
		os.Exit(1)
	}

	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rodiff.AreDiffArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-diff: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the diff command with all arguments
	runDiffCommand(args)
}

func runDiffCommand(args []string) {
	cmd := exec.Command("diff", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-diff: Error executing diff: %v\n", err)
		os.Exit(1)
	}
}