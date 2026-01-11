package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rofile"
)

// ro-file - Read-only file wrapper
// This program prevents any file commands that could potentially be dangerous

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "ro-file: No file provided\n")
		fmt.Fprintf(os.Stderr, "Usage: ro-file <file>\n")
		os.Exit(1)
	}

	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rofile.AreFileArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-file: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the file command with all arguments
	runFileCommand(args)
}

func runFileCommand(args []string) {
	cmd := exec.Command("file", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-file: Error executing file: %v\n", err)
		os.Exit(1)
	}
}