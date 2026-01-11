package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rouname"
)

// ro-uname - Read-only uname wrapper
// This program prevents any uname commands that could potentially be dangerous

func main() {
	if len(os.Args) < 2 {
		// uname can be called without arguments, so we allow this
		// Execute uname with no arguments
		runUnameCommand([]string{})
		return
	}

	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rouname.AreUnameArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-uname: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the uname command with all arguments
	runUnameCommand(args)
}

func runUnameCommand(args []string) {
	cmd := exec.Command("uname", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-uname: Error executing uname: %v\n", err)
		os.Exit(1)
	}
}