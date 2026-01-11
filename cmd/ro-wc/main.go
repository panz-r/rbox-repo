package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rowc"
)

// ro-wc - Read-only wc wrapper
// This program prevents any wc commands that could potentially be dangerous

func main() {
	if len(os.Args) < 2 {
		// wc requires at least one argument (file or option)
		fmt.Fprintf(os.Stderr, "ro-wc: No arguments provided\n")
		fmt.Fprintf(os.Stderr, "Usage: ro-wc [options] [files...]\n")
		os.Exit(1)
	}

	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rowc.AreWcArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-wc: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the wc command with all arguments
	runWcCommand(args)
}

func runWcCommand(args []string) {
	cmd := exec.Command("wc", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-wc: Error executing wc: %v\n", err)
		os.Exit(1)
	}
}