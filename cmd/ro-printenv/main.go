package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/roprintenv"
)

// ro-printenv - Read-only printenv wrapper
// This program executes printenv command with read-only security checks

func main() {
	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := roprintenv.ArePrintenvArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-printenv: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the printenv command with all arguments
	runPrintenvCommand(args)
}

func runPrintenvCommand(args []string) {
	cmd := exec.Command("printenv", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-printenv: Error executing printenv: %v\n", err)
		os.Exit(1)
	}
}