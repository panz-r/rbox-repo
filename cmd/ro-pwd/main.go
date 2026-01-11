package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/ropwd"
)

// ro-pwd - Read-only pwd wrapper
// This program executes pwd command with read-only security checks

func main() {
	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := ropwd.ArePwdArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-pwd: Error - %s and is not allowed in read-only mode\n", reason)
		os.Exit(1)
	}

	// Execute the pwd command with all arguments
	runPwdCommand(args)
}

func runPwdCommand(args []string) {
	cmd := exec.Command("pwd", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-pwd: Error executing pwd: %v\n", err)
		os.Exit(1)
	}
}