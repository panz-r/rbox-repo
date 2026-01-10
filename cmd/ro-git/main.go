package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rogit"
)

// ro-git - Read-only git wrapper
// This program prevents any git commands that could modify the repository

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "ro-git: No command provided\n")
		fmt.Fprintf(os.Stderr, "Usage: ro-git <git-command> [args...]\n")
		os.Exit(1)
	}

	gitCommand := os.Args[1]
	args := os.Args[2:]

	// Check if the command is allowed
	if allowed, reason := rogit.IsAllowedCommand(gitCommand, args); !allowed {
		fmt.Fprintf(os.Stderr, "ro-git: Error - '%s' %s in read-only mode\n", gitCommand, reason)
		os.Exit(1)
	}

	// Execute the git command with all remaining arguments
	cmd := exec.Command("git", append([]string{gitCommand}, args...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-git: Error executing git: %v\n", err)
		os.Exit(1)
	}
}