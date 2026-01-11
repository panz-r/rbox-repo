package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/command"
	"github.com/panz/openroutertest/internal/roecho"
)

// ro-echo - Read-only echo wrapper
// This program prevents echo operations that could execute commands

func main() {
	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := roecho.AreEchoArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-echo: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the echo command with all arguments using executor
	executor := command.GetRealExecutor()
	cmd := executor.Command("echo", args...)
	executor.SetStdout(cmd, os.Stdout)
	executor.SetStderr(cmd, os.Stderr)
	executor.SetStdin(cmd, os.Stdin)

	if err := executor.Run(cmd); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-echo: Error executing echo: %v\n", err)
		os.Exit(1)
	}
}
