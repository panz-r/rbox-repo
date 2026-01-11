package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/panz/openroutertest/internal/robash"
)

// ro-bash - Read-only bash wrapper
// This program validates bash scripts and commands before execution

func main() {
	args := os.Args[1:]

	// Handle different modes
	if len(args) == 0 {
		// Interactive mode - start read-only shell
		startInteractiveShell()
		return
	}

	// Check if we're executing a script file
	if len(args) >= 2 && args[0] == "--script" {
		// Script execution mode
		scriptFile := args[1]
		if safe, reason := robash.IsScriptFileSafe(scriptFile); !safe {
			fmt.Fprintf(os.Stderr, "ro-bash: Error - script file '%s' %s\n", scriptFile, reason)
			os.Exit(1)
		}

		// Execute the script with bash
		cmd := exec.Command("bash", append([]string{"--norc", "--noprofile"}, args[1:]...)...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin

		if err := cmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			fmt.Fprintf(os.Stderr, "ro-bash: Error executing script: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Check if we're executing a command directly
	if safe, reason := robash.IsCommandLineSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-bash: Error - command '%s' %s\n", args[0], reason)
		os.Exit(1)
	}

	// Execute the command with bash
	cmd := exec.Command("bash", append([]string{"--norc", "--noprofile", "-c"}, strings.Join(args, " "))...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "ro-bash: Error executing command: %v\n", err)
		os.Exit(1)
	}
}

// startInteractiveShell starts a read-only interactive bash shell
func startInteractiveShell() {
	fmt.Println("Read-only Bash Shell - Type 'exit' to quit")
	fmt.Println("Only safe read-only commands are allowed.")

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("ro-bash> ")

		// Read input
		input, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Println()
				break
			}
			fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
			continue
		}

		// Trim whitespace and handle empty input
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		// Check for exit command
		if input == "exit" || input == "quit" {
			break
		}

		// Validate the command
		if safe, reason := robash.IsInteractiveCommandSafe(input); !safe {
			fmt.Fprintf(os.Stderr, "ro-bash: Error - %s\n", reason)
			continue
		}

		// Execute the command
		cmd := exec.Command("bash", "--norc", "--noprofile", "-c", input)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin

		if err := cmd.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != 0 {
				// Command failed, but that's OK - show the error
				continue
			}
			fmt.Fprintf(os.Stderr, "ro-bash: Error executing command: %v\n", err)
		}
	}

	fmt.Println("Goodbye!")
}
