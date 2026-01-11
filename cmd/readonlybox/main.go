package main

import (
	"fmt"
	"os"

	"github.com/panz/openroutertest/internal/readonlybox"
)

// readonlybox - A BusyBox-like read-only toolbox
// Single binary containing all read-only command wrappers

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "readonlybox: No command provided\n")
		fmt.Fprintf(os.Stderr, "Usage: readonlybox <command> [args...]\n")
		fmt.Fprintf(os.Stderr, "\nAvailable commands:\n")
		readonlybox.ListCommands()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	// Execute the command
	if err := readonlybox.ExecuteCommand(command, args); err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: %v\n", err)
		os.Exit(1)
	}
}