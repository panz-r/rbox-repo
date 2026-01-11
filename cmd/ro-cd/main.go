package main

import (
	"fmt"
	"os"

	"github.com/panz/openroutertest/internal/rocd"
)

// ro-cd - Read-only cd wrapper
// This program changes directory but prevents dangerous operations

func main() {
	args := os.Args[1:]

	// Check if arguments are safe
	if safe, reason := rocd.AreCdArgsSafe(args); !safe {
		fmt.Fprintf(os.Stderr, "ro-cd: Error - '%s' %s and is not allowed in read-only mode\n", args[0], reason)
		os.Exit(1)
	}

	// Perform the directory change
	err := rocd.ChangeDirectory(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ro-cd: Error changing directory: %v\n", err)
		os.Exit(1)
	}

	// Print the new directory (like some cd implementations)
	newDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ro-cd: Error getting current directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s\n", newDir)
}
