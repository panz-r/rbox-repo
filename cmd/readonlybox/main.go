package main

import (
	"fmt"
	"os"

	"github.com/panz/openroutertest/internal/access"
	"github.com/panz/openroutertest/internal/config"
	"github.com/panz/openroutertest/internal/readonlybox"
)

// readonlybox - A BusyBox-like read-only toolbox
// Single binary containing all read-only command wrappers

func main() {
	// Handle special commands first
	if len(os.Args) >= 2 {
		if os.Args[1] == "--configure-access" {
			handleConfigureAccess()
			return
		}
		if os.Args[1] == "--show-access" {
			handleShowAccess()
			return
		}
	}

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "readonlybox: No command provided\n")
		fmt.Fprintf(os.Stderr, "Usage: readonlybox <command> [args...]\n")
		fmt.Fprintf(os.Stderr, "\nAvailable commands:\n")
		readonlybox.ListCommands()
		fmt.Fprintf(os.Stderr, "\nSpecial commands:\n")
		fmt.Fprintf(os.Stderr, "  --configure-access <config-file>  Configure access control\n")
		fmt.Fprintf(os.Stderr, "  --show-access                    Show current access configuration\n")
		os.Exit(1)
	}

	// Load access control configuration
	accessEngine, err := loadAccessControlEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: Failed to load access control: %v\n", err)
		fmt.Fprintf(os.Stderr, "Using default read-only mode\n")
		// Continue with default behavior
	} else {
		// Set the global access engine
		readonlybox.SetAccessEngine(accessEngine)
	}

	command := os.Args[1]
	args := os.Args[2:]

	// Check if command is allowed by access control
	if accessEngine != nil {
		allowedCommands := accessEngine.GetAllowedCommands()
		isAllowed := false
		for _, cmd := range allowedCommands {
			if cmd == command {
				isAllowed = true
				break
			}
		}

		if !isAllowed {
			fmt.Fprintf(os.Stderr, "readonlybox: Command '%s' is not allowed by access control policy\n", command)
			os.Exit(1)
		}
	}

	// Execute the command
	if err := readonlybox.ExecuteCommand(command, args); err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: %v\n", err)
		os.Exit(1)
	}
}

func loadAccessControlEngine() (*access.AccessControlEngine, error) {
	// Try to find and load configuration
	configPath, err := config.FindConfigFile()
	if err != nil {
		// No config file found, use default
		return nil, nil
	}

	// Load the configuration
	configAST, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	// Create access control engine
	engine := access.NewAccessControlEngine(*configAST)

	return engine, nil
}

func handleConfigureAccess() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: readonlybox --configure-access <config-file>\n")
		os.Exit(1)
	}

	configPath := os.Args[2]

	// Load the configuration
	configAST, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Save it to the default location
	err = config.SaveConfig(configAST, ".readonlybox.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: Failed to save config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Access control configuration loaded from %s and saved to .readonlybox.yaml\n", configPath)
}

func handleShowAccess() {
	// Try to load current configuration
	configPath, err := config.FindConfigFile()
	if err != nil {
		fmt.Printf("No access control configuration found. Using default read-only mode.\n")
		return
	}

	configAST, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: Failed to load current config: %v\n", err)
		return
	}

	fmt.Printf("Current Access Control Configuration:\n")
	fmt.Printf("  Version: %s\n", configAST.Version)
	fmt.Printf("  Base Directory: %s\n", configAST.BaseDir)
	fmt.Printf("  Commands: %d rules\n", len(configAST.Rules))

	if configAST.TempConfig != nil {
		fmt.Printf("  Temp Files:\n")
		fmt.Printf("    Pattern: %s\n", configAST.TempConfig.Pattern)
		fmt.Printf("    Max Size: %s\n", configAST.TempConfig.MaxSize)
		fmt.Printf("    Max Count: %d\n", configAST.TempConfig.MaxCount)
		fmt.Printf("    Auto Cleanup: %s\n", configAST.TempConfig.AutoCleanup)
	}
}
