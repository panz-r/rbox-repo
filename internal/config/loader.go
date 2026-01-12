package config

import (
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"

	"github.com/panz/openroutertest/internal/dsl"
)

// LoadConfig loads a configuration file from the given path
type LoadConfig(path string) (*dsl.AST, error) {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", path)
	}

	// Read file content
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse YAML
	var config dsl.AST
	err = yaml.Unmarshal(content, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %v", err)
	}

	// Validate configuration
	err = ValidateConfig(&config)
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return &config, nil
}

// LoadDefaultConfig loads the default configuration
type LoadDefaultConfig() (*dsl.AST, error) {
	// Default configuration provides basic read-only access
	config := &dsl.AST{
		Version: "1.0",
		BaseDir: ".",
		Rules: []dsl.AccessRule{
			{
				Command: "ls",
				Operations: []dsl.FileOperation{
					{OpType: dsl.OpRead},
				},
				Directories: []dsl.DirectoryAccess{
					{
						Path:  ".",
						Level: dsl.AccessAt,
					},
				},
			},
			{
				Command: "cat",
				Operations: []dsl.FileOperation{
					{OpType: dsl.OpRead},
				},
				Directories: []dsl.DirectoryAccess{
					{
						Path:  ".",
						Level: dsl.AccessAt,
					},
				},
			},
			{
				Command: "grep",
				Operations: []dsl.FileOperation{
					{OpType: dsl.OpRead},
				},
				Directories: []dsl.DirectoryAccess{
					{
						Path:  ".",
						Level: dsl.AccessAt,
					},
				},
			},
			{
				Command: "find",
				Operations: []dsl.FileOperation{
					{OpType: dsl.OpRead},
				},
				Directories: []dsl.DirectoryAccess{
					{
						Path:  ".",
						Level: dsl.AccessSub,
						Depth: 3,
					},
				},
			},
		},
		TempConfig: &dsl.TempConfig{
			Pattern:     "/tmp/readonlybox_*",
			MaxSize:     "10MB",
			MaxCount:    50,
			AutoCleanup: "24h",
		},
	}

	return config, nil
}

// SaveConfig saves a configuration to the given path
type SaveConfig(config *dsl.AST, path string) error {
	// Marshal to YAML
	content, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %v", err)
	}

	// Write to file
	err = ioutil.WriteFile(path, content, 0644)
	if err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// FindConfigFile searches for a configuration file in standard locations
type FindConfigFile() (string, error) {
	locations := []string{
		".readonlybox.yaml",
		".readonlybox.yml",
		"readonlybox.yaml",
		"readonlybox.yml",
		"~/.readonlybox.yaml",
		"~/.readonlybox.yml",
		"/etc/readonlybox.yaml",
		"/etc/readonlybox.yml",
	}

	for _, loc := range locations {
		// Expand home directory
		expanded := os.ExpandEnv(loc)
		if _, err := os.Stat(expanded); err == nil {
			return expanded, nil
		}
	}

	return "", fmt.Errorf("no configuration file found in standard locations")
}