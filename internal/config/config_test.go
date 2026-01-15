package config

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/panz/openroutertest/internal/dsl"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file with correct DSL format
	configContent := `version: "1.0"
base_directory: /home/user/project
commands:
  - command: ls
    operations:
      - op_type: 0
    directories:
      - path: /home/user/project/
        level: 0
  - command: cat
    operations:
      - op_type: 0
    directories:
      - path: /home/user/project/
        level: 0
temp_files:
  pattern: /tmp/readonlybox_*
  max_size: 10MB
  max_count: 50
  auto_cleanup: 24h
`

	tmpfile, err := ioutil.TempFile("", "readonlybox_test_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(configContent)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpfile.Close()

	// Load the config
	config, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Validate config
	if config.Version != "1.0" {
		t.Errorf("Expected version 1.0, got %s", config.Version)
	}

	if config.BaseDir != "/home/user/project" {
		t.Errorf("Expected base directory /home/user/project, got %s", config.BaseDir)
	}

	if len(config.Rules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(config.Rules))
	}

	if config.TempConfig == nil {
		t.Error("Expected temp config, got nil")
	} else {
		if config.TempConfig.Pattern != "/tmp/readonlybox_*" {
			t.Errorf("Expected pattern /tmp/readonlybox_*, got %s", config.TempConfig.Pattern)
		}
	}
}

func TestLoadDefaultConfig(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("Failed to load default config: %v", err)
	}

	if config.Version != "1.0" {
		t.Errorf("Expected version 1.0, got %s", config.Version)
	}

	if config.BaseDir != "." {
		t.Errorf("Expected base directory ., got %s", config.BaseDir)
	}

	if len(config.Rules) != 4 {
		t.Errorf("Expected 4 rules, got %d", len(config.Rules))
	}

	if config.TempConfig == nil {
		t.Error("Expected temp config, got nil")
	}
}

func TestSaveConfig(t *testing.T) {
	// Create a test config
	config := &dsl.AST{
		Version: "1.0",
		BaseDir: "/test",
		Rules: []dsl.AccessRule{
			{
				Command: "test",
				Operations: []dsl.FileOperation{
					{OpType: dsl.OpRead},
				},
				Directories: []dsl.DirectoryAccess{
					{
						Path:  "/test",
						Level: dsl.AccessAt,
					},
				},
			},
		},
	}

	tmpfile, err := ioutil.TempFile("", "readonlybox_save_test_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	// Save the config
	err = SaveConfig(config, tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Load it back
	loadedConfig, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load saved config: %v", err)
	}

	// Compare
	if loadedConfig.Version != config.Version {
		t.Errorf("Version mismatch: expected %s, got %s", config.Version, loadedConfig.Version)
	}

	if loadedConfig.BaseDir != config.BaseDir {
		t.Errorf("BaseDir mismatch: expected %s, got %s", config.BaseDir, loadedConfig.BaseDir)
	}

	if len(loadedConfig.Rules) != len(config.Rules) {
		t.Errorf("Rules count mismatch: expected %d, got %d", len(config.Rules), len(loadedConfig.Rules))
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *dsl.AST
		shouldError bool
	}{
		{
			name: "valid config",
			config: &dsl.AST{
				Version: "1.0",
				BaseDir: "/test",
				Rules: []dsl.AccessRule{
					{
						Command: "ls",
						Operations: []dsl.FileOperation{
							{OpType: dsl.OpRead},
						},
						Directories: []dsl.DirectoryAccess{
							{
								Path:  "/test",
								Level: dsl.AccessAt,
							},
						},
					},
				},
			},
			shouldError: false,
		},
		{
			name: "missing version",
			config: &dsl.AST{
				Version: "",
				BaseDir: "/test",
			},
			shouldError: true,
		},
		{
			name: "invalid path",
			config: &dsl.AST{
				Version: "1.0",
				BaseDir: "/test/../invalid",
			},
			shouldError: true,
		},
		{
			name: "invalid rule",
			config: &dsl.AST{
				Version: "1.0",
				BaseDir: "/test",
				Rules: []dsl.AccessRule{
					{
						Command: "", // empty command
					},
				},
			},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfig(tt.config)
			if tt.shouldError && err == nil {
				t.Error("Expected error, got nil")
			} else if !tt.shouldError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
