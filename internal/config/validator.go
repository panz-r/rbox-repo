package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/panz/openroutertest/internal/dsl"
)

// ValidateConfig validates a configuration for correctness
func ValidateConfig(config *dsl.AST) error {
	if config.Version == "" {
		return fmt.Errorf("version is required")
	}

	if config.BaseDir == "" {
		config.BaseDir = "."
	}

	// Validate base directory
	if !isValidPath(config.BaseDir) {
		return fmt.Errorf("invalid base directory: %s", config.BaseDir)
	}

	// Validate rules
	for _, rule := range config.Rules {
		err := validateAccessRule(rule)
		if err != nil {
			return fmt.Errorf("invalid rule for command %s: %v", rule.Command, err)
		}
	}

	// Validate workflows
	for _, workflow := range config.Workflows {
		err := validateWorkflow(workflow)
		if err != nil {
			return fmt.Errorf("invalid workflow %s: %v", workflow.Name, err)
		}
	}

	// Validate temp config
	if config.TempConfig != nil {
		err := validateTempConfig(config.TempConfig)
		if err != nil {
			return fmt.Errorf("invalid temp config: %v", err)
		}
	}

	return nil
}

func validateAccessRule(rule dsl.AccessRule) error {
	if rule.Command == "" {
		return fmt.Errorf("command name is required")
	}

	if len(rule.Directories) == 0 && len(rule.Operations) == 0 {
		return fmt.Errorf("rule must have at least one directory or operation")
	}

	// Validate directories
	for _, dir := range rule.Directories {
		if dir.Path == "" {
			return fmt.Errorf("directory path is required")
		}

		if !isValidPath(dir.Path) {
			return fmt.Errorf("invalid directory path: %s", dir.Path)
		}

		if dir.Level == dsl.AccessSuper || dir.Level == dsl.AccessSub {
			if dir.Depth <= 0 {
				return fmt.Errorf("depth must be positive for super/sub access")
			}
		}
	}

	// Validate operations
	for _, op := range rule.Operations {
		if op.OpType < dsl.OpRead || op.OpType > dsl.OpOverwrite {
			return fmt.Errorf("invalid operation type: %d", op.OpType)
		}

		if op.IsTemp && op.Path == "" {
			return fmt.Errorf("temp operation requires a path pattern")
		}
	}

	return nil
}

func validateWorkflow(workflow dsl.Workflow) error {
	if workflow.Name == "" {
		return fmt.Errorf("workflow name is required")
	}

	if len(workflow.Rules) == 0 {
		return fmt.Errorf("workflow must have at least one rule")
	}

	for _, rule := range workflow.Rules {
		err := validateAccessRule(rule)
		if err != nil {
			return fmt.Errorf("invalid rule in workflow: %v", err)
		}
	}

	return nil
}

func validateTempConfig(config *dsl.TempConfig) error {
	if config.Pattern == "" {
		return fmt.Errorf("pattern is required")
	}

	if config.MaxCount < 0 {
		return fmt.Errorf("max_count must be non-negative")
	}

	// Validate pattern
	if !strings.Contains(config.Pattern, "*") && !strings.Contains(config.Pattern, "?") {
		return fmt.Errorf("pattern should contain wildcards")
	}

	return nil
}

func isValidPath(path string) bool {
	if path == "" {
		return false
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return false
	}

	// Check for absolute paths or relative paths
	if !filepath.IsAbs(path) && !strings.HasPrefix(path, ".") && path != "/" {
		return false
	}

	// Check for invalid characters
	for _, char := range path {
		if char < 32 || char > 126 { // Non-printable ASCII
			return false
		}
	}

	return true
}
