package semantic

import (
	"fmt"
	"strings"
)

// CatCommand represents a parsed cat command
type CatCommand struct {
	InputFiles []string
	Options    map[string]bool
}

// CatParser parses cat commands
type CatParser struct{}

// ParseArguments implements CommandParser for cat commands
func (c *CatParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided")
	}

	cmd := &CatCommand{
		Options: make(map[string]bool),
	}

	// Parse options
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]
		if opt == "--" {
			i++
			break
		}

		// Simple option parsing (no values for now)
		for _, ch := range opt[1:] {
			cmd.Options[string(ch)] = true
		}
		i++
	}

	// Parse input files
	if i < len(args) {
		cmd.InputFiles = args[i:]
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for cat commands
func (c *CatParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*CatCommand)
	if !ok {
		return nil, fmt.Errorf("invalid cat command type")
	}

	operations := make([]SemanticOperation, 0)

	// Add read operations for each input file
	for _, file := range cmd.InputFiles {
		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    file,
			Context:       "input_file",
			Parameters: map[string]interface{}{
				"command": "cat",
			},
		})
	}

	// If no input files, cat reads from stdin (no file operation)
	if len(cmd.InputFiles) == 0 {
		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    "/dev/stdin",
			Context:       "stdin",
			Parameters: map[string]interface{}{
				"command": "cat",
			},
		})
	}

	return operations, nil
}