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

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// Add read operations for each input file
	for _, file := range cmd.InputFiles {
		builder.AddReadOperation(file, "input_file")
		builder.WithCommandInfo("cat")
		builder.WithPrecise() // Precise since we know exactly what file is being read
	}

	// If no input files, cat reads from stdin (no file operation)
	if len(cmd.InputFiles) == 0 {
		builder.AddReadOperation("/dev/stdin", "stdin")
		builder.WithCommandInfo("cat")
		builder.WithOverApproximated() // Less precise since we don't know stdin source
	}

	return builder.Build(), nil
}

// GetOperationGraph implements the enhanced CommandParser interface for cat commands
func (c *CatParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*CatCommand)
	if !ok {
		return nil, fmt.Errorf("invalid cat command type")
	}

	// Get basic semantic operations
	operations, err := c.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("cat", operations, []SemanticOperation{})

	return graph, nil
}