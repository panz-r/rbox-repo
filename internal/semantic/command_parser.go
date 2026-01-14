package semantic

import (
	"fmt"
)

// CommandParser interface for command-specific parsing
type CommandParser interface {
	// ParseArguments parses command-specific arguments
	ParseArguments(args []string) (interface{}, error)

	// GetSemanticOperations extracts semantic operations from parsed command
	GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error)

	// GetOperationGraph extracts complete operation graph from parsed command (enhanced)
	GetOperationGraph(parsed interface{}) (*OperationGraph, error)
}

// GenericCommand represents a generic parsed command
type GenericCommand struct {
	Command string
	Args    []string
}

// GenericParser is a fallback parser for unknown commands
type GenericParser struct{}

// ParseArguments implements CommandParser for generic commands
func (g *GenericParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided")
	}
	return &GenericCommand{
		Command: args[0],
		Args:    args[1:],
	}, nil
}

// GetSemanticOperations implements CommandParser for generic commands
func (g *GenericParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*GenericCommand)
	if !ok {
		return nil, fmt.Errorf("invalid parsed command type")
	}

	// For unknown commands, we use conservative over-approximation
	// This ensures we never under-approximate the command's effects
	operations := make([]SemanticOperation, 0)

	// Add read operations for all arguments (conservative approach)
	for _, arg := range cmd.Args {
		// Skip options (starting with -)
		if len(arg) > 0 && arg[0] == '-' {
			continue
		}

		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    arg,
			Context:       "argument",
			Parameters: map[string]interface{}{
				"command":         cmd.Command,
				"over_approximated": true,
			},
		})
	}

	// If no arguments, add a conservative operation
	if len(operations) == 0 {
		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    "*",
			Context:       "conservative_approximation",
			Parameters: map[string]interface{}{
				"command":         cmd.Command,
				"over_approximated": true,
			},
		})
	}

	return operations, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for generic commands
func (g *GenericParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	cmd, ok := parsed.(*GenericCommand)
	if !ok {
		return nil, fmt.Errorf("invalid parsed command type")
	}

	// Get basic semantic operations
	operations, err := g.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph with conservative assumptions
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph(cmd.Command, operations, []SemanticOperation{})

	return graph, nil
}