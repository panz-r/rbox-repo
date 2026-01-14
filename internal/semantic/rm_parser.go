package semantic

import (
	"fmt"
	"strings"
)

// RmCommand represents a parsed rm or rmdir command
type RmCommand struct {
	CommandType string   // "rm" or "rmdir"
	Targets     []string // Files/directories to remove
	Options     map[string]interface{}
	Recursive   bool
	Force       bool
	Interactive bool
	Verbose     bool
}

// RmParser parses rm and rmdir commands
type RmParser struct{}

// ParseArguments implements CommandParser for rm/rmdir commands
func (r *RmParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified for rm parser")
	}

	cmd := &RmCommand{
		CommandType: args[0], // "rm" or "rmdir"
		Options:     make(map[string]interface{}),
	}

	i := 1
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "-r", "-R", "--recursive":
			cmd.Recursive = true
			cmd.Options["recursive"] = true
		case "-f", "--force":
			cmd.Force = true
			cmd.Options["force"] = true
		case "-i", "--interactive":
			cmd.Interactive = true
			cmd.Options["interactive"] = true
		case "-v", "--verbose":
			cmd.Verbose = true
			cmd.Options["verbose"] = true
		case "--":
			i++
			break
		default:
			// Handle combined options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'r', 'R':
						cmd.Recursive = true
						cmd.Options["recursive"] = true
					case 'f':
						cmd.Force = true
						cmd.Options["force"] = true
					case 'i':
						cmd.Interactive = true
						cmd.Options["interactive"] = true
					case 'v':
						cmd.Verbose = true
						cmd.Options["verbose"] = true
					}
				}
			}
		}
		i++
	}

	// Parse targets
	if i < len(args) {
		cmd.Targets = args[i:]
	} else {
		return nil, fmt.Errorf("missing targets for %s command", cmd.CommandType)
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for rm/rmdir commands
func (r *RmParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*RmCommand)
	if !ok {
		return nil, fmt.Errorf("invalid rm command type")
	}

	operations := make([]SemanticOperation, 0)
	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// rm/rmdir commands are inherently dangerous - they delete files
	for _, target := range cmd.Targets {
		// First, we need to read the target to check if it exists and what type it is
		builder.AddReadOperation(target, "target_read")
			
			builder = builder.WithParameter("command", cmd.CommandType)
			
			builder = builder.WithParameter("dangerous", true) // Even reading is part of dangerous operation

		// Read metadata
		builder.AddReadOperation(target+".meta", "target_metadata")
			
			builder = builder.WithParameter("command", cmd.CommandType)
			
			builder = builder.WithParameter("over_approximated", true)

		// The actual delete operation
		if cmd.CommandType == "rm" {
			builder.AddWriteOperation(target, "file_delete")
				
			builder = builder.WithParameter("command", cmd.CommandType)
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("delete_operation", true)
		} else { // rmdir
			builder.AddWriteOperation(target, "directory_delete")
				
			builder = builder.WithParameter("command", cmd.CommandType)
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("delete_operation", true)
		}

		// If recursive, we need to handle contents conservatively
		if cmd.Recursive {
			builder.AddWriteOperation(target+"/*", "recursive_delete")
				
			builder = builder.WithParameter("command", cmd.CommandType)
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("delete_operation", true)
				
			builder = builder.WithParameter("over_approximated", true) // Conservative: unknown contents
		}

		// If force is set, we might delete without confirmation
		if cmd.Force {
			builder.AddWriteOperation(target, "force_delete")
				
			builder = builder.WithParameter("command", cmd.CommandType)
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("force", true)
				
			builder = builder.WithParameter("high_risk", true) // Force delete is higher risk
		}
	}

	// Add operations for interactive mode
	if cmd.Interactive {
		builder.AddReadOperation("/dev/tty", "interactive_prompt")
			
			builder = builder.WithParameter("command", cmd.CommandType)
			
			builder = builder.WithParameter("interactive", true)
	}

	operations = builder.Build()

	return operations, nil
}
// GetOperationGraph implements the enhanced CommandParser interface for rm commands
func (p *RmParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*RmCommand)
	if !ok {
		return nil, fmt.Errorf("invalid rm command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("rm", operations, []SemanticOperation{})

	return graph, nil
}

