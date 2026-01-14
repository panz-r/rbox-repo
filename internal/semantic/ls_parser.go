package semantic

import (
	"fmt"
	"strings"
)

// LsCommand represents a parsed ls command
type LsCommand struct {
	Directories []string
	Options     map[string]interface{}
	ShowAll     bool
	LongFormat  bool
	HumanReadable bool
	Recursive   bool
	SortByTime  bool
	ReverseSort bool
	ShowHidden bool
}

// LsParser parses ls commands
type LsParser struct{}

// ParseArguments implements CommandParser for ls commands
func (l *LsParser) ParseArguments(args []string) (interface{}, error) {
	cmd := &LsCommand{
		Options: make(map[string]interface{}),
	}

	i := 0
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "-a", "--all":
			cmd.ShowAll = true
			cmd.ShowHidden = true
			cmd.Options["all"] = true
		case "-l":
			cmd.LongFormat = true
			cmd.Options["long_format"] = true
		case "-h", "--human-readable":
			cmd.HumanReadable = true
			cmd.Options["human_readable"] = true
		case "-R", "--recursive":
			cmd.Recursive = true
			cmd.Options["recursive"] = true
		case "-t":
			cmd.SortByTime = true
			cmd.Options["sort_by_time"] = true
		case "-r", "--reverse":
			cmd.ReverseSort = true
			cmd.Options["reverse"] = true
		case "-A":
			cmd.ShowHidden = true
			cmd.Options["show_hidden"] = true
		case "--":
			i++
			break
		default:
			// Handle combined options like -lh, -la, etc.
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'a':
						cmd.ShowAll = true
						cmd.ShowHidden = true
						cmd.Options["all"] = true
					case 'l':
						cmd.LongFormat = true
						cmd.Options["long_format"] = true
					case 'h':
						cmd.HumanReadable = true
						cmd.Options["human_readable"] = true
					case 'R':
						cmd.Recursive = true
						cmd.Options["recursive"] = true
					case 't':
						cmd.SortByTime = true
						cmd.Options["sort_by_time"] = true
					case 'r':
						cmd.ReverseSort = true
						cmd.Options["reverse"] = true
					case 'A':
						cmd.ShowHidden = true
						cmd.Options["show_hidden"] = true
					}
				}
			}
		}
		i++
	}

	// Remaining arguments are directories
	if i < len(args) {
		cmd.Directories = args[i:]
	}

	// If no directories specified, default to current directory
	if len(cmd.Directories) == 0 {
		cmd.Directories = []string{"."}
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for ls commands
func (l *LsParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*LsCommand)
	if !ok {
		return nil, fmt.Errorf("invalid ls command type")
	}

	operations := make([]SemanticOperation, 0)

	// Add read operations for each directory
	for _, dir := range cmd.Directories {
		// Base operation: read directory contents
		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    dir,
			Context:       "directory_listing",
			Parameters: map[string]interface{}{
				"command":       "ls",
				"options":       cmd.Options,
				"long_format":   cmd.LongFormat,
				"recursive":     cmd.Recursive,
				"show_hidden":   cmd.ShowHidden,
			},
		})

		// If recursive, add operations for subdirectories (conservative approximation)
		if cmd.Recursive {
			operations = append(operations, SemanticOperation{
				OperationType: OpRead,
				TargetPath:    dir + "/*",
				Context:       "recursive_directory_listing",
				Parameters: map[string]interface{}{
					"command":     "ls",
					"recursive":   true,
					"over_approximated": true, // Conservative: we don't know exact subdirs
				},
			})
		}

		// If long format, we're reading file metadata which might require additional permissions
		if cmd.LongFormat {
			operations = append(operations, SemanticOperation{
				OperationType: OpRead,
				TargetPath:    dir + "/.*",
				Context:       "file_metadata",
				Parameters: map[string]interface{}{
					"command":     "ls",
					"long_format": true,
				},
			})
		}
	}

	return operations, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for ls commands
func (l *LsParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*LsCommand)
	if !ok {
		return nil, fmt.Errorf("invalid ls command type")
	}

	// Get basic semantic operations
	operations, err := l.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("ls", operations, []SemanticOperation{})

	return graph, nil
}