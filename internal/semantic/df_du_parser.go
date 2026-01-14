package semantic

import (
	"fmt"
	"strings"
)

// DfDuCommand represents a parsed df or du command
type DfDuCommand struct {
	CommandType  string // "df" or "du"
	Paths        []string
	Options      map[string]interface{}
	HumanReadable bool
	ShowAll      bool
	ShowInodes   bool
	MaxDepth     int
	Summarize    bool
}

// DfDuParser parses df and du commands
type DfDuParser struct{}

// ParseArguments implements CommandParser for df/du commands
func (d *DfDuParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified for df/du parser")
	}

	cmd := &DfDuCommand{
		CommandType: args[0], // "df" or "du"
		Options:     make(map[string]interface{}),
	}

	i := 1
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "-h", "--human-readable":
			cmd.HumanReadable = true
			cmd.Options["human_readable"] = true
		case "-a", "--all":
			cmd.ShowAll = true
			cmd.Options["show_all"] = true
		case "-i", "--inodes":
			cmd.ShowInodes = true
			cmd.Options["show_inodes"] = true
		case "--max-depth":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing depth value after --max-depth")
			}
			// Simple parsing - in real implementation would use strconv.Atoi
			cmd.MaxDepth = 1 // Default
			cmd.Options["max_depth"] = args[i+1]
			i += 2
			continue
		case "-s", "--summarize":
			cmd.Summarize = true
			cmd.Options["summarize"] = true
		case "--":
			i++
			break
		default:
			// Handle other options
			cmd.Options[opt] = true
		}
		i++
	}

	// Remaining arguments are paths
	if i < len(args) {
		cmd.Paths = args[i:]
	}

	// If no paths specified, default behavior depends on command
	if len(cmd.Paths) == 0 {
		if cmd.CommandType == "df" {
			// df with no paths shows all filesystems
			cmd.Paths = []string{"all_filesystems"}
		} else if cmd.CommandType == "du" {
			// du with no paths shows current directory
			cmd.Paths = []string{"."}
		}
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for df/du commands
func (d *DfDuParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*DfDuCommand)
	if !ok {
		return nil, fmt.Errorf("invalid df/du command type")
	}

	operations := make([]SemanticOperation, 0)

	if cmd.CommandType == "df" {
		// df reads filesystem information
		// This is a sound model: we know df reads filesystem stats
		for _, path := range cmd.Paths {
			if path == "all_filesystems" {
				// Conservative: read all mounted filesystems
				operations = append(operations, SemanticOperation{
					OperationType: OpRead,
					TargetPath:    "/etc/mtab",
					Context:       "mounted_filesystems",
					Parameters: map[string]interface{}{
						"command":       "df",
						"options":       cmd.Options,
						"human_readable": cmd.HumanReadable,
						"show_inodes":   cmd.ShowInodes,
						"over_approximated": true, // We don't know all mount points
					},
				})
				operations = append(operations, SemanticOperation{
					OperationType: OpRead,
					TargetPath:    "/proc/mounts",
					Context:       "mount_info",
					Parameters: map[string]interface{}{
						"command": "df",
					},
				})
			} else {
				// Precise: read specific filesystem
				operations = append(operations, SemanticOperation{
					OperationType: OpRead,
					TargetPath:    path,
					Context:       "filesystem_info",
					Parameters: map[string]interface{}{
						"command":       "df",
						"options":       cmd.Options,
						"human_readable": cmd.HumanReadable,
						"show_inodes":   cmd.ShowInodes,
					},
				})
			}
		}
	} else if cmd.CommandType == "du" {
		// du reads directory information and calculates usage
		// This uses conservative approximation for subdirectories
		for _, path := range cmd.Paths {
			// Base operation: read the specified directory
			operations = append(operations, SemanticOperation{
				OperationType: OpRead,
				TargetPath:    path,
				Context:       "directory_usage",
				Parameters: map[string]interface{}{
					"command":       "du",
					"options":       cmd.Options,
					"human_readable": cmd.HumanReadable,
					"summarize":     cmd.Summarize,
				},
			})

			// If max depth is not limited, we need conservative approximation
			if cmd.MaxDepth == 0 {
				operations = append(operations, SemanticOperation{
					OperationType: OpRead,
					TargetPath:    path + "/*",
					Context:       "recursive_directory_usage",
					Parameters: map[string]interface{}{
						"command":           "du",
						"over_approximated": true, // Conservative: unknown subdirectory depth
					},
				})
			}
		}
	}

	return operations, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for df/du commands
func (d *DfDuParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*DfDuCommand)
	if !ok {
		return nil, fmt.Errorf("invalid df/du command type")
	}

	// Get basic semantic operations
	operations, err := d.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("df", operations, []SemanticOperation{})

	return graph, nil
}