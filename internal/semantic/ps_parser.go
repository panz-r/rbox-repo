package semantic

import (
	"fmt"
	"strings"
)

// PsCommand represents a parsed ps command
type PsCommand struct {
	Options      map[string]interface{}
	ShowAll      bool
	FullFormat   bool
	LongFormat   bool
	UserSpec     string
	ProcessIDs   []string
	ShowThreads  bool
	ShowForest   bool
	NoHeaders    bool
}

// PsParser parses ps commands
type PsParser struct{}

// ParseArguments implements CommandParser for ps commands
func (p *PsParser) ParseArguments(args []string) (interface{}, error) {
	cmd := &PsCommand{
		Options: make(map[string]interface{}),
	}

	i := 0
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "-e", "-A", "--every-process":
			cmd.ShowAll = true
			cmd.Options["show_all"] = true
		case "-f", "--full", "--full-format":
			cmd.FullFormat = true
			cmd.Options["full_format"] = true
		case "-l", "--long":
			cmd.LongFormat = true
			cmd.Options["long_format"] = true
		case "-u", "--user":
			cmd.FullFormat = true
			cmd.Options["user_format"] = true
		case "-U":
			// User list follows
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing user list after -U")
			}
			cmd.UserSpec = args[i+1]
			cmd.Options["user_spec"] = args[i+1]
			i += 2
			continue
		case "-p":
			// Process IDs follow
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing process IDs after -p")
			}
			// Parse comma-separated PIDs
			pids := strings.Split(args[i+1], ",")
			cmd.ProcessIDs = append(cmd.ProcessIDs, pids...)
			cmd.Options["process_ids"] = pids
			i += 2
			continue
		case "-T", "-H":
			cmd.ShowThreads = true
			cmd.Options["show_threads"] = true
		case "--forest":
			cmd.ShowForest = true
			cmd.Options["show_forest"] = true
		case "-N", "--no-headers":
			cmd.NoHeaders = true
			cmd.Options["no_headers"] = true
		case "--":
			i++
			break
		default:
			// Handle other options
			cmd.Options[opt] = true
		}
		i++
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for ps commands
func (p *PsParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*PsCommand)
	if !ok {
		return nil, fmt.Errorf("invalid ps command type")
	}

	operations := make([]SemanticOperation, 0)

	// PS reads process information from the system
	// This is a conservative approximation since we don't know exactly which processes will be accessed
	operations = append(operations, SemanticOperation{
		OperationType: OpRead,
		TargetPath:    "/proc/*",
		Context:       "process_listing",
		Parameters: map[string]interface{}{
			"command": "ps",
			"options": cmd.Options,
			"show_all": cmd.ShowAll,
			"full_format": cmd.FullFormat,
			"user_spec": cmd.UserSpec,
			"over_approximated": true, // Conservative: we read all accessible processes
		},
	})

	// If specific PIDs are requested, add precise operations for each
	if len(cmd.ProcessIDs) > 0 {
		for _, pid := range cmd.ProcessIDs {
			operations = append(operations, SemanticOperation{
				OperationType: OpRead,
				TargetPath:    "/proc/" + pid,
				Context:       "process_info",
				Parameters: map[string]interface{}{
					"command": "ps",
					"pid":      pid,
					"precise":   true, // Precise: we know exactly which PID
				},
			})
		}
	} else if cmd.ShowAll {
		// If showing all processes, this is definitely an over-approximation
		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    "/proc/*/status",
			Context:       "all_process_status",
			Parameters: map[string]interface{}{
				"command": "ps",
				"over_approximated": true,
				"dangerous": true, // Reading all processes can be sensitive
			},
		})
	}

	return operations, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for ps commands
func (p *PsParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*PsCommand)
	if !ok {
		return nil, fmt.Errorf("invalid ps command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("ps", operations, []SemanticOperation{})

	return graph, nil
}