package semantic

import (
	"fmt"
	"strings"
)

// SedAWKCommand represents a parsed sed or awk command
type SedAWKCommand struct {
	CommandType string // "sed" or "awk"
	Script      string
	Files       []string
	Options     map[string]interface{}
	InPlace     bool
	BackupExt   string
	FieldSep    string
}

// SedAWKParser parses sed and awk commands
type SedAWKParser struct{}

// ParseArguments implements CommandParser for sed/awk commands
func (s *SedAWKParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified for sed/awk parser")
	}

	cmd := &SedAWKCommand{
		CommandType: args[0], // "sed" or "awk"
		Options:     make(map[string]interface{}),
	}

	i := 1
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "-i", "--in-place":
			cmd.InPlace = true
			cmd.Options["in_place"] = true
		case "-e":
			// Script follows
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing script after -e")
			}
			cmd.Script = args[i+1]
			cmd.Options["script"] = args[i+1]
			i += 2
			continue
		case "-f":
			// Script file follows
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing script file after -f")
			}
			cmd.Options["script_file"] = args[i+1]
			i += 2
			continue
		case "-F":
			cmd.FieldSep = "\t"
			cmd.Options["field_separator"] = "\t"
		case "-v":
			// Variable assignment for awk
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing variable assignment after -v")
			}
			cmd.Options["variable"] = args[i+1]
			i += 2
			continue
		case "--":
			i++
			break
		default:
			// Handle other options
			cmd.Options[opt] = true
		}
		i++
	}

	// If no script specified yet, the next argument might be the script
	if cmd.Script == "" && i < len(args) && !strings.HasPrefix(args[i], "-") {
		// For sed, this could be the script
		if cmd.CommandType == "sed" {
			cmd.Script = args[i]
			cmd.Options["script"] = args[i]
			i++
		}
	}

	// Remaining arguments are files
	if i < len(args) {
		cmd.Files = args[i:]
	}

	// If no files specified, read from stdin
	if len(cmd.Files) == 0 {
		cmd.Files = []string{"/dev/stdin"}
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for sed/awk commands
func (s *SedAWKParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*SedAWKCommand)
	if !ok {
		return nil, fmt.Errorf("invalid sed/awk command type")
	}

	operations := make([]SemanticOperation, 0)

	// Add read operations for each input file
	for _, file := range cmd.Files {
		// Skip stdin placeholder if it's not actually used
		if file == "/dev/stdin" && len(cmd.Files) > 1 {
			continue
		}

		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    file,
			Context:       "input_file",
			Parameters: map[string]interface{}{
				"command": cmd.CommandType,
				"script":  cmd.Script,
			},
		})

		// For text processing, we might also read file metadata (conservative)
		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    file + ".meta",
			Context:       "file_metadata",
			Parameters: map[string]interface{}{
				"command":           cmd.CommandType,
				"over_approximated": true, // Conservative: might read metadata
			},
		})
	}

	// If in-place editing is requested, add write operations
	if cmd.InPlace {
		for _, file := range cmd.Files {
			// Skip stdin for in-place editing
			if file == "/dev/stdin" {
				continue
			}
			operations = append(operations, SemanticOperation{
				OperationType: OpEdit,
				TargetPath:    file,
				Context:       "in_place_edit",
				Parameters: map[string]interface{}{
					"command":    cmd.CommandType,
					"script":     cmd.Script,
					"dangerous":  true,
					"precise":     true, // We know exactly which file will be modified
				},
			})

			// In-place editing might create backup files (conservative)
			if cmd.BackupExt != "" {
				operations = append(operations, SemanticOperation{
					OperationType: OpCreate,
					TargetPath:    file + cmd.BackupExt,
					Context:       "backup_file",
					Parameters: map[string]interface{}{
						"command":           cmd.CommandType,
						"over_approximated": true, // Conservative: backup file creation
					},
				})
			}
		}
	}

	// If script file is specified, add read operation for it
	if scriptFile, ok := cmd.Options["script_file"]; ok {
		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    scriptFile.(string),
			Context:       "script_file",
			Parameters: map[string]interface{}{
				"command": cmd.CommandType,
				"precise":  true, // We know exactly which script file
			},
		})
	}

	return operations, nil
}