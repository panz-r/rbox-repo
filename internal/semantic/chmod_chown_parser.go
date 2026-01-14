package semantic

import (
	"fmt"
	"strings"
)

// ChmodChownCommand represents a parsed chmod or chown command
type ChmodChownCommand struct {
	CommandType string   // "chmod" or "chown"
	Targets     []string // Files/directories to modify
	Mode        string   // For chmod: permission mode
	Owner       string   // For chown: owner specification
	Options     map[string]interface{}
	Recursive   bool
	Verbose     bool
}

// ChmodChownParser parses chmod and chown commands
type ChmodChownParser struct{}

// ParseArguments implements CommandParser for chmod/chown commands
func (c *ChmodChownParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified for chmod/chown parser")
	}

	cmd := &ChmodChownCommand{
		CommandType: args[0], // "chmod" or "chown"
		Options:     make(map[string]interface{}),
	}

	i := 1
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "-R", "--recursive":
			cmd.Recursive = true
			cmd.Options["recursive"] = true
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
					case 'R':
						cmd.Recursive = true
						cmd.Options["recursive"] = true
					case 'v':
						cmd.Verbose = true
						cmd.Options["verbose"] = true
					}
				}
			}
		}
		i++
	}

	// Parse mode/owner and targets based on command type
	if i < len(args) {
		if cmd.CommandType == "chmod" {
			// chmod: first non-option is mode, rest are targets
			cmd.Mode = args[i]
			cmd.Options["mode"] = args[i]
			i++
			if i < len(args) {
				cmd.Targets = args[i:]
			} else {
				return nil, fmt.Errorf("missing targets for chmod command")
			}
		} else if cmd.CommandType == "chown" {
			// chown: first non-option is owner, rest are targets
			cmd.Owner = args[i]
			cmd.Options["owner"] = args[i]
			i++
			if i < len(args) {
				cmd.Targets = args[i:]
			} else {
				return nil, fmt.Errorf("missing targets for chown command")
			}
		}
	} else {
		return nil, fmt.Errorf("missing mode/owner and targets for %s command", cmd.CommandType)
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for chmod/chown commands
func (c *ChmodChownParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*ChmodChownCommand)
	if !ok {
		return nil, fmt.Errorf("invalid chmod/chown command type")
	}

	operations := make([]SemanticOperation, 0)
	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// chmod/chown commands modify file attributes - they are dangerous
	for _, target := range cmd.Targets {
		// First, we need to read the target to check if it exists
		builder.AddReadOperation(target, "target_read")
			
			builder = builder.WithParameter("command", cmd.CommandType)
			
			builder = builder.WithParameter("dangerous", true) // Even reading is part of dangerous operation

		// Read current attributes
		builder.AddReadOperation(target+".attrs", "current_attributes")
			
			builder = builder.WithParameter("command", cmd.CommandType)
			
			builder = builder.WithParameter("over_approximated", true)

		// The actual attribute modification operation
		if cmd.CommandType == "chmod" {
			builder.AddWriteOperation(target+".attrs", "permission_change")
				
			builder = builder.WithParameter("command", cmd.CommandType)
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("mode", cmd.Mode)
				
			builder = builder.WithParameter("attribute_change", true)
		} else { // chown
			builder.AddWriteOperation(target+".attrs", "ownership_change")
				
			builder = builder.WithParameter("command", cmd.CommandType)
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("owner", cmd.Owner)
				
			builder = builder.WithParameter("attribute_change", true)
		}

		// If recursive, we need to handle contents conservatively
		if cmd.Recursive {
			builder.AddWriteOperation(target+"/*", "recursive_attribute_change")
				
			builder = builder.WithParameter("command", cmd.CommandType)
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("over_approximated", true) // Conservative: unknown contents

			if cmd.CommandType == "chmod" {
				builder = builder.WithParameter("mode", cmd.Mode)
			} else {
				builder = builder.WithParameter("owner", cmd.Owner)
			}
		}

		// Read parent directory attributes (for context)
		parentDir := "."
		if lastSlash := strings.LastIndex(target, "/"); lastSlash != -1 {
			parentDir = target[:lastSlash]
		}
		builder.AddReadOperation(parentDir+".attrs", "parent_attributes")
			
			builder = builder.WithParameter("command", cmd.CommandType)
			
			builder = builder.WithParameter("over_approximated", true)
	}

	// Add operations for verbose mode
	if cmd.Verbose {
		builder.AddWriteOperation("/dev/stdout", "verbose_output")
			
			builder = builder.WithParameter("command", cmd.CommandType)
			
			builder = builder.WithParameter("verbose", true)
	}

	operations = builder.Build()

	return operations, nil
}