package semantic

import (
	"fmt"
	"strings"
)

// CpMvCommand represents a parsed cp or mv command
type CpMvCommand struct {
	CommandType string   // "cp" or "mv"
	Sources     []string // Source files/directories
	Destination string   // Destination file/directory
	Options     map[string]interface{}
	Recursive   bool
	Force       bool
	Interactive bool
	Preserve    bool
	Verbose     bool
}

// CpMvParser parses cp and mv commands
type CpMvParser struct{}

// ParseArguments implements CommandParser for cp/mv commands
func (c *CpMvParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified for cp/mv parser")
	}

	cmd := &CpMvCommand{
		CommandType: args[0], // "cp" or "mv"
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
		case "-p", "--preserve":
			cmd.Preserve = true
			cmd.Options["preserve"] = true
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
					case 'p':
						cmd.Preserve = true
						cmd.Options["preserve"] = true
					case 'v':
						cmd.Verbose = true
						cmd.Options["verbose"] = true
					}
				}
			}
		}
		i++
	}

	// Parse source and destination
	if i < len(args) {
		// Last argument is destination, rest are sources
		if i+1 < len(args) {
			cmd.Sources = args[i : len(args)-1]
			cmd.Destination = args[len(args)-1]
		} else {
			// Only one argument - could be missing destination
			return nil, fmt.Errorf("missing destination for %s command", cmd.CommandType)
		}
	} else {
		return nil, fmt.Errorf("missing source and destination for %s command", cmd.CommandType)
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for cp/mv commands
func (c *CpMvParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*CpMvCommand)
	if !ok {
		return nil, fmt.Errorf("invalid cp/mv command type")
	}

	operations := make([]SemanticOperation, 0)
	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// Add read operations for all source files/directories
	for _, source := range cmd.Sources {
		// Read the source
		builder.AddReadOperation(source, "source_read")
			
			builder = builder.WithParameter("command", cmd.CommandType)

		// If recursive, add recursive read operations (conservative)
		if cmd.Recursive {
			builder.AddReadOperation(source+"/*", "recursive_source_read")
				
			builder = builder.WithParameter("over_approximated", true)
				
			builder = builder.WithParameter("command", cmd.CommandType)
		}

		// Read metadata (conservative)
		builder.AddReadOperation(source+".meta", "source_metadata")
			
			builder = builder.WithParameter("over_approximated", true)
			
			builder = builder.WithParameter("command", cmd.CommandType)
	}

	// Add operations for destination
	if cmd.Destination != "" {
		// Check if destination is a directory (ends with /)
		isDirectory := strings.HasSuffix(cmd.Destination, "/")

		// For cp/mv, we always write to destination
		if isDirectory {
			// Destination is a directory - files will be created inside it
			for _, source := range cmd.Sources {
				// Extract filename from source path
				filename := source
				if lastSlash := strings.LastIndex(source, "/"); lastSlash != -1 {
					filename = source[lastSlash+1:]
				}

				destPath := cmd.Destination + filename

				if cmd.CommandType == "mv" {
					// Move: read then write (essentially rename)
					builder.AddWriteOperation(destPath, "move_destination")
						
			builder = builder.WithParameter("command", cmd.CommandType)
						
			builder = builder.WithParameter("dangerous", true)
						
			builder = builder.WithParameter("precise", true)
				} else {
					// Copy: create new file
					builder.AddCreateOperation(destPath, "copy_destination")
						
			builder = builder.WithParameter("command", cmd.CommandType)
						
			builder = builder.WithParameter("dangerous", true)
						
			builder = builder.WithParameter("precise", true)
				}
			}
		} else {
			// Destination is a file - depends on number of sources
			if len(cmd.Sources) == 1 {
				// Single source to single destination
				if cmd.CommandType == "mv" {
					builder.AddWriteOperation(cmd.Destination, "move_destination")
						
			builder = builder.WithParameter("command", cmd.CommandType)
						
			builder = builder.WithParameter("dangerous", true)
						
			builder = builder.WithParameter("precise", true)
				} else {
					builder.AddCreateOperation(cmd.Destination, "copy_destination")
						
			builder = builder.WithParameter("command", cmd.CommandType)
						
			builder = builder.WithParameter("dangerous", true)
						
			builder = builder.WithParameter("precise", true)
				}
			} else {
				// Multiple sources to directory destination
				// This is actually an error case, but we'll be conservative
				builder.AddCreateOperation(cmd.Destination+"/*", "multiple_copy_destination")
					
			builder = builder.WithParameter("command", cmd.CommandType)
					
			builder = builder.WithParameter("dangerous", true)
					
			builder = builder.WithParameter("over_approximated", true)
			}
		}

		// Read destination metadata if it exists (for mv, we might overwrite)
		builder.AddReadOperation(cmd.Destination+".meta", "destination_metadata")
			
			builder = builder.WithParameter("over_approximated", true)
			
			builder = builder.WithParameter("command", cmd.CommandType)

		// If force is set, we might overwrite existing files
		if cmd.Force {
			builder.AddWriteOperation(cmd.Destination, "force_overwrite")
				
			builder = builder.WithParameter("command", cmd.CommandType)
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("over_approximated", true)
		}
	}

	// Add operations based on specific options
	if cmd.Preserve {
		// Preserving attributes might involve additional metadata operations
		for _, source := range cmd.Sources {
			builder.AddReadOperation(source+".attrs", "preserve_attributes")
				
			builder = builder.WithParameter("command", cmd.CommandType)
				
			builder = builder.WithParameter("over_approximated", true)
		}
	}

	operations = builder.Build()

	return operations, nil
}