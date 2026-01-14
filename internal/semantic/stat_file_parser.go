package semantic

import (
	"fmt"
	"strings"
)

// StatCommand represents a parsed stat command
type StatCommand struct {
	Files       []string
	Options     map[string]interface{}
	Format      string
	FileSystem  bool
	Terse       bool
	Dereference bool
}

// FileCommand represents a parsed file command
type FileCommand struct {
	Files       []string
	Options     map[string]interface{}
	Brief       bool
	MimeType    bool
	MimeEncoding bool
	NoDereference bool
}

// StatFileParser parses stat and file commands
type StatFileParser struct {
	commandType string // "stat" or "file"
}

// ParseArguments implements CommandParser for stat/file commands
func (s *StatFileParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided")
	}

	if s.commandType == "stat" {
		return s.parseStatCommand(args)
	} else if s.commandType == "file" {
		return s.parseFileCommand(args)
	}

	return nil, fmt.Errorf("unknown command type: %s", s.commandType)
}

func (s *StatFileParser) parseStatCommand(args []string) (*StatCommand, error) {
	cmd := &StatCommand{
		Options: make(map[string]interface{}),
	}

	i := 0
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]
		if opt == "--" {
			i++
			break
		}

		switch opt {
		case "-c", "--format":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Format = args[i+1]
			cmd.Options["format"] = args[i+1]
			i += 2

		case "-f", "--file-system":
			cmd.FileSystem = true
			cmd.Options["file_system"] = true
			i++

		case "-t", "--terse":
			cmd.Terse = true
			cmd.Options["terse"] = true
			i++

		case "-L", "--dereference":
			cmd.Dereference = true
			cmd.Options["dereference"] = true
			i++

		case "--no-dereference":
			cmd.Dereference = false
			cmd.Options["no_dereference"] = true
			i++

		default:
			// Handle combined short options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'c':
						// -c requires argument, handle separately
						if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
							cmd.Format = args[i+1]
							cmd.Options["format"] = args[i+1]
							i++
						}
					case 'f':
						cmd.FileSystem = true
					case 't':
						cmd.Terse = true
					case 'L':
						cmd.Dereference = true
					}
				}
				i++
			} else {
				return nil, fmt.Errorf("unknown stat option: %s", opt)
			}
		}
	}

	// Parse file arguments
	if i < len(args) {
		cmd.Files = args[i:]
	}

	return cmd, nil
}

func (s *StatFileParser) parseFileCommand(args []string) (*FileCommand, error) {
	cmd := &FileCommand{
		Options: make(map[string]interface{}),
	}

	i := 0
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]
		if opt == "--" {
			i++
			break
		}

		switch opt {
		case "-b", "--brief":
			cmd.Brief = true
			cmd.Options["brief"] = true
			i++

		case "-i", "--mime-type":
			cmd.MimeType = true
			cmd.Options["mime_type"] = true
			i++

		case "-I", "--mime-encoding":
			cmd.MimeEncoding = true
			cmd.Options["mime_encoding"] = true
			i++

		case "-h", "--no-dereference":
			cmd.NoDereference = true
			cmd.Options["no_dereference"] = true
			i++

		case "-L", "--dereference":
			cmd.NoDereference = false
			cmd.Options["dereference"] = true
			i++

		default:
			// Handle combined short options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'b':
						cmd.Brief = true
					case 'i':
						cmd.MimeType = true
					case 'I':
						cmd.MimeEncoding = true
					case 'h':
						cmd.NoDereference = true
					case 'L':
						cmd.NoDereference = false
					}
				}
				i++
			} else {
				return nil, fmt.Errorf("unknown file option: %s", opt)
			}
		}
	}

	// Parse file arguments
	if i < len(args) {
		cmd.Files = args[i:]
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for stat/file commands
func (s *StatFileParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	builder := ParserUtilsInstance.SemanticOperationBuilder()

	if statCmd, ok := parsed.(*StatCommand); ok {
		// Add read operations for each file
		for _, file := range statCmd.Files {
			builder.AddReadOperation(file, "file_metadata")
			builder.WithCommandInfo("stat")

			// Add stat-specific parameters
			if statCmd.Format != "" {
				builder.WithParameter("format", statCmd.Format)
			}
			if statCmd.FileSystem {
				builder.WithParameter("file_system", true)
			}
			if statCmd.Terse {
				builder.WithParameter("terse", true)
			}
			if statCmd.Dereference {
				builder.WithParameter("dereference", true)
			}

			// Stat operations are precise since we know exactly what files are being accessed
			builder.WithPrecise()
		}

		// If no files specified, stat might read from stdin or use defaults
		if len(statCmd.Files) == 0 {
			builder.AddReadOperation("/dev/stdin", "file_metadata")
			builder.WithCommandInfo("stat")
			builder.WithOverApproximated() // Less precise without explicit files
		}
	} else if fileCmd, ok := parsed.(*FileCommand); ok {
		// Add read operations for each file
		for _, file := range fileCmd.Files {
			builder.AddReadOperation(file, "file_type")
			builder.WithCommandInfo("file")

			// Add file-specific parameters
			if fileCmd.Brief {
				builder.WithParameter("brief", true)
			}
			if fileCmd.MimeType {
				builder.WithParameter("mime_type", true)
			}
			if fileCmd.MimeEncoding {
				builder.WithParameter("mime_encoding", true)
			}
			if fileCmd.NoDereference {
				builder.WithParameter("no_dereference", true)
			}

			// File operations are precise since we know exactly what files are being checked
			builder.WithPrecise()
		}

		// If no files specified, file might read from stdin
		if len(fileCmd.Files) == 0 {
			builder.AddReadOperation("/dev/stdin", "file_type")
			builder.WithCommandInfo("file")
			builder.WithOverApproximated() // Less precise without explicit files
		}
	}

	return builder.Build(), nil
}

// GetOperationGraph implements the enhanced CommandParser interface
func (p *StatFileParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	// This parser handles multiple command types
	var commandName string

	switch parsed.(type) {
	case *StatCommand:
		commandName = "stat"
	case *FileCommand:
		commandName = "file"
	default:
		return nil, fmt.Errorf("invalid command type for stat/file parser")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph(commandName, operations, []SemanticOperation{})

	return graph, nil
}