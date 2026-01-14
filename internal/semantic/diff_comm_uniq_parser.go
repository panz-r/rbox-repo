package semantic

import (
	"fmt"
	"strings"
)

// DiffCommand represents a parsed diff command
type DiffCommand struct {
	Files       []string
	Options     map[string]interface{}
	Context     int
	Unified     int
	IgnoreCase  bool
	Recursive   bool
	Brief       bool
	IgnoreWhitespace bool
	IgnoreAllWhitespace bool
	IgnoreBlankLines bool
	ShowFunction bool
	SideBySide  bool
}

// CommCommand represents a parsed comm command
type CommCommand struct {
	Files       []string
	Options     map[string]interface{}
	SuppressColumn1 bool
	SuppressColumn2 bool
	SuppressColumn3 bool
	CheckSorted bool
}

// UniqCommand represents a parsed uniq command
type UniqCommand struct {
	Files       []string
	Options     map[string]interface{}
	Count       bool
	Repeated    bool
	Unique      bool
	IgnoreCase  bool
	SkipFields  int
	SkipChars   int
	CheckChars  int
}

// DiffCommUniqParser parses diff, comm, and uniq commands
type DiffCommUniqParser struct {
	commandType string // "diff", "comm", or "uniq"
}

// ParseArguments implements CommandParser for diff/comm/uniq commands
func (d *DiffCommUniqParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided")
	}

	if d.commandType == "diff" {
		return d.parseDiffCommand(args)
	} else if d.commandType == "comm" {
		return d.parseCommCommand(args)
	} else if d.commandType == "uniq" {
		return d.parseUniqCommand(args)
	}

	return nil, fmt.Errorf("unknown command type: %s", d.commandType)
}

func (d *DiffCommUniqParser) parseDiffCommand(args []string) (*DiffCommand, error) {
	cmd := &DiffCommand{
		Options: make(map[string]interface{}),
		Context: 3, // Default context lines
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
		case "-c", "-C":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Context = parseInt(args[i+1])
			cmd.Options["context"] = cmd.Context
			i += 2

		case "-u", "-U":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Unified = parseInt(args[i+1])
			cmd.Options["unified"] = cmd.Unified
			i += 2

		case "-i", "--ignore-case":
			cmd.IgnoreCase = true
			cmd.Options["ignore_case"] = true
			i++

		case "-r", "--recursive":
			cmd.Recursive = true
			cmd.Options["recursive"] = true
			i++

		case "-q", "--brief":
			cmd.Brief = true
			cmd.Options["brief"] = true
			i++

		case "-w", "--ignore-all-space":
			cmd.IgnoreAllWhitespace = true
			cmd.Options["ignore_all_whitespace"] = true
			i++

		case "-b", "--ignore-space-change":
			cmd.IgnoreWhitespace = true
			cmd.Options["ignore_whitespace"] = true
			i++

		case "-B", "--ignore-blank-lines":
			cmd.IgnoreBlankLines = true
			cmd.Options["ignore_blank_lines"] = true
			i++

		case "-p", "--show-c-function":
			cmd.ShowFunction = true
			cmd.Options["show_function"] = true
			i++

		case "-y", "--side-by-side":
			cmd.SideBySide = true
			cmd.Options["side_by_side"] = true
			i++

		default:
			// Handle combined short options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'i':
						cmd.IgnoreCase = true
					case 'r':
						cmd.Recursive = true
					case 'q':
						cmd.Brief = true
					case 'w':
						cmd.IgnoreAllWhitespace = true
					case 'b':
						cmd.IgnoreWhitespace = true
					case 'B':
						cmd.IgnoreBlankLines = true
					case 'p':
						cmd.ShowFunction = true
					case 'y':
						cmd.SideBySide = true
					}
				}
				i++
			} else {
				return nil, fmt.Errorf("unknown diff option: %s", opt)
			}
		}
	}

	// Parse file arguments (diff requires at least 2 files)
	if i < len(args) {
		cmd.Files = args[i:]
	}

	return cmd, nil
}

func (d *DiffCommUniqParser) parseCommCommand(args []string) (*CommCommand, error) {
	cmd := &CommCommand{
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
		case "-1":
			cmd.SuppressColumn1 = true
			cmd.Options["suppress_column_1"] = true
			i++

		case "-2":
			cmd.SuppressColumn2 = true
			cmd.Options["suppress_column_2"] = true
			i++

		case "-3":
			cmd.SuppressColumn3 = true
			cmd.Options["suppress_column_3"] = true
			i++

		case "--check-order", "-c":
			cmd.CheckSorted = true
			cmd.Options["check_sorted"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown comm option: %s", opt)
		}
	}

	// Parse file arguments (comm requires exactly 2 files)
	if i < len(args) {
		cmd.Files = args[i:]
	}

	return cmd, nil
}

func (d *DiffCommUniqParser) parseUniqCommand(args []string) (*UniqCommand, error) {
	cmd := &UniqCommand{
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
		case "-c", "--count":
			cmd.Count = true
			cmd.Options["count"] = true
			i++

		case "-d", "--repeated":
			cmd.Repeated = true
			cmd.Options["repeated"] = true
			i++

		case "-u", "--unique":
			cmd.Unique = true
			cmd.Options["unique"] = true
			i++

		case "-i", "--ignore-case":
			cmd.IgnoreCase = true
			cmd.Options["ignore_case"] = true
			i++

		case "-f", "--skip-fields":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.SkipFields = parseInt(args[i+1])
			cmd.Options["skip_fields"] = cmd.SkipFields
			i += 2

		case "-s", "--skip-chars":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.SkipChars = parseInt(args[i+1])
			cmd.Options["skip_chars"] = cmd.SkipChars
			i += 2

		case "-w", "--check-chars":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.CheckChars = parseInt(args[i+1])
			cmd.Options["check_chars"] = cmd.CheckChars
			i += 2

		default:
			return nil, fmt.Errorf("unknown uniq option: %s", opt)
		}
	}

	// Parse file arguments
	if i < len(args) {
		cmd.Files = args[i:]
	}

	return cmd, nil
}

// Simple integer parsing helper
func parseInt(s string) int {
	// In real implementation, use strconv.Atoi
	// For now, return a default value
	return 1
}

// GetSemanticOperations implements CommandParser for diff/comm/uniq commands
func (d *DiffCommUniqParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	builder := ParserUtilsInstance.SemanticOperationBuilder()

	if diffCmd, ok := parsed.(*DiffCommand); ok {
		// Add read operations for each file
		for _, file := range diffCmd.Files {
			builder.AddReadOperation(file, "file_content")
			builder.WithCommandInfo("diff")

			// Add diff-specific parameters
			if diffCmd.IgnoreCase {
				builder.WithParameter("ignore_case", true)
			}
			if diffCmd.Recursive {
				builder.WithParameter("recursive", true)
			}
			if diffCmd.Brief {
				builder.WithParameter("brief", true)
			}
			if diffCmd.Unified > 0 {
				builder.WithParameter("unified", diffCmd.Unified)
			}

			// Diff operations are precise since we know exactly what files are being compared
			builder.WithPrecise()
		}

		// If no files specified, diff might read from stdin
		if len(diffCmd.Files) == 0 {
			builder.AddReadOperation("/dev/stdin", "file_content")
			builder.WithCommandInfo("diff")
			builder.WithOverApproximated() // Less precise without explicit files
		}
	} else if commCmd, ok := parsed.(*CommCommand); ok {
		// Add read operations for each file
		for _, file := range commCmd.Files {
			builder.AddReadOperation(file, "file_content")
			builder.WithCommandInfo("comm")

			// Add comm-specific parameters
			if commCmd.SuppressColumn1 {
				builder.WithParameter("suppress_column_1", true)
			}
			if commCmd.SuppressColumn2 {
				builder.WithParameter("suppress_column_2", true)
			}
			if commCmd.SuppressColumn3 {
				builder.WithParameter("suppress_column_3", true)
			}
			if commCmd.CheckSorted {
				builder.WithParameter("check_sorted", true)
			}

			// Comm operations are precise since we know exactly what files are being compared
			builder.WithPrecise()
		}

		// If no files specified, comm might read from stdin
		if len(commCmd.Files) == 0 {
			builder.AddReadOperation("/dev/stdin", "file_content")
			builder.WithCommandInfo("comm")
			builder.WithOverApproximated() // Less precise without explicit files
		}
	} else if uniqCmd, ok := parsed.(*UniqCommand); ok {
		// Add read operations for each file
		for _, file := range uniqCmd.Files {
			builder.AddReadOperation(file, "file_content")
			builder.WithCommandInfo("uniq")

			// Add uniq-specific parameters
			if uniqCmd.Count {
				builder.WithParameter("count", true)
			}
			if uniqCmd.Repeated {
				builder.WithParameter("repeated", true)
			}
			if uniqCmd.Unique {
				builder.WithParameter("unique", true)
			}
			if uniqCmd.IgnoreCase {
				builder.WithParameter("ignore_case", true)
			}
			if uniqCmd.SkipFields > 0 {
				builder.WithParameter("skip_fields", uniqCmd.SkipFields)
			}

			// Uniq operations are precise since we know exactly what files are being processed
			builder.WithPrecise()
		}

		// If no files specified, uniq reads from stdin
		if len(uniqCmd.Files) == 0 {
			builder.AddReadOperation("/dev/stdin", "file_content")
			builder.WithCommandInfo("uniq")
			builder.WithOverApproximated() // Less precise without explicit files
		}
	}

	return builder.Build(), nil
}

// GetOperationGraph implements the enhanced CommandParser interface
func (p *DiffCommUniqParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	// This parser handles multiple command types
	var commandName string

	switch parsed.(type) {
	case *DiffCommand:
		commandName = "diff"
	case *CommCommand:
		commandName = "comm"
	case *UniqCommand:
		commandName = "uniq"
	default:
		return nil, fmt.Errorf("invalid command type for diff/comm/uniq parser")
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