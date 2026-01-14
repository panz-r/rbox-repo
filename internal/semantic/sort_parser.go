package semantic

import (
	"fmt"
	"strings"
)

// SortCommand represents a parsed sort command
type SortCommand struct {
	InputFiles      []string
	Options         map[string]interface{}
	KeySpec         string // -k option
	Reverse         bool   // -r option
	NumericSort     bool   // -n option
	HumanNumeric    bool   // -h option
	Unique          bool   // -u option
	Merge           bool   // -m option
	IgnoreCase      bool   // -f option
	IgnoreBlanks    bool   // -b option
	IgnoreLeading   bool   // -d option
	Stable          bool   // -s option
	OutputFile      string // -o option
	FieldSeparator  string // -t option
}

// SortParser parses sort commands
type SortParser struct{}

// ParseArguments implements CommandParser for sort commands
func (s *SortParser) ParseArguments(args []string) (interface{}, error) {
	// Sort can work with no arguments (reads from stdin)
	if len(args) == 0 {
		return &SortCommand{
			Options: make(map[string]interface{}),
		}, nil
	}

	cmd := &SortCommand{
		Options: make(map[string]interface{}),
	}

	i := 0
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-r":
			cmd.Reverse = true
			cmd.Options["reverse"] = true
		case "-n":
			cmd.NumericSort = true
			cmd.Options["numeric"] = true
		case "-h":
			cmd.HumanNumeric = true
			cmd.Options["human_numeric"] = true
		case "-u":
			cmd.Unique = true
			cmd.Options["unique"] = true
		case "-m":
			cmd.Merge = true
			cmd.Options["merge"] = true
		case "-f":
			cmd.IgnoreCase = true
			cmd.Options["ignore_case"] = true
		case "-b":
			cmd.IgnoreBlanks = true
			cmd.Options["ignore_blanks"] = true
		case "-d":
			cmd.IgnoreLeading = true
			cmd.Options["ignore_leading"] = true
		case "-s":
			cmd.Stable = true
			cmd.Options["stable"] = true
		case "-o":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing output file after -o option")
			}
			cmd.OutputFile = args[i+1]
			cmd.Options["output_file"] = args[i+1]
			i += 2
			continue
		case "-t":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing field separator after -t option")
			}
			cmd.FieldSeparator = args[i+1]
			cmd.Options["field_separator"] = args[i+1]
			i += 2
			continue
		case "-k":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing key specification after -k option")
			}
			cmd.KeySpec = args[i+1]
			cmd.Options["key_spec"] = args[i+1]
			i += 2
			continue
		default:
			// Handle combined options like -rn
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'r':
						cmd.Reverse = true
						cmd.Options["reverse"] = true
					case 'n':
						cmd.NumericSort = true
						cmd.Options["numeric"] = true
					case 'h':
						cmd.HumanNumeric = true
						cmd.Options["human_numeric"] = true
					case 'u':
						cmd.Unique = true
						cmd.Options["unique"] = true
					case 'm':
						cmd.Merge = true
						cmd.Options["merge"] = true
					case 'f':
						cmd.IgnoreCase = true
						cmd.Options["ignore_case"] = true
					case 'b':
						cmd.IgnoreBlanks = true
						cmd.Options["ignore_blanks"] = true
					case 'd':
						cmd.IgnoreLeading = true
						cmd.Options["ignore_leading"] = true
					case 's':
						cmd.Stable = true
						cmd.Options["stable"] = true
					}
				}
			}
		}
		i++
	}

	// Remaining arguments are input files
	if i < len(args) {
		cmd.InputFiles = args[i:]
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for sort commands
func (s *SortParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*SortCommand)
	if !ok {
		return nil, fmt.Errorf("invalid sort command type")
	}

	operations := make([]SemanticOperation, 0)

	// Add read operations for each input file
	for _, file := range cmd.InputFiles {
		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    file,
			Context:       "input_file",
			Parameters: map[string]interface{}{
				"command": "sort",
				"options": cmd.Options,
			},
		})
	}

	// If no input files, sort reads from stdin
	if len(cmd.InputFiles) == 0 {
		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    "/dev/stdin",
			Context:       "stdin",
			Parameters: map[string]interface{}{
				"command": "sort",
				"options": cmd.Options,
			},
		})
	}

	// If output file is specified, add write operation
	if cmd.OutputFile != "" {
		operations = append(operations, SemanticOperation{
			OperationType: OpWrite,
			TargetPath:    cmd.OutputFile,
			Context:       "output_file",
			Parameters: map[string]interface{}{
				"command": "sort",
			},
		})
	}

	return operations, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for sort commands
func (s *SortParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*SortCommand)
	if !ok {
		return nil, fmt.Errorf("invalid sort command type")
	}

	// Get basic semantic operations
	operations, err := s.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("sort", operations, []SemanticOperation{})

	return graph, nil
}