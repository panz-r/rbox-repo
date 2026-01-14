package semantic

import (
	"fmt"
	"strings"
)

// HeadTailCommand represents a parsed head or tail command
type HeadTailCommand struct {
	CommandType string // "head" or "tail"
	InputFiles  []string
	Options     map[string]interface{}
	Lines       int
	Bytes       int
	Quiet       bool
	Verbose     bool
}

// HeadTailParser parses head and tail commands
type HeadTailParser struct {
	commandType string // "head" or "tail"
}

// ParseArguments implements CommandParser for head/tail commands
func (h *HeadTailParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided")
	}

	cmd := &HeadTailCommand{
		CommandType: h.commandType,
		Options: make(map[string]interface{}),
		Lines:   10, // Default for head
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
		case "-n", "--lines":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			// Parse the line count (could be +N or -N or N)
			linesStr := args[i+1]
			if strings.HasPrefix(linesStr, "+") || strings.HasPrefix(linesStr, "-") {
				cmd.Options["lines_offset"] = linesStr
			} else {
				// Simple parsing - in real implementation use strconv.Atoi
				cmd.Lines = 1 // Default, proper parsing needed
			}
			i += 2

		case "-c", "--bytes":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			bytesStr := args[i+1]
			if strings.HasPrefix(bytesStr, "+") || strings.HasPrefix(bytesStr, "-") {
				cmd.Options["bytes_offset"] = bytesStr
			} else {
				// Simple parsing - in real implementation use strconv.Atoi
				cmd.Bytes = 1 // Default, proper parsing needed
			}
			i += 2

		case "-q", "--quiet", "--silent":
			cmd.Quiet = true
			i++

		case "-v", "--verbose":
			cmd.Verbose = true
			i++

		default:
			// Handle combined short options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'n':
						// -n requires argument, handle separately
						if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
							cmd.Lines = 1 // Default parsing
							i++
						}
					case 'c':
						// -c requires argument, handle separately
						if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
							cmd.Bytes = 1 // Default parsing
							i++
						}
					case 'q':
						cmd.Quiet = true
					case 'v':
						cmd.Verbose = true
					}
				}
				i++
			} else {
				return nil, fmt.Errorf("unknown option: %s", opt)
			}
		}
	}

	// Parse input files
	if i < len(args) {
		cmd.InputFiles = args[i:]
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for head/tail commands
func (h *HeadTailParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*HeadTailCommand)
	if !ok {
		return nil, fmt.Errorf("invalid head/tail command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// Add read operations for each input file
	for _, file := range cmd.InputFiles {
		builder.AddReadOperation(file, "input_file")
		builder.WithCommandInfo("head_tail")
		builder.WithParameter("command_type", cmd.CommandType)

		// Add specific parameters based on options
		if cmd.Lines > 0 {
			builder.WithParameter("lines", cmd.Lines)
		}
		if cmd.Bytes > 0 {
			builder.WithParameter("bytes", cmd.Bytes)
		}
		if cmd.Quiet {
			builder.WithParameter("quiet", true)
		}
		if cmd.Verbose {
			builder.WithParameter("verbose", true)
		}

		// Mark as precise since we know exactly what files are being read
		builder.WithPrecise()
	}

	// If no input files, head/tail reads from stdin
	if len(cmd.InputFiles) == 0 {
		builder.AddReadOperation("/dev/stdin", "stdin")
		builder.WithCommandInfo("head_tail")
		builder.WithParameter("command_type", cmd.CommandType)
		builder.WithOverApproximated() // Less precise since we don't know stdin source
	}

	return builder.Build(), nil
}