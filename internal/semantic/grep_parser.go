package semantic

import (
	"fmt"
	"strings"
)

// GrepCommand represents a parsed grep command
type GrepCommand struct {
	Pattern      string
	InputFiles   []string
	Options      map[string]interface{} // Can store various option values
	UseRecursive bool
	CaseInsensitive bool
	InvertMatch    bool
	ShowLineNumbers bool
	ShowFileNames   bool
}

// GrepParser parses grep commands
type GrepParser struct{}

// ParseArguments implements CommandParser for grep commands
func (g *GrepParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for grep")
	}

	cmd := &GrepCommand{
		Options: make(map[string]interface{}),
	}

	i := 0
	// Parse options first
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-r", "-R":
			cmd.UseRecursive = true
			cmd.Options["recursive"] = true
		case "-i":
			cmd.CaseInsensitive = true
			cmd.Options["case_insensitive"] = true
		case "-v":
			cmd.InvertMatch = true
			cmd.Options["invert_match"] = true
		case "-n":
			cmd.ShowLineNumbers = true
			cmd.Options["line_numbers"] = true
		case "-l":
			cmd.ShowFileNames = true
			cmd.Options["file_names"] = true
		case "-e":
			// Pattern follows -e option
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing pattern after -e option")
			}
			cmd.Pattern = args[i+1]
			cmd.Options["pattern"] = args[i+1]
			i += 2
			continue
		case "-f":
			// Pattern file follows -f option
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing file after -f option")
			}
			cmd.Options["pattern_file"] = args[i+1]
			i += 2
			continue
		default:
			// Handle single-letter options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'r', 'R':
						cmd.UseRecursive = true
						cmd.Options["recursive"] = true
					case 'i':
						cmd.CaseInsensitive = true
						cmd.Options["case_insensitive"] = true
					case 'v':
						cmd.InvertMatch = true
						cmd.Options["invert_match"] = true
					case 'n':
						cmd.ShowLineNumbers = true
						cmd.Options["line_numbers"] = true
					case 'l':
						cmd.ShowFileNames = true
						cmd.Options["file_names"] = true
					}
				}
			}
		}
		i++
	}

	// If no pattern specified with -e, the next argument is the pattern
	if cmd.Pattern == "" && i < len(args) {
		cmd.Pattern = args[i]
		i++
	}

	// Remaining arguments are input files
	if i < len(args) {
		cmd.InputFiles = args[i:]
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for grep commands
func (g *GrepParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*GrepCommand)
	if !ok {
		return nil, fmt.Errorf("invalid grep command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// Add read operations for each input file
	for _, file := range cmd.InputFiles {
		builder.AddReadOperation(file, "input_file")
		builder.WithCommandInfo("grep")
		builder.WithParameter("pattern", cmd.Pattern)
		builder.WithParameter("case_insensitive", cmd.CaseInsensitive)
		builder.WithParameter("invert_match", cmd.InvertMatch)
		builder.WithParameter("show_line_numbers", cmd.ShowLineNumbers)
		builder.WithParameter("show_file_names", cmd.ShowFileNames)
		builder.WithPrecise() // Precise since we know exactly what file is being read
	}

	// If pattern file is specified, add read operation for it
	if patternFile, ok := cmd.Options["pattern_file"]; ok {
		builder.AddReadOperation(patternFile.(string), "pattern_file")
		builder.WithCommandInfo("grep")
		builder.WithOverApproximated() // Pattern files can be complex
	}

	// If no input files, grep reads from stdin
	if len(cmd.InputFiles) == 0 {
		builder.AddReadOperation("/dev/stdin", "stdin")
		builder.WithCommandInfo("grep")
		builder.WithParameter("pattern", cmd.Pattern)
		builder.WithParameter("case_insensitive", cmd.CaseInsensitive)
		builder.WithParameter("invert_match", cmd.InvertMatch)
		builder.WithOverApproximated() // Less precise since we don't know stdin source
	}

	return builder.Build(), nil
}