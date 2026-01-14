package semantic

import (
	"fmt"
	"strings"
)

// GzipCommand represents a parsed gzip command
type GzipCommand struct {
	Options     map[string]interface{}
	Operation   string // "compress" or "decompress"
	Files       []string
	OutputFile  string
	Force       bool
	Keep        bool
	Recursive   bool
	Verbose     bool
	Fast        bool
	Best        bool
	Level       int
}

// GzipParser parses gzip commands
type GzipParser struct {
	utils *ParserUtils
}

// NewGzipParser creates a new GzipParser
func NewGzipParser() *GzipParser {
	return &GzipParser{
		utils: ParserUtilsInstance,
	}
}

// ParseArguments implements CommandParser for gzip commands
func (g *GzipParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified for gzip parser")
	}

	cmd := &GzipCommand{
		Options: make(map[string]interface{}),
		Operation: "compress", // Default operation
	}

	i := 0
	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "-d", "--decompress", "--uncompress":
			cmd.Operation = "decompress"
			cmd.Options["operation"] = "decompress"
		case "-c", "--stdout", "--to-stdout":
			cmd.Options["stdout"] = true
		case "-f", "--force":
			cmd.Force = true
			cmd.Options["force"] = true
		case "-k", "--keep":
			cmd.Keep = true
			cmd.Options["keep"] = true
		case "-r", "--recursive":
			cmd.Recursive = true
			cmd.Options["recursive"] = true
		case "-v", "--verbose":
			cmd.Verbose = true
			cmd.Options["verbose"] = true
		case "--fast", "-1":
			cmd.Fast = true
			cmd.Level = 1
			cmd.Options["level"] = 1
		case "--best", "-9":
			cmd.Best = true
			cmd.Level = 9
			cmd.Options["level"] = 9
		case "-l", "--list":
			cmd.Operation = "list"
			cmd.Options["operation"] = "list"
		case "-t", "--test":
			cmd.Operation = "test"
			cmd.Options["operation"] = "test"
		case "-o", "--output":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing output file after -o")
			}
			cmd.OutputFile = args[i+1]
			cmd.Options["output"] = args[i+1]
			i += 2
			continue
		case "--":
			i++
			break
		default:
			// Handle level options (-2 through -9)
			if len(opt) == 2 && opt[0] == '-' && opt[1] >= '2' && opt[1] <= '9' {
				level := int(opt[1] - '0')
				cmd.Level = level
				cmd.Options["level"] = level
			} else if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				// Handle combined options
				for _, ch := range opt[1:] {
					switch ch {
					case 'd':
						cmd.Operation = "decompress"
						cmd.Options["operation"] = "decompress"
					case 'c':
						cmd.Options["stdout"] = true
					case 'f':
						cmd.Force = true
						cmd.Options["force"] = true
					case 'k':
						cmd.Keep = true
						cmd.Options["keep"] = true
					case 'r':
						cmd.Recursive = true
						cmd.Options["recursive"] = true
					case 'v':
						cmd.Verbose = true
						cmd.Options["verbose"] = true
					case '1':
						cmd.Fast = true
						cmd.Level = 1
						cmd.Options["level"] = 1
					case '9':
						cmd.Best = true
						cmd.Level = 9
						cmd.Options["level"] = 9
					}
				}
			}
		}
		i++
	}

	// Parse remaining arguments (files)
	if i < len(args) {
		cmd.Files = args[i:]
	}

	// Validate based on operation
	if (cmd.Operation == "compress" || cmd.Operation == "decompress") && len(cmd.Files) == 0 {
		return nil, fmt.Errorf("no input files specified for %s operation", cmd.Operation)
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for gzip commands
func (g *GzipParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*GzipCommand)
	if !ok {
		return nil, fmt.Errorf("invalid gzip command type")
	}

	builder := g.utils.SemanticOperationBuilder()
	operations := make([]SemanticOperation, 0)

	switch cmd.Operation {
	case "compress":
		// Read all input files
		for _, file := range cmd.Files {
			builder.AddReadOperation(file, "compress_input")
				
			builder = builder.WithParameter("command", "gzip")
				
			builder = builder.WithParameter("operation", "compress")

			// Read metadata (conservative)
			builder.AddReadOperation(file+".meta", "input_metadata")
				
			builder = builder.WithParameter("command", "gzip")
				
			builder = builder.WithParameter("over_approximated", true)

			// Write compressed file
			outputFile := file + ".gz"
			if cmd.OutputFile != "" {
				outputFile = cmd.OutputFile
			}

			builder.AddWriteOperation(outputFile, "compressed_output")
				
			builder = builder.WithParameter("command", "gzip")
				
			builder = builder.WithParameter("operation", "compress")
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("compression_level", cmd.Level)

			// If keep is set, original file is preserved
			if !cmd.Keep {
				builder.AddWriteOperation(file, "original_file_modification")
					
			builder = builder.WithParameter("command", "gzip")
					
			builder = builder.WithParameter("operation", "compress")
					
			builder = builder.WithParameter("dangerous", true)
			}
		}

	case "decompress":
		// Read compressed files
		for _, file := range cmd.Files {
			builder.AddReadOperation(file, "compressed_input")
				
			builder = builder.WithParameter("command", "gzip")
				
			builder = builder.WithParameter("operation", "decompress")

			// Determine output file name
			outputFile := strings.TrimSuffix(file, ".gz")
			if outputFile == file {
				outputFile = strings.TrimSuffix(file, ".z")
			}
			if cmd.OutputFile != "" {
				outputFile = cmd.OutputFile
			}

			// Write decompressed file (dangerous)
			builder.AddWriteOperation(outputFile, "decompressed_output")
				
			builder = builder.WithParameter("command", "gzip")
				
			builder = builder.WithParameter("operation", "decompress")
				
			builder = builder.WithParameter("dangerous", true)

			// If keep is not set, original compressed file might be modified
			if !cmd.Keep {
				builder.AddWriteOperation(file, "original_compressed_modification")
					
			builder = builder.WithParameter("command", "gzip")
					
			builder = builder.WithParameter("operation", "decompress")
					
			builder = builder.WithParameter("dangerous", true)
			}
		}

	case "list":
		// List operation only reads, doesn't write
		for _, file := range cmd.Files {
			builder.AddReadOperation(file, "list_compressed")
				
			builder = builder.WithParameter("command", "gzip")
				
			builder = builder.WithParameter("operation", "list")
		}

	case "test":
		// Test operation only reads, doesn't write
		for _, file := range cmd.Files {
			builder.AddReadOperation(file, "test_compressed")
				
			builder = builder.WithParameter("command", "gzip")
				
			builder = builder.WithParameter("operation", "test")
		}
	}

	// Handle stdout operations
	if cmd.Options["stdout"] == true {
		builder.AddWriteOperation("/dev/stdout", "stdout_output")
			
			builder = builder.WithParameter("command", "gzip")
			
			builder = builder.WithParameter("operation", cmd.Operation)
	}

	// Handle recursive operations
	if cmd.Recursive {
		for _, file := range cmd.Files {
			builder.AddReadOperation(file+"/*", "recursive_input")
				
			builder = builder.WithParameter("command", "gzip")
				
			builder = builder.WithParameter("operation", cmd.Operation)
				
			builder = builder.WithParameter("over_approximated", true)

			if cmd.Operation == "compress" || cmd.Operation == "decompress" {
				builder.AddWriteOperation(file+"/*", "recursive_output")
					
			builder = builder.WithParameter("command", "gzip")
					
			builder = builder.WithParameter("operation", cmd.Operation)
					
			builder = builder.WithParameter("dangerous", true)
					
			builder = builder.WithParameter("over_approximated", true)
			}
		}
	}

	// Handle verbose operations
	if cmd.Verbose {
		builder.AddWriteOperation("/dev/stdout", "verbose_output")
			
			builder = builder.WithParameter("command", "gzip")
			
			builder = builder.WithParameter("verbose", true)
	}

	operations = builder.Build()

	return operations, nil
}
// GetOperationGraph implements the enhanced CommandParser interface for gzip commands
func (p *GzipParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*GzipCommand)
	if !ok {
		return nil, fmt.Errorf("invalid gzip command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("gzip", operations, []SemanticOperation{})

	return graph, nil
}

