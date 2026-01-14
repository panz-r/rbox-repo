package semantic

import (
	"fmt"
	"strings"
)

// TarCommand represents a parsed tar command
type TarCommand struct {
	Options     map[string]interface{}
	Operation   string // "create", "extract", "list", etc.
	ArchiveFile string
	Files       []string
	Directory   string
	Compression string
	Verbose     bool
	Force       bool
	Preserve    bool
	Gzip        bool
	Bzip2       bool
	Xz          bool
}

// TarParser parses tar commands
type TarParser struct {
	utils *ParserUtils
}

// NewTarParser creates a new TarParser
func NewTarParser() *TarParser {
	return &TarParser{
		utils: ParserUtilsInstance,
	}
}

// ParseArguments implements CommandParser for tar commands
func (t *TarParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified for tar parser")
	}

	cmd := &TarCommand{
		Options: make(map[string]interface{}),
	}

	i := 0
	// First argument should be the operation (e.g., -c, -x, -t)
	if i < len(args) && strings.HasPrefix(args[i], "-") {
		op := args[i]

		// Handle combined operation options (e.g., -czvf)
		if len(op) > 2 {
			// Extract the operation character (first character after -)
			opChar := "-" + string(op[1])
			// Rest of the characters are additional options
			remainingOpts := op[2:]

			// Process the operation
			switch opChar {
			case "-c":
				cmd.Operation = "create"
				cmd.Options["operation"] = "create"
			case "-x":
				cmd.Operation = "extract"
				cmd.Options["operation"] = "extract"
			case "-t":
				cmd.Operation = "list"
				cmd.Options["operation"] = "list"
			case "-r":
				cmd.Operation = "append"
				cmd.Options["operation"] = "append"
			case "-u":
				cmd.Operation = "update"
				cmd.Options["operation"] = "update"
			case "-d":
				cmd.Operation = "diff"
				cmd.Options["operation"] = "diff"
			default:
				return nil, fmt.Errorf("unknown tar operation: %s", opChar)
			}

			// Process remaining options in the combined string
			for _, ch := range remainingOpts {
				switch ch {
				case 'z':
					cmd.Gzip = true
					cmd.Compression = "gzip"
					cmd.Options["compression"] = "gzip"
				case 'j':
					cmd.Bzip2 = true
					cmd.Compression = "bzip2"
					cmd.Options["compression"] = "bzip2"
				case 'J':
					cmd.Xz = true
					cmd.Compression = "xz"
					cmd.Options["compression"] = "xz"
				case 'v':
					cmd.Verbose = true
					cmd.Options["verbose"] = true
				case 'f':
					// -f requires an argument, which should be the next argument
					cmd.Options["file_flag"] = true
					// We'll handle the actual file argument in the main parsing loop
				}
			}

			i++
			// Continue with normal option parsing
			// If we had -f in combined options, the next argument should be the archive file
			if fileFlag, ok := cmd.Options["file_flag"]; ok && fileFlag.(bool) && i < len(args) && !strings.HasPrefix(args[i], "-") {
				cmd.ArchiveFile = args[i]
				cmd.Options["file"] = args[i]
				i++
				delete(cmd.Options, "file_flag")
			}
		} else {
			switch op {
			case "-c", "--create":
				cmd.Operation = "create"
				cmd.Options["operation"] = "create"
			case "-x", "--extract", "--get":
				cmd.Operation = "extract"
				cmd.Options["operation"] = "extract"
			case "-t", "--list":
				cmd.Operation = "list"
				cmd.Options["operation"] = "list"
			case "-r", "--append":
				cmd.Operation = "append"
				cmd.Options["operation"] = "append"
			case "-u", "--update":
				cmd.Operation = "update"
				cmd.Options["operation"] = "update"
			case "-d", "--diff", "--compare":
				cmd.Operation = "diff"
				cmd.Options["operation"] = "diff"
			default:
				return nil, fmt.Errorf("unknown tar operation: %s", op)
			}
		}
	} else {
		return nil, fmt.Errorf("missing tar operation")
	}

	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "-f", "--file":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing archive file after -f")
			}
			cmd.ArchiveFile = args[i+1]
			cmd.Options["file"] = args[i+1]
			i += 2
			continue
		case "-C", "--directory":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing directory after -C")
			}
			cmd.Directory = args[i+1]
			cmd.Options["directory"] = args[i+1]
			i += 2
			continue
		case "-v", "--verbose":
			cmd.Verbose = true
			cmd.Options["verbose"] = true
		case "-z", "--gzip", "--gunzip":
			cmd.Gzip = true
			cmd.Compression = "gzip"
			cmd.Options["compression"] = "gzip"
		case "-j", "--bzip2":
			cmd.Bzip2 = true
			cmd.Compression = "bzip2"
			cmd.Options["compression"] = "bzip2"
		case "-J", "--xz":
			cmd.Xz = true
			cmd.Compression = "xz"
			cmd.Options["compression"] = "xz"
		case "--force-local":
			cmd.Force = true
			cmd.Options["force_local"] = true
		case "-p", "--preserve-permissions", "--same-permissions":
			cmd.Preserve = true
			cmd.Options["preserve"] = true
		case "--":
			i++
			break
		default:
			// Handle combined options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'v':
						cmd.Verbose = true
						cmd.Options["verbose"] = true
					case 'z':
						cmd.Gzip = true
						cmd.Compression = "gzip"
						cmd.Options["compression"] = "gzip"
					case 'j':
						cmd.Bzip2 = true
						cmd.Compression = "bzip2"
						cmd.Options["compression"] = "bzip2"
					case 'J':
						cmd.Xz = true
						cmd.Compression = "xz"
						cmd.Options["compression"] = "xz"
					case 'f':
						// -f requires an argument, handle separately
						if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
							cmd.ArchiveFile = args[i+1]
							cmd.Options["file"] = args[i+1]
							i++
						}
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

	// Validate required fields based on operation
	if (cmd.Operation == "create" || cmd.Operation == "extract" || cmd.Operation == "append" || cmd.Operation == "update") && cmd.ArchiveFile == "" {
		return nil, fmt.Errorf("archive file is required for %s operation", cmd.Operation)
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for tar commands
func (t *TarParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*TarCommand)
	if !ok {
		return nil, fmt.Errorf("invalid tar command type")
	}

	builder := t.utils.SemanticOperationBuilder()
	operations := make([]SemanticOperation, 0)

	// All tar operations read the archive file
	if cmd.ArchiveFile != "" {
		builder.AddReadOperation(cmd.ArchiveFile, "archive_read")
			
			builder = builder.WithParameter("command", "tar")
			
			builder = builder.WithParameter("operation", cmd.Operation)

		// For extract operations, we also write files
		if cmd.Operation == "extract" || cmd.Operation == "update" {
			builder.AddWriteOperation(cmd.ArchiveFile, "archive_write")
				
			builder = builder.WithParameter("command", "tar")
				
			builder = builder.WithParameter("operation", cmd.Operation)
				
			builder = builder.WithParameter("dangerous", true)
		}

		// Read metadata (conservative)
		builder.AddReadOperation(cmd.ArchiveFile+".meta", "archive_metadata")
			
			builder = builder.WithParameter("command", "tar")
			
			builder = builder.WithParameter("over_approximated", true)
	}

	// Handle files based on operation
	switch cmd.Operation {
	case "create", "append", "update":
		// Read all source files
		for _, file := range cmd.Files {
			builder.AddReadOperation(file, "source_file_read")
				
			builder = builder.WithParameter("command", "tar")
				
			builder = builder.WithParameter("operation", cmd.Operation)

			// If preserving permissions, read metadata
			if cmd.Preserve {
				builder.AddReadOperation(file+".meta", "source_file_metadata")
					
			builder = builder.WithParameter("command", "tar")
					
			builder = builder.WithParameter("over_approximated", true)
			}
		}

		// Write to archive (dangerous for create/append/update)
		if cmd.ArchiveFile != "" {
			builder.AddWriteOperation(cmd.ArchiveFile, "archive_write")
				
			builder = builder.WithParameter("command", "tar")
				
			builder = builder.WithParameter("operation", cmd.Operation)
				
			builder = builder.WithParameter("dangerous", true)
		}

	case "extract":
		// Write extracted files (dangerous)
		for _, file := range cmd.Files {
			// If no files specified, we extract everything (conservative)
			if file == "." || file == "*" || file == "" {
				builder.AddWriteOperation(cmd.Directory+"/*", "extracted_files")
					
			builder = builder.WithParameter("command", "tar")
					
			builder = builder.WithParameter("operation", "extract")
					
			builder = builder.WithParameter("dangerous", true)
					
			builder = builder.WithParameter("over_approximated", true)
				break
			} else {
				destPath := file
				if cmd.Directory != "" {
					destPath = cmd.Directory + "/" + file
				}

				builder.AddWriteOperation(destPath, "extracted_file")
					
			builder = builder.WithParameter("command", "tar")
					
			builder = builder.WithParameter("operation", "extract")
					
			builder = builder.WithParameter("dangerous", true)
			}
		}

		// If no specific files, extract everything conservatively
		if len(cmd.Files) == 0 {
			builder.AddWriteOperation(cmd.Directory+"/*", "all_extracted_files")
				
			builder = builder.WithParameter("command", "tar")
				
			builder = builder.WithParameter("operation", "extract")
				
			builder = builder.WithParameter("dangerous", true)
				
			builder = builder.WithParameter("over_approximated", true)
		}

	case "list":
		// List operation only reads, doesn't write
		builder.AddReadOperation(cmd.ArchiveFile, "archive_list")
			
			builder = builder.WithParameter("command", "tar")
			
			builder = builder.WithParameter("operation", "list")

	case "diff":
		// Diff operation reads files and archive
		for _, file := range cmd.Files {
			builder.AddReadOperation(file, "diff_source_file")
				
			builder = builder.WithParameter("command", "tar")
				
			builder = builder.WithParameter("operation", "diff")
		}
	}

	// Handle directory operations
	if cmd.Directory != "" {
		builder.AddReadOperation(cmd.Directory, "target_directory")
			
			builder = builder.WithParameter("command", "tar")
			
			builder = builder.WithParameter("over_approximated", true)

		// For extract operations, we might create directories
		if cmd.Operation == "extract" {
			builder.AddCreateOperation(cmd.Directory+"/*", "created_directories")
				
			builder = builder.WithParameter("command", "tar")
				
			builder = builder.WithParameter("operation", "extract")
				
			builder = builder.WithParameter("over_approximated", true)
		}
	}

	// Handle compression operations
	if cmd.Compression != "" {
		builder.AddReadOperation(cmd.ArchiveFile, "compression_"+cmd.Compression)
			
			builder = builder.WithParameter("command", "tar")
			
			builder = builder.WithParameter("compression", cmd.Compression)

		if cmd.Operation == "create" || cmd.Operation == "append" || cmd.Operation == "update" {
			builder.AddWriteOperation(cmd.ArchiveFile, "compression_write_"+cmd.Compression)
				
			builder = builder.WithParameter("command", "tar")
				
			builder = builder.WithParameter("compression", cmd.Compression)
				
			builder = builder.WithParameter("dangerous", true)
		}
	}

	// Verbose operations might write to stdout
	if cmd.Verbose {
		builder.AddWriteOperation("/dev/stdout", "verbose_output")
			
			builder = builder.WithParameter("command", "tar")
			
			builder = builder.WithParameter("verbose", true)
	}

	operations = builder.Build()

	return operations, nil
}
// GetOperationGraph implements the enhanced CommandParser interface for tar commands
func (p *TarParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*TarCommand)
	if !ok {
		return nil, fmt.Errorf("invalid tar command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("tar", operations, []SemanticOperation{})

	return graph, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for tar commands
