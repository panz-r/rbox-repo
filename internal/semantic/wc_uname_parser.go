package semantic

import (
	"fmt"
	"strings"
)

// WcCommand represents a parsed wc (word count) command
type WcCommand struct {
	InputFiles []string
	Options    map[string]bool
	CountLines bool
	CountWords bool
	CountChars bool
	CountBytes bool
	MaxLineLength bool
}

// UnameCommand represents a parsed uname command
type UnameCommand struct {
	Options map[string]bool
	AllInfo bool
	KernelName bool
	NodeName bool
	KernelRelease bool
	KernelVersion bool
	Machine bool
	Processor bool
	HardwarePlatform bool
	OperatingSystem bool
}

// WcUnameParser parses wc and uname commands
type WcUnameParser struct {
	commandType string // "wc" or "uname"
}

// ParseArguments implements CommandParser for wc/uname commands
func (w *WcUnameParser) ParseArguments(args []string) (interface{}, error) {
	if w.commandType == "wc" {
		if len(args) == 0 {
			return nil, fmt.Errorf("no arguments provided")
		}
		return w.parseWcCommand(args)
	} else if w.commandType == "uname" {
		// uname can be called with no arguments
		return w.parseUnameCommand(args)
	}

	return nil, fmt.Errorf("unknown command type: %s", w.commandType)
}

func (w *WcUnameParser) parseWcCommand(args []string) (*WcCommand, error) {
	cmd := &WcCommand{
		Options: make(map[string]bool),
		CountLines: true,    // Default
		CountWords: true,    // Default
		CountChars: true,    // Default
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
		case "-l", "--lines":
			cmd.CountLines = true
			cmd.CountWords = false
			cmd.CountChars = false
			cmd.CountBytes = false
			i++

		case "-w", "--words":
			cmd.CountWords = true
			cmd.CountLines = false
			cmd.CountChars = false
			cmd.CountBytes = false
			i++

		case "-m", "--chars":
			cmd.CountChars = true
			cmd.CountLines = false
			cmd.CountWords = false
			cmd.CountBytes = false
			i++

		case "-c", "--bytes":
			cmd.CountBytes = true
			cmd.CountLines = false
			cmd.CountWords = false
			cmd.CountChars = false
			i++

		case "-L", "--max-line-length":
			cmd.MaxLineLength = true
			i++

		default:
			// Handle combined short options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'l':
						cmd.CountLines = true
					case 'w':
						cmd.CountWords = true
					case 'm':
						cmd.CountChars = true
					case 'c':
						cmd.CountBytes = true
					case 'L':
						cmd.MaxLineLength = true
					}
				}
				i++
			} else {
				return nil, fmt.Errorf("unknown wc option: %s", opt)
			}
		}
	}

	// Parse input files
	if i < len(args) {
		cmd.InputFiles = args[i:]
	}

	return cmd, nil
}

func (w *WcUnameParser) parseUnameCommand(args []string) (*UnameCommand, error) {
	cmd := &UnameCommand{
		Options: make(map[string]bool),
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
		case "-a", "--all":
			cmd.AllInfo = true
			i++

		case "-s", "--kernel-name":
			cmd.KernelName = true
			i++

		case "-n", "--nodename":
			cmd.NodeName = true
			i++

		case "-r", "--kernel-release":
			cmd.KernelRelease = true
			i++

		case "-v", "--kernel-version":
			cmd.KernelVersion = true
			i++

		case "-m", "--machine":
			cmd.Machine = true
			i++

		case "-p", "--processor":
			cmd.Processor = true
			i++

		case "-i", "--hardware-platform":
			cmd.HardwarePlatform = true
			i++

		case "-o", "--operating-system":
			cmd.OperatingSystem = true
			i++

		default:
			return nil, fmt.Errorf("unknown uname option: %s", opt)
		}
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for wc/uname commands
func (w *WcUnameParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	builder := ParserUtilsInstance.SemanticOperationBuilder()

	if wcCmd, ok := parsed.(*WcCommand); ok {
		// Add read operations for each input file
		for _, file := range wcCmd.InputFiles {
			builder.AddReadOperation(file, "input_file")
			builder.WithCommandInfo("wc")

			// Add specific parameters based on options
			if wcCmd.CountLines {
				builder.WithParameter("count_lines", true)
			}
			if wcCmd.CountWords {
				builder.WithParameter("count_words", true)
			}
			if wcCmd.CountChars {
				builder.WithParameter("count_chars", true)
			}
			if wcCmd.CountBytes {
				builder.WithParameter("count_bytes", true)
			}
			if wcCmd.MaxLineLength {
				builder.WithParameter("max_line_length", true)
			}

			// Mark as precise since we know exactly what files are being read
			builder.WithPrecise()
		}

		// If no input files, wc reads from stdin
		if len(wcCmd.InputFiles) == 0 {
			builder.AddReadOperation("/dev/stdin", "stdin")
			builder.WithCommandInfo("wc")
			builder.WithOverApproximated() // Less precise since we don't know stdin source
		}
	} else if unameCmd, ok := parsed.(*UnameCommand); ok {
		// uname doesn't read files, it reads system information
		builder.AddReadOperation("/proc/sys/kernel/version", "system_info")
		builder.WithCommandInfo("uname")
		builder.WithOverApproximated() // System info reading is over-approximated

		// Add parameters for what info is being requested
		if unameCmd.AllInfo {
			builder.WithParameter("all_info", true)
		}
		if unameCmd.KernelName {
			builder.WithParameter("kernel_name", true)
		}
		if unameCmd.NodeName {
			builder.WithParameter("node_name", true)
		}
		// Add other specific fields as needed
	}

	return builder.Build(), nil
}