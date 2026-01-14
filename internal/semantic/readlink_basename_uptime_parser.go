package semantic

import (
	"fmt"
	"strings"
)

// ReadlinkCommand represents a parsed readlink command
type ReadlinkCommand struct {
	Files       []string
	Options     map[string]interface{}
	Follow      bool
	NoNewline   bool
	Canonicalize bool
	Verbose     bool
}

// BasenameCommand represents a parsed basename command
type BasenameCommand struct {
	Paths       []string
	Options     map[string]interface{}
	Suffix      string
	Multiple    bool
	Zero        bool
}

// DirnameCommand represents a parsed dirname command
type DirnameCommand struct {
	Paths       []string
	Options     map[string]interface{}
	Zero        bool
}

// UptimeCommand represents a parsed uptime command
type UptimeCommand struct {
	Options     map[string]interface{}
	Pretty      bool
	Since       bool
}

// FreeCommand represents a parsed free command
type FreeCommand struct {
	Options     map[string]interface{}
	Bytes       bool
	KiloBytes   bool
	MegaBytes   bool
	GigaBytes   bool
	Human       bool
	Total       bool
	Low         bool
	Wide        bool
	Count       int
}

// ReadlinkBasenameUptimeParser parses readlink, basename, dirname, uptime, and free commands
type ReadlinkBasenameUptimeParser struct {
	commandType string // "readlink", "basename", "dirname", "uptime", or "free"
}

// ParseArguments implements CommandParser for readlink/basename/dirname/uptime/free commands
func (r *ReadlinkBasenameUptimeParser) ParseArguments(args []string) (interface{}, error) {
	if r.commandType == "readlink" {
		return r.parseReadlinkCommand(args)
	} else if r.commandType == "basename" {
		return r.parseBasenameCommand(args)
	} else if r.commandType == "dirname" {
		return r.parseDirnameCommand(args)
	} else if r.commandType == "uptime" {
		return r.parseUptimeCommand(args)
	} else if r.commandType == "free" {
		return r.parseFreeCommand(args)
	}

	return nil, fmt.Errorf("unknown command type: %s", r.commandType)
}

func (r *ReadlinkBasenameUptimeParser) parseReadlinkCommand(args []string) (*ReadlinkCommand, error) {
	cmd := &ReadlinkCommand{
		Options: make(map[string]interface{}),
		Follow: true, // Default behavior
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
		case "-f", "--canonicalize":
			cmd.Canonicalize = true
			cmd.Options["canonicalize"] = true
			i++

		case "-e", "--canonicalize-existing":
			cmd.Canonicalize = true
			cmd.Options["canonicalize_existing"] = true
			i++

		case "-m", "--canonicalize-missing":
			cmd.Canonicalize = true
			cmd.Options["canonicalize_missing"] = true
			i++

		case "-n", "--no-newline":
			cmd.NoNewline = true
			cmd.Options["no_newline"] = true
			i++

		case "-q", "--quiet":
			cmd.Options["quiet"] = true
			i++

		case "-v", "--verbose":
			cmd.Verbose = true
			cmd.Options["verbose"] = true
			i++

		case "--help":
			cmd.Options["help"] = true
			i++

		case "--version":
			cmd.Options["version"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown readlink option: %s", opt)
		}
	}

	// Parse file arguments
	if i < len(args) {
		cmd.Files = args[i:]
	}

	return cmd, nil
}

func (r *ReadlinkBasenameUptimeParser) parseBasenameCommand(args []string) (*BasenameCommand, error) {
	cmd := &BasenameCommand{
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
		case "-s", "--suffix":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Suffix = args[i+1]
			cmd.Options["suffix"] = args[i+1]
			i += 2

		case "-a", "--multiple":
			cmd.Multiple = true
			cmd.Options["multiple"] = true
			i++

		case "-z", "--zero":
			cmd.Zero = true
			cmd.Options["zero"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown basename option: %s", opt)
		}
	}

	// Parse path arguments
	if i < len(args) {
		cmd.Paths = args[i:]
	}

	return cmd, nil
}

func (r *ReadlinkBasenameUptimeParser) parseDirnameCommand(args []string) (*DirnameCommand, error) {
	cmd := &DirnameCommand{
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
		case "-z", "--zero":
			cmd.Zero = true
			cmd.Options["zero"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown dirname option: %s", opt)
		}
	}

	// Parse path arguments
	if i < len(args) {
		cmd.Paths = args[i:]
	}

	return cmd, nil
}

func (r *ReadlinkBasenameUptimeParser) parseUptimeCommand(args []string) (*UptimeCommand, error) {
	cmd := &UptimeCommand{
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
		case "-p", "--pretty":
			cmd.Pretty = true
			cmd.Options["pretty"] = true
			i++

		case "-s", "--since":
			cmd.Since = true
			cmd.Options["since"] = true
			i++

		case "--help":
			cmd.Options["help"] = true
			i++

		case "--version":
			cmd.Options["version"] = true
			i++

		default:
			return nil, fmt.Errorf("unknown uptime option: %s", opt)
		}
	}

	// uptime doesn't take file arguments
	return cmd, nil
}

func (r *ReadlinkBasenameUptimeParser) parseFreeCommand(args []string) (*FreeCommand, error) {
	cmd := &FreeCommand{
		Options: make(map[string]interface{}),
		Count: 1, // Default count
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
		case "-b", "--bytes":
			cmd.Bytes = true
			cmd.Options["bytes"] = true
			i++

		case "-k", "--kilo":
			cmd.KiloBytes = true
			cmd.Options["kilo"] = true
			i++

		case "-m", "--mega":
			cmd.MegaBytes = true
			cmd.Options["mega"] = true
			i++

		case "-g", "--giga":
			cmd.GigaBytes = true
			cmd.Options["giga"] = true
			i++

		case "-h", "--human":
			cmd.Human = true
			cmd.Options["human"] = true
			i++

		case "-t", "--total":
			cmd.Total = true
			cmd.Options["total"] = true
			i++

		case "-l", "--low":
			cmd.Low = true
			cmd.Options["low"] = true
			i++

		case "-w", "--wide":
			cmd.Wide = true
			cmd.Options["wide"] = true
			i++

		case "-c", "--count":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument after %s", opt)
			}
			cmd.Count = parseInt(args[i+1])
			cmd.Options["count"] = cmd.Count
			i += 2

		default:
			return nil, fmt.Errorf("unknown free option: %s", opt)
		}
	}

	// free doesn't take file arguments
	return cmd, nil
}

// GetSemanticOperations implements CommandParser for readlink/basename/dirname/uptime/free commands
func (r *ReadlinkBasenameUptimeParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	builder := ParserUtilsInstance.SemanticOperationBuilder()

	if readlinkCmd, ok := parsed.(*ReadlinkCommand); ok {
		// Add read operations for each file
		for _, file := range readlinkCmd.Files {
			builder.AddReadOperation(file, "symbolic_link")
			builder.WithCommandInfo("readlink")

			// Add readlink-specific parameters
			if readlinkCmd.Follow {
				builder.WithParameter("follow", true)
			}
			if readlinkCmd.Canonicalize {
				builder.WithParameter("canonicalize", true)
			}
			if readlinkCmd.NoNewline {
				builder.WithParameter("no_newline", true)
			}
			if readlinkCmd.Verbose {
				builder.WithParameter("verbose", true)
			}

			// Readlink operations are precise since we know exactly what files are being read
			builder.WithPrecise()
		}

		// If no files specified, readlink might read from stdin
		if len(readlinkCmd.Files) == 0 {
			builder.AddReadOperation("/dev/stdin", "symbolic_link")
			builder.WithCommandInfo("readlink")
			builder.WithOverApproximated() // Less precise without explicit files
		}
	} else if basenameCmd, ok := parsed.(*BasenameCommand); ok {
		// Add read operations for each path
		for _, path := range basenameCmd.Paths {
			builder.AddReadOperation(path, "pathname")
			builder.WithCommandInfo("basename")

			// Add basename-specific parameters
			if basenameCmd.Suffix != "" {
				builder.WithParameter("suffix", basenameCmd.Suffix)
			}
			if basenameCmd.Multiple {
				builder.WithParameter("multiple", true)
			}
			if basenameCmd.Zero {
				builder.WithParameter("zero", true)
			}

			// Basename operations are precise since we know exactly what paths are being processed
			builder.WithPrecise()
		}

		// If no paths specified, basename might read from stdin
		if len(basenameCmd.Paths) == 0 {
			builder.AddReadOperation("/dev/stdin", "pathname")
			builder.WithCommandInfo("basename")
			builder.WithOverApproximated() // Less precise without explicit paths
		}
	} else if dirnameCmd, ok := parsed.(*DirnameCommand); ok {
		// Add read operations for each path
		for _, path := range dirnameCmd.Paths {
			builder.AddReadOperation(path, "pathname")
			builder.WithCommandInfo("dirname")

			// Add dirname-specific parameters
			if dirnameCmd.Zero {
				builder.WithParameter("zero", true)
			}

			// Dirname operations are precise since we know exactly what paths are being processed
			builder.WithPrecise()
		}

		// If no paths specified, dirname might read from stdin
		if len(dirnameCmd.Paths) == 0 {
			builder.AddReadOperation("/dev/stdin", "pathname")
			builder.WithCommandInfo("dirname")
			builder.WithOverApproximated() // Less precise without explicit paths
		}
	} else if uptimeCmd, ok := parsed.(*UptimeCommand); ok {
		// Uptime reads system information
		builder.AddReadOperation("/proc/uptime", "system_info")
		builder.WithCommandInfo("uptime")

		// Add uptime-specific parameters
		if uptimeCmd.Pretty {
			builder.WithParameter("pretty", true)
		}
		if uptimeCmd.Since {
			builder.WithParameter("since", true)
		}

		builder.WithOverApproximated() // System info reading is over-approximated
		builder.WithSafe() // Uptime is generally safe
	} else if freeCmd, ok := parsed.(*FreeCommand); ok {
		// Free reads system memory information
		builder.AddReadOperation("/proc/meminfo", "system_info")
		builder.WithCommandInfo("free")

		// Add free-specific parameters
		if freeCmd.Bytes {
			builder.WithParameter("bytes", true)
		}
		if freeCmd.KiloBytes {
			builder.WithParameter("kilo", true)
		}
		if freeCmd.MegaBytes {
			builder.WithParameter("mega", true)
		}
		if freeCmd.GigaBytes {
			builder.WithParameter("giga", true)
		}
		if freeCmd.Human {
			builder.WithParameter("human", true)
		}
		if freeCmd.Total {
			builder.WithParameter("total", true)
		}
		if freeCmd.Low {
			builder.WithParameter("low", true)
		}
		if freeCmd.Wide {
			builder.WithParameter("wide", true)
		}
		if freeCmd.Count > 1 {
			builder.WithParameter("count", freeCmd.Count)
		}

		builder.WithOverApproximated() // System info reading is over-approximated
		builder.WithSafe() // Free is generally safe
	}

	return builder.Build(), nil
}