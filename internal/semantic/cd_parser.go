package semantic

import (
	"fmt"
	"strings"
)

// CdCommand represents a parsed cd command
type CdCommand struct {
	Directory string
	Options   map[string]bool
	Physical  bool
	Silent    bool
}

// CdParser parses cd commands
type CdParser struct{}

// ParseArguments implements CommandParser for cd commands
func (c *CdParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for cd")
	}

	cmd := &CdCommand{
		Options: make(map[string]bool),
	}

	// Parse options
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-P", "--physical":
			cmd.Physical = true
			cmd.Options["physical"] = true
		case "-L", "--logical":
			// Default behavior, no special handling needed
			cmd.Options["logical"] = true
		case "-@":
			cmd.Options["extended"] = true
		case "-e":
			cmd.Options["exists"] = true
		case "-s", "-q":
			cmd.Silent = true
			cmd.Options["silent"] = true
		default:
			// Unknown option, store it
			cmd.Options[opt] = true
		}
		i++
	}

	// Parse directory
	if i < len(args) {
		cmd.Directory = args[i]
	} else {
		// Default to home directory if no argument provided
		cmd.Directory = "~"
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for cd commands
func (c *CdParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*CdCommand)
	if !ok {
		return nil, fmt.Errorf("invalid cd command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// cd command reads directory information
	builder.AddReadOperation(cmd.Directory, "directory_info")
	builder.WithCommandInfo("cd")
	builder.WithParameter("physical", cmd.Physical)
	builder.WithParameter("silent", cmd.Silent)
	builder.WithPrecise()

	// If using physical mode, might need to resolve symlinks
	if cmd.Physical {
		builder.AddReadOperation(cmd.Directory+"/.*", "symlink_resolution")
		builder.WithCommandInfo("cd")
		builder.WithParameter("physical", true)
		builder.WithOverApproximated()
	}

	// cd doesn't write, but changes process state
	builder.AddReadOperation("/proc/self/cwd", "process_state_change")
	builder.WithCommandInfo("cd")
	builder.WithParameter("state_change", true)
	builder.WithOverApproximated()

	return builder.Build(), nil
}

// NewCdParser creates a new CdParser instance
func NewCdParser() *CdParser {
	return &CdParser{}
}