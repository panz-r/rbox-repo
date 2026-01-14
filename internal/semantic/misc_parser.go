package semantic

import (
	"fmt"
	"strings"
)

// PwdCommandMisc represents a parsed pwd command
type PwdCommandMisc struct {
	Options map[string]bool
	Physical bool
	Logical  bool
}

// PwdParser parses pwd commands
type PwdParser struct{}

// ParseArguments implements CommandParser for pwd commands
func (p *PwdParser) ParseArguments(args []string) (interface{}, error) {
	cmd := &PwdCommandMisc{
		Options: make(map[string]bool),
		Logical: true, // Default behavior
	}

	// Parse options
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			switch arg {
			case "-P", "--physical":
				cmd.Physical = true
				cmd.Logical = false
				cmd.Options["physical"] = true
			case "-L", "--logical":
				cmd.Logical = true
				cmd.Physical = false
				cmd.Options["logical"] = true
			case "--help", "--version":
				cmd.Options[arg] = true
			default:
				cmd.Options[arg] = true
			}
		}
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for pwd commands
func (p *PwdParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*PwdCommandMisc)
	if !ok {
		return nil, fmt.Errorf("invalid pwd command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// pwd reads current working directory
	builder.AddReadOperation("/proc/self/cwd", "current_working_directory")
	builder.WithCommandInfo("pwd")
	builder.WithParameter("physical", cmd.Physical)
	builder.WithParameter("logical", cmd.Logical)
	builder.WithPrecise()

	// If physical mode, might need to resolve symlinks
	if cmd.Physical {
		builder.AddReadOperation("/proc/self/cwd", "symlink_resolution")
		builder.WithCommandInfo("pwd")
		builder.WithParameter("physical", true)
		builder.WithOverApproximated()
	}

	return builder.Build(), nil
}

// SleepCommandMisc represents a parsed sleep command
type SleepCommandMisc struct {
	Duration string
	Options  map[string]interface{}
}

// SleepParser parses sleep commands
type SleepParser struct{}

// ParseArguments implements CommandParser for sleep commands
func (s *SleepParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for sleep")
	}

	cmd := &SleepCommandMisc{
		Options: make(map[string]interface{}),
		Duration: args[0],
	}

	// Parse options (sleep doesn't have many standard options)
	for i, arg := range args {
		if strings.HasPrefix(arg, "-") {
			cmd.Options[arg] = true
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				cmd.Options[arg] = args[i+1]
			}
		}
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for sleep commands
func (s *SleepParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*SleepCommandMisc)
	if !ok {
		return nil, fmt.Errorf("invalid sleep command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// sleep doesn't perform file operations, but changes process state
	builder.AddReadOperation("/proc/self/status", "process_state")
	builder.WithCommandInfo("sleep")
	builder.WithParameter("duration", cmd.Duration)
	builder.WithParameter("state_change", true)
	builder.WithOverApproximated()

	return builder.Build(), nil
}

// TimeoutCommand represents a parsed timeout command
type TimeoutCommand struct {
	Duration   string
	Command    string
	Args       []string
	Options    map[string]bool
	KillAfter  bool
	Signal     string
}

// TimeoutParser parses timeout commands
type TimeoutParser struct{}

// ParseArguments implements CommandParser for timeout commands
func (t *TimeoutParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("timeout requires duration and command")
	}

	cmd := &TimeoutCommand{
		Options: make(map[string]bool),
		Duration: args[0],
	}

	// Parse options
	i := 1
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-k", "--kill-after":
			cmd.KillAfter = true
			cmd.Options["kill_after"] = true
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				cmd.Signal = args[i+1]
				i += 2
				continue
			}
		case "-s", "--signal":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				cmd.Signal = args[i+1]
				i += 2
				continue
			}
		default:
			cmd.Options[opt] = true
		}
		i++
	}

	// Remaining arguments are the command to execute
	if i < len(args) {
		cmd.Command = args[i]
		if i+1 < len(args) {
			cmd.Args = args[i+1:]
		}
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for timeout commands
func (t *TimeoutParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*TimeoutCommand)
	if !ok {
		return nil, fmt.Errorf("invalid timeout command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// timeout monitors process execution
	builder.AddReadOperation("/proc/self/status", "process_monitoring")
	builder.WithCommandInfo("timeout")
	builder.WithParameter("duration", cmd.Duration)
	builder.WithParameter("command", cmd.Command)
	builder.WithParameter("kill_after", cmd.KillAfter)
	builder.WithOverApproximated()

	// If there's a command to execute, add execute operation
	if cmd.Command != "" {
		builder.AddExecuteOperation(cmd.Command, "timeout_execution")
		builder.WithCommandInfo("timeout")
		builder.WithParameter("dangerous", true)
		builder.WithParameter("over_approximated", true)
	}

	return builder.Build(), nil
}

// WhichCommand represents a parsed which command
type WhichCommand struct {
	Programs []string
	Options  map[string]bool
	All      bool
}

// WhichParser parses which commands
type WhichParser struct{}

// ParseArguments implements CommandParser for which commands
func (w *WhichParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for which")
	}

	cmd := &WhichCommand{
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
		case "-a", "--all":
			cmd.All = true
			cmd.Options["all"] = true
		case "--skip-dot":
			cmd.Options["skip_dot"] = true
		case "--skip-tty":
			cmd.Options["skip_tty"] = true
		case "--read-alias":
			cmd.Options["read_alias"] = true
		case "--read-functions":
			cmd.Options["read_functions"] = true
		case "--show-dot":
			cmd.Options["show_dot"] = true
		case "--show-tty":
			cmd.Options["show_tty"] = true
		case "--skip-alias":
			cmd.Options["skip_alias"] = true
		case "--skip-functions":
			cmd.Options["skip_functions"] = true
		default:
			cmd.Options[opt] = true
		}
		i++
	}

	// Remaining arguments are programs to find
	if i < len(args) {
		cmd.Programs = args[i:]
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for which commands
func (w *WhichParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*WhichCommand)
	if !ok {
		return nil, fmt.Errorf("invalid which command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// which reads PATH environment and searches for executables
	builder.AddReadOperation("$PATH", "path_environment")
	builder.WithCommandInfo("which")
	builder.WithParameter("all", cmd.All)
	builder.WithOverApproximated()

	// For each program, add read operations for potential locations
	for _, program := range cmd.Programs {
		builder.AddReadOperation("/usr/bin/"+program, "executable_search")
		builder.WithCommandInfo("which")
		builder.WithParameter("program", program)
		builder.WithOverApproximated()

		builder.AddReadOperation("/usr/local/bin/"+program, "executable_search")
		builder.WithCommandInfo("which")
		builder.WithParameter("program", program)
		builder.WithOverApproximated()

		builder.AddReadOperation("/bin/"+program, "executable_search")
		builder.WithCommandInfo("which")
		builder.WithParameter("program", program)
		builder.WithOverApproximated()
	}

	return builder.Build(), nil
}

// FreeCommandMisc represents a parsed free command
type FreeCommandMisc struct {
	Options map[string]interface{}
	Human   bool
	Total   bool
	Wide    bool
	Kilo    bool
	Mega    bool
	Giga    bool
	Count   int
}

// FreeParser parses free commands
type FreeParser struct{}

// ParseArguments implements CommandParser for free commands
func (f *FreeParser) ParseArguments(args []string) (interface{}, error) {
	cmd := &FreeCommandMisc{
		Options: make(map[string]interface{}),
	}

	// Parse options
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			for _, ch := range arg[1:] {
				switch ch {
				case 'h':
					cmd.Human = true
					cmd.Options["human"] = true
				case 't':
					cmd.Total = true
					cmd.Options["total"] = true
				case 'w':
					cmd.Wide = true
					cmd.Options["wide"] = true
				case 'k':
					cmd.Kilo = true
					cmd.Options["kilo"] = true
				case 'm':
					cmd.Mega = true
					cmd.Options["mega"] = true
				case 'g':
					cmd.Giga = true
					cmd.Options["giga"] = true
				case 'c':
					if len(arg) > 2 {
						// Handle -c count
						cmd.Count = ParserUtilsInstance.ParseInt(arg[2:])
						cmd.Options["count"] = cmd.Count
					}
				case 's':
					if len(arg) > 2 {
						// Handle -s seconds
						cmd.Options["seconds"] = ParserUtilsInstance.ParseInt(arg[2:])
					}
				}
			}
		}
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for free commands
func (f *FreeParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*FreeCommandMisc)
	if !ok {
		return nil, fmt.Errorf("invalid free command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// free reads system memory information
	builder.AddReadOperation("/proc/meminfo", "memory_info")
	builder.WithCommandInfo("free")
	builder.WithParameter("human", cmd.Human)
	builder.WithParameter("total", cmd.Total)
	builder.WithParameter("wide", cmd.Wide)
	builder.WithPrecise()

	// Also reads swap information
	builder.AddReadOperation("/proc/swaps", "swap_info")
	builder.WithCommandInfo("free")
	builder.WithOverApproximated()

	return builder.Build(), nil
}

// NewPwdParser creates a new PwdParser instance
func NewPwdParser() *PwdParser {
	return &PwdParser{}
}

// NewSleepParser creates a new SleepParser instance
func NewSleepParser() *SleepParser {
	return &SleepParser{}
}

// NewTimeoutParser creates a new TimeoutParser instance
func NewTimeoutParser() *TimeoutParser {
	return &TimeoutParser{}
}

// NewWhichParser creates a new WhichParser instance
func NewWhichParser() *WhichParser {
	return &WhichParser{}
}

// NewFreeParser creates a new FreeParser instance
func NewFreeParser() *FreeParser {
	return &FreeParser{}
}
// GetOperationGraph implements the enhanced CommandParser interface for misc commands
func (p *PwdParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*PwdCommand)
	if !ok {
		return nil, fmt.Errorf("invalid pwd command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("pwd", operations, []SemanticOperation{})

	return graph, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for sleep commands
func (p *SleepParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*SleepCommand)
	if !ok {
		return nil, fmt.Errorf("invalid sleep command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("sleep", operations, []SemanticOperation{})

	return graph, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for timeout commands
func (p *TimeoutParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*TimeoutCommand)
	if !ok {
		return nil, fmt.Errorf("invalid timeout command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("timeout", operations, []SemanticOperation{})

	return graph, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for which commands
func (p *WhichParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*WhichCommand)
	if !ok {
		return nil, fmt.Errorf("invalid which command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("which", operations, []SemanticOperation{})

	return graph, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for free commands
func (p *FreeParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*FreeCommand)
	if !ok {
		return nil, fmt.Errorf("invalid free command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("free", operations, []SemanticOperation{})

	return graph, nil
}
