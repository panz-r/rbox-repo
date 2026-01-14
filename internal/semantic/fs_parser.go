package semantic

import (
	"fmt"
	"strings"
)

// DdCommand represents a parsed dd command
type DdCommand struct {
	InputFile     string
	OutputFile    string
	BlockSize     string
	Count         string
	Options       map[string]interface{}
	HasInputFile  bool
	HasOutputFile bool
	Dangerous     bool
}

// DdParser parses dd commands
type DdParser struct{}

// ParseArguments implements CommandParser for dd commands
func (d *DdParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for dd")
	}

	cmd := &DdCommand{
		Options: make(map[string]interface{}),
	}

	// Parse dd operands (they come in pairs: option=value)
	i := 0
	for i < len(args) {
		arg := args[i]

		if !strings.Contains(arg, "=") {
			// This might be a legacy syntax, skip for now
			i++
			continue
		}

		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			i++
			continue
		}

		opt := parts[0]
		val := parts[1]

		switch opt {
		case "if":
			cmd.InputFile = val
			cmd.HasInputFile = true
			cmd.Options["if"] = val
		case "of":
			cmd.OutputFile = val
			cmd.HasOutputFile = true
			cmd.Options["of"] = val
			// Output file makes it dangerous
			cmd.Dangerous = true
		case "bs":
			cmd.BlockSize = val
			cmd.Options["bs"] = val
		case "count":
			cmd.Count = val
			cmd.Options["count"] = val
		case "seek":
			cmd.Options["seek"] = val
		case "skip":
			cmd.Options["skip"] = val
		case "status":
			cmd.Options["status"] = val
		default:
			cmd.Options[opt] = val
		}
		i++
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for dd commands
func (d *DdParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*DdCommand)
	if !ok {
		return nil, fmt.Errorf("invalid dd command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// If there's an input file, add read operation
	if cmd.HasInputFile {
		builder.AddReadOperation(cmd.InputFile, "dd_input")
		builder.WithCommandInfo("dd")
		builder.WithParameter("block_size", cmd.BlockSize)
		builder.WithParameter("count", cmd.Count)
		if cmd.InputFile == "/dev/random" || cmd.InputFile == "/dev/urandom" {
			builder.WithOverApproximated()
		} else {
			builder.WithPrecise()
		}
	}

	// If there's an output file, add write operation
	if cmd.HasOutputFile {
		builder.AddWriteOperation(cmd.OutputFile, "dd_output")
		builder.WithCommandInfo("dd")
		builder.WithParameter("block_size", cmd.BlockSize)
		builder.WithParameter("count", cmd.Count)
		builder.WithParameter("dangerous", cmd.Dangerous)
		builder.WithOverApproximated()

		// Also add create operation
		builder.AddCreateOperation(cmd.OutputFile, "dd_create")
		builder.WithCommandInfo("dd")
		builder.WithParameter("dangerous", cmd.Dangerous)
		builder.WithOverApproximated()
	}

	// dd always reads/writes in blocks, so it's conservative to assume
	// it might affect adjacent data
	if cmd.HasOutputFile {
		builder.AddWriteOperation(cmd.OutputFile+"_adjacent", "dd_potential_overwrite")
		builder.WithCommandInfo("dd")
		builder.WithParameter("over_approximated", true)
		builder.WithParameter("dangerous", true)
	}

	return builder.Build(), nil
}

// ExprCommand represents a parsed expr command
type ExprCommand struct {
	Expression string
	Options    map[string]bool
}

// ExprParser parses expr commands
type ExprParser struct{}

// ParseArguments implements CommandParser for expr commands
func (e *ExprParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for expr")
	}

	cmd := &ExprCommand{
		Options: make(map[string]bool),
		Expression: strings.Join(args, " "),
	}

	// expr doesn't have many standard options, but let's check for some
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			cmd.Options[arg] = true
		}
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for expr commands
func (e *ExprParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*ExprCommand)
	if !ok {
		return nil, fmt.Errorf("invalid expr command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// expr evaluates expressions, doesn't perform file operations
	// but might read environment variables
	builder.AddReadOperation("$ENV", "environment_variables")
	builder.WithCommandInfo("expr")
	builder.WithParameter("expression", cmd.Expression)
	builder.WithOverApproximated()

	// Check if expression contains dangerous patterns
	dangerousPatterns := []string{"`", "$", "exec", "eval", "system"}
	isDangerous := false
	for _, pattern := range dangerousPatterns {
		if strings.Contains(cmd.Expression, pattern) {
			isDangerous = true
			break
		}
	}

	if isDangerous {
		builder.AddExecuteOperation("expr_dangerous", "expr_execution")
		builder.WithCommandInfo("expr")
		builder.WithParameter("dangerous", true)
		builder.WithParameter("expression", cmd.Expression)
		builder.WithOverApproximated()
	}

	return builder.Build(), nil
}

// LnCommand represents a parsed ln command
type LnCommand struct {
	Target      string
	LinkName    string
	Options     map[string]bool
	Symbolic    bool
	Force       bool
	Interactive bool
	Backup      bool
	NoDeref     bool
	Relative    bool
	Verbose     bool
}

// LnParser parses ln commands
type LnParser struct{}

// ParseArguments implements CommandParser for ln commands
func (l *LnParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("ln requires target and link name")
	}

	cmd := &LnCommand{
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
		case "-s", "--symbolic":
			cmd.Symbolic = true
			cmd.Options["symbolic"] = true
		case "-f", "--force":
			cmd.Force = true
			cmd.Options["force"] = true
		case "-i", "--interactive":
			cmd.Interactive = true
			cmd.Options["interactive"] = true
		case "-b", "--backup":
			cmd.Backup = true
			cmd.Options["backup"] = true
		case "-n", "--no-dereference":
			cmd.NoDeref = true
			cmd.Options["no_dereference"] = true
		case "-r", "--relative":
			cmd.Relative = true
			cmd.Options["relative"] = true
		case "-v", "--verbose":
			cmd.Verbose = true
			cmd.Options["verbose"] = true
		default:
			// Handle combined options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 's':
						cmd.Symbolic = true
					case 'f':
						cmd.Force = true
					case 'i':
						cmd.Interactive = true
					case 'b':
						cmd.Backup = true
					case 'n':
						cmd.NoDeref = true
					case 'r':
						cmd.Relative = true
					case 'v':
						cmd.Verbose = true
					}
				}
			}
		}
		i++
	}

	// Parse target and link name
	if i < len(args) {
		cmd.Target = args[i]
		i++
	}
	if i < len(args) {
		cmd.LinkName = args[i]
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for ln commands
func (l *LnParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*LnCommand)
	if !ok {
		return nil, fmt.Errorf("invalid ln command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// Read the target file
	builder.AddReadOperation(cmd.Target, "ln_target")
	builder.WithCommandInfo("ln")
	builder.WithParameter("symbolic", cmd.Symbolic)
	builder.WithParameter("no_dereference", cmd.NoDeref)
	builder.WithPrecise()

	// Create the link (write operation)
	builder.AddCreateOperation(cmd.LinkName, "ln_create")
	builder.WithCommandInfo("ln")
	builder.WithParameter("symbolic", cmd.Symbolic)
	builder.WithParameter("force", cmd.Force)
	builder.WithParameter("dangerous", cmd.Force || cmd.Symbolic)
	builder.WithOverApproximated()

	// If force is used, might overwrite existing file
	if cmd.Force {
		builder.AddWriteOperation(cmd.LinkName, "ln_overwrite")
		builder.WithCommandInfo("ln")
		builder.WithParameter("dangerous", true)
		builder.WithOverApproximated()
	}

	// If backup is used, might create backup files
	if cmd.Backup {
		builder.AddCreateOperation(cmd.LinkName+"~", "ln_backup")
		builder.WithCommandInfo("ln")
		builder.WithParameter("backup", true)
		builder.WithOverApproximated()
	}

	return builder.Build(), nil
}

// MkdirCommand represents a parsed mkdir command
type MkdirCommand struct {
	Directories []string
	Options     map[string]interface{}
	Parents     bool
	Mode        string
	Verbose     bool
}

// MkdirParser parses mkdir commands
type MkdirParser struct{}

// ParseArguments implements CommandParser for mkdir commands
func (m *MkdirParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for mkdir")
	}

	cmd := &MkdirCommand{
		Options: make(map[string]interface{}),
	}

	// Parse options
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-p", "--parents":
			cmd.Parents = true
			cmd.Options["parents"] = true
		case "-m", "--mode":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				cmd.Mode = args[i+1]
				cmd.Options["mode"] = args[i+1]
				i += 2
				continue
			}
		case "-v", "--verbose":
			cmd.Verbose = true
			cmd.Options["verbose"] = true
		case "-Z":
			cmd.Options["context"] = true
		default:
			// Handle combined options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'p':
							cmd.Options["parents"] = true
						cmd.Parents = true
					case 'v':
							cmd.Options["verbose"] = true
						cmd.Verbose = true
					}
				}
			}
		}
		i++
	}

	// Parse directories
	if i < len(args) {
		cmd.Directories = args[i:]
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for mkdir commands
func (m *MkdirParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*MkdirCommand)
	if !ok {
		return nil, fmt.Errorf("invalid mkdir command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// For each directory, add create operation
	for _, dir := range cmd.Directories {
		builder.AddCreateOperation(dir, "mkdir_create")
		builder.WithCommandInfo("mkdir")
		builder.WithParameter("mode", cmd.Mode)
		builder.WithParameter("parents", cmd.Parents)
		builder.WithParameter("dangerous", true)
		builder.WithOverApproximated()

		// If parents option is used, might create parent directories
		if cmd.Parents {
			builder.AddCreateOperation(dir+"/*", "mkdir_parents")
			builder.WithCommandInfo("mkdir")
			builder.WithParameter("recursive", true)
			builder.WithParameter("over_approximated", true)
			builder.WithParameter("dangerous", true)
		}

		// Read parent directory to check permissions
		parentDir := "."
		if strings.Contains(dir, "/") {
			parentDir = dir[:strings.LastIndex(dir, "/")]
			if parentDir == "" {
				parentDir = "/"
			}
		}
		builder.AddReadOperation(parentDir, "mkdir_parent_check")
		builder.WithCommandInfo("mkdir")
		builder.WithOverApproximated()
	}

	return builder.Build(), nil
}

// PrintenvCommandFS represents a parsed printenv command
type PrintenvCommandFS struct {
	Variables []string
	Options   map[string]bool
	All       bool
	Null      bool
}

// PrintenvParser parses printenv commands
type PrintenvParser struct{}

// ParseArguments implements CommandParser for printenv commands
func (p *PrintenvParser) ParseArguments(args []string) (interface{}, error) {
	cmd := &PrintenvCommandFS{
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
		case "--all":
			cmd.All = true
			cmd.Options["all"] = true
		case "-0", "--null":
			cmd.Null = true
			cmd.Options["null"] = true
		case "--help":
			cmd.Options["help"] = true
		case "--version":
			cmd.Options["version"] = true
		default:
			cmd.Options[opt] = true
		}
		i++
	}

	// Parse variables
	if i < len(args) {
		cmd.Variables = args[i:]
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for printenv commands
func (p *PrintenvParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*PrintenvCommandFS)
	if !ok {
		return nil, fmt.Errorf("invalid printenv command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// printenv reads environment variables
	if len(cmd.Variables) > 0 {
		for _, varName := range cmd.Variables {
			builder.AddReadOperation("$"+varName, "environment_variable")
			builder.WithCommandInfo("printenv")
			builder.WithParameter("variable", varName)
			builder.WithPrecise()
		}
	} else if cmd.All {
		// Read all environment variables
		builder.AddReadOperation("$ENV", "all_environment")
		builder.WithCommandInfo("printenv")
		builder.WithParameter("all", true)
		builder.WithOverApproximated()
	} else {
		// Default: read all environment variables
		builder.AddReadOperation("$ENV", "environment")
		builder.WithCommandInfo("printenv")
		builder.WithOverApproximated()
	}

	return builder.Build(), nil
}

// RmdirCommand represents a parsed rmdir command
type RmdirCommand struct {
	Directories []string
	Options     map[string]bool
	Parents     bool
	IgnoreFail  bool
	Verbose     bool
}

// RmdirParser parses rmdir commands
type RmdirParser struct{}

// ParseArguments implements CommandParser for rmdir commands
func (r *RmdirParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for rmdir")
	}

	cmd := &RmdirCommand{
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
		case "-p", "--parents":
			cmd.Parents = true
			cmd.Options["parents"] = true
		case "--ignore-fail-on-non-empty":
			cmd.IgnoreFail = true
			cmd.Options["ignore_fail"] = true
		case "-v", "--verbose":
			cmd.Verbose = true
			cmd.Options["verbose"] = true
		default:
			// Handle combined options
			if len(opt) > 1 && !strings.HasPrefix(opt, "--") {
				for _, ch := range opt[1:] {
					switch ch {
					case 'p':
						cmd.Parents = true
					case 'v':
						cmd.Verbose = true
					}
				}
			}
		}
		i++
	}

	// Parse directories
	if i < len(args) {
		cmd.Directories = args[i:]
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for rmdir commands
func (r *RmdirParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*RmdirCommand)
	if !ok {
		return nil, fmt.Errorf("invalid rmdir command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// For each directory, add dangerous operations
	for _, dir := range cmd.Directories {
		// Read directory to check if it's empty
		builder.AddReadOperation(dir, "rmdir_check")
		builder.WithCommandInfo("rmdir")
		builder.WithOverApproximated()

		// Remove directory operation (dangerous)
		builder.AddWriteOperation(dir, "rmdir_remove")
		builder.WithCommandInfo("rmdir")
		builder.WithParameter("dangerous", true)
		builder.WithParameter("parents", cmd.Parents)
		builder.WithOverApproximated()

		// If parents option is used, might remove parent directories
		if cmd.Parents {
			builder.AddWriteOperation(dir+"/*", "rmdir_parents")
			builder.WithCommandInfo("rmdir")
			builder.WithParameter("recursive", true)
			builder.WithParameter("over_approximated", true)
			builder.WithParameter("dangerous", true)
		}
	}

	return builder.Build(), nil
}

// UlimitCommand represents a parsed ulimit command
type UlimitCommand struct {
	Options map[string]interface{}
	Limit   string
	Value   string
}

// UlimitParser parses ulimit commands
type UlimitParser struct{}

// ParseArguments implements CommandParser for ulimit commands
func (u *UlimitParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for ulimit")
	}

	cmd := &UlimitCommand{
		Options: make(map[string]interface{}),
		Limit:   args[0],
	}

	// Parse options and values
	if len(args) > 1 {
		cmd.Value = args[1]
		cmd.Options[cmd.Limit] = cmd.Value
	}

	// Check for options
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			if len(arg) > 1 {
				opt := arg[1:]
				cmd.Options["-"+opt] = true
				if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
					cmd.Value = args[1]
					cmd.Options[opt] = args[1]
				}
			}
		}
	}

	return cmd, nil
}

// GetSemanticOperations implements CommandParser for ulimit commands
func (u *UlimitParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*UlimitCommand)
	if !ok {
		return nil, fmt.Errorf("invalid ulimit command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// ulimit modifies process limits, doesn't perform file operations
	// but reads/writes process state
	builder.AddReadOperation("/proc/self/limits", "process_limits")
	builder.WithCommandInfo("ulimit")
	builder.WithParameter("limit", cmd.Limit)
	builder.WithParameter("value", cmd.Value)
	builder.WithOverApproximated()

	// If setting a limit, it's a write operation
	if cmd.Value != "" {
		builder.AddWriteOperation("/proc/self/limits", "ulimit_set")
		builder.WithCommandInfo("ulimit")
		builder.WithParameter("limit", cmd.Limit)
		builder.WithParameter("value", cmd.Value)
		builder.WithParameter("dangerous", true)
		builder.WithOverApproximated()
	}

	return builder.Build(), nil
}

// NewDdParser creates a new DdParser instance
func NewDdParser() *DdParser {
	return &DdParser{}
}

// NewExprParser creates a new ExprParser instance
func NewExprParser() *ExprParser {
	return &ExprParser{}
}

// NewLnParser creates a new LnParser instance
func NewLnParser() *LnParser {
	return &LnParser{}
}

// NewMkdirParser creates a new MkdirParser instance
func NewMkdirParser() *MkdirParser {
	return &MkdirParser{}
}

// NewPrintenvParser creates a new PrintenvParser instance
func NewPrintenvParser() *PrintenvParser {
	return &PrintenvParser{}
}

// NewRmdirParser creates a new RmdirParser instance
func NewRmdirParser() *RmdirParser {
	return &RmdirParser{}
}

// NewUlimitParser creates a new UlimitParser instance
func NewUlimitParser() *UlimitParser {
	return &UlimitParser{}
}
// GetOperationGraph implements the enhanced CommandParser interface for fs commands

// GetOperationGraph implements the enhanced CommandParser interface for dd commands
func (p *DdParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*DdCommand)
	if !ok {
		return nil, fmt.Errorf("invalid dd command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("dd", operations, []SemanticOperation{})

	return graph, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for expr commands
func (p *ExprParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*ExprCommand)
	if !ok {
		return nil, fmt.Errorf("invalid expr command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("expr", operations, []SemanticOperation{})

	return graph, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for ln commands
func (p *LnParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*LnCommand)
	if !ok {
		return nil, fmt.Errorf("invalid ln command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("ln", operations, []SemanticOperation{})

	return graph, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for mkdir commands
func (p *MkdirParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*MkdirCommand)
	if !ok {
		return nil, fmt.Errorf("invalid mkdir command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("mkdir", operations, []SemanticOperation{})

	return graph, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for printenv commands
func (p *PrintenvParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*PrintenvCommand)
	if !ok {
		return nil, fmt.Errorf("invalid printenv command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("printenv", operations, []SemanticOperation{})

	return graph, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for rmdir commands
func (p *RmdirParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*RmdirCommand)
	if !ok {
		return nil, fmt.Errorf("invalid rmdir command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("rmdir", operations, []SemanticOperation{})

	return graph, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for ulimit commands
func (p *UlimitParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*UlimitCommand)
	if !ok {
		return nil, fmt.Errorf("invalid ulimit command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("ulimit", operations, []SemanticOperation{})

	return graph, nil
}
