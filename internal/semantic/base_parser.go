package semantic

import (
	"fmt"
	"strings"
)

// BaseCommand represents the common structure for all command types
type BaseCommand struct {
	CommandName string                 `json:"command_name"`
	Options     map[string]interface{} `json:"options"`
	Arguments   []string               `json:"arguments"`
	Files       []string               `json:"files"`
	Directories []string               `json:"directories"`
}

// NewBaseCommand creates a new BaseCommand with initialized fields
func NewBaseCommand(commandName string) *BaseCommand {
	return &BaseCommand{
		CommandName: commandName,
		Options:     make(map[string]interface{}),
		Arguments:   make([]string, 0),
		Files:       make([]string, 0),
		Directories: make([]string, 0),
	}
}

// AddOption adds an option to the command
func (bc *BaseCommand) AddOption(key string, value interface{}) {
	bc.Options[key] = value
}

// AddArgument adds an argument to the command
func (bc *BaseCommand) AddArgument(arg string) {
	bc.Arguments = append(bc.Arguments, arg)
}

// AddFile adds a file to the command
func (bc *BaseCommand) AddFile(file string) {
	bc.Files = append(bc.Files, file)
}

// AddDirectory adds a directory to the command
func (bc *BaseCommand) AddDirectory(dir string) {
	bc.Directories = append(bc.Directories, dir)
}

// HasOption checks if an option exists
func (bc *BaseCommand) HasOption(key string) bool {
	_, exists := bc.Options[key]
	return exists
}

// GetOptionString gets an option as a string
func (bc *BaseCommand) GetOptionString(key string) (string, bool) {
	if val, exists := bc.Options[key]; exists {
		if strVal, ok := val.(string); ok {
			return strVal, true
		}
	}
	return "", false
}

// GetOptionBool gets an option as a boolean
func (bc *BaseCommand) GetOptionBool(key string) (bool, bool) {
	if val, exists := bc.Options[key]; exists {
		if boolVal, ok := val.(bool); ok {
			return boolVal, true
		}
	}
	return false, false
}

// BaseParser provides common parsing functionality that can be extended
type BaseParser struct {
	commandName string
	utils       *ParserUtils
}

// NewBaseParser creates a new BaseParser
func NewBaseParser(commandName string) *BaseParser {
	return &BaseParser{
		commandName: commandName,
		utils:       ParserUtilsInstance,
	}
}

// ParseBasicArguments provides basic argument parsing that can be extended
func (bp *BaseParser) ParseBasicArguments(args []string) (*BaseCommand, int, error) {
	if len(args) == 0 {
		return nil, 0, fmt.Errorf("no command specified")
	}

	cmd := NewBaseCommand(bp.commandName)
	i := 0

	// Parse options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		// Handle "--" argument terminator
		if opt == "--" {
			i++
			break
		}

		// Handle long options
		if strings.HasPrefix(opt, "--") {
			cmd.AddOption(opt, true)
			i++
			continue
		}

		// Handle combined short options
		if len(opt) > 2 {
			for _, ch := range opt[1:] {
				shortOpt := "-" + string(ch)
				cmd.AddOption(shortOpt, true)
			}
			i++
			continue
		}

		// Handle single short options
		if len(opt) == 2 {
			cmd.AddOption(opt, true)

			// Check if this option takes an argument
			if bp.utils.optionTakesArgument(opt) && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				cmd.AddOption(opt, args[i+1])
				i += 2
				continue
			}
			i++
		}
	}

	// Parse remaining arguments
	if i < len(args) {
		for _, arg := range args[i:] {
			cmd.AddArgument(arg)
		}
	}

	return cmd, i, nil
}

// ParseFilesAndDirectories separates arguments into files and directories
func (bp *BaseParser) ParseFilesAndDirectories(args []string) ([]string, []string) {
	files := make([]string, 0)
	directories := make([]string, 0)

	for _, arg := range args {
		// Simple heuristic: if it ends with common file extensions, it's a file
		// Otherwise, assume it's a directory
		if strings.Contains(arg, ".") && !strings.HasSuffix(arg, "/") {
			files = append(files, arg)
		} else {
			directories = append(directories, arg)
		}
	}

	return files, directories
}

// GetDefaultFiles returns default files for commands that read from stdin by default
func (bp *BaseParser) GetDefaultFiles() []string {
	// Common commands that read from stdin by default
	stdinCommands := map[string]bool{
		"cat": true, "grep": true, "sed": true, "awk": true, "sort": true,
	}

	if stdinCommands[bp.commandName] {
		return []string{"/dev/stdin"}
	}
	return []string{}
}

// GetDefaultDirectories returns default directories for commands
func (bp *BaseParser) GetDefaultDirectories() []string {
	// Common commands that operate on current directory by default
	dirCommands := map[string]bool{
		"ls": true, "du": true, "find": true,
	}

	if dirCommands[bp.commandName] {
		return []string{"."}
	}
	return []string{}
}

// BaseSemanticOperationGenerator provides common semantic operation generation
type BaseSemanticOperationGenerator struct {
	commandName string
	utils       *ParserUtils
}

// NewBaseSemanticOperationGenerator creates a new generator
func NewBaseSemanticOperationGenerator(commandName string) *BaseSemanticOperationGenerator {
	return &BaseSemanticOperationGenerator{
		commandName: commandName,
		utils:       ParserUtilsInstance,
	}
}

// GenerateReadOperations generates read operations for files and directories
func (bsog *BaseSemanticOperationGenerator) GenerateReadOperations(
	files []string,
	directories []string,
	context string,
	parameters map[string]interface{},
) []SemanticOperation {

	builder := bsog.utils.SemanticOperationBuilder()

	// Add file read operations
	for _, file := range files {
		if bsog.utils.FilePathUtils().IsStdPath(file) {
			// Skip stdin/stdout for read operations in some contexts
			continue
		}

		opBuilder := builder.AddReadOperation(file, context)
		if parameters != nil {
			for k, v := range parameters {
				opBuilder.WithParameter(k, v)
			}
		}
		opBuilder.WithCommandInfo(bsog.commandName)

		// Add metadata read operation (conservative)
		builder.AddReadOperation(file+".meta", context+"_metadata")
		builder = builder.WithParameter("over_approximated", true)
		builder = builder.WithCommandInfo(bsog.commandName)
	}

	// Add directory read operations
	for _, dir := range directories {
		builder.AddReadOperation(dir, context)
		builder = builder.WithCommandInfo(bsog.commandName)

		// Add recursive read operation if appropriate (conservative)
		builder.AddReadOperation(dir+"/*", context+"_recursive")
		builder = builder.WithParameter("over_approximated", true)
		builder = builder.WithCommandInfo(bsog.commandName)
	}

	return builder.Build()
}

// GenerateWriteOperations generates write operations
func (bsog *BaseSemanticOperationGenerator) GenerateWriteOperations(
	targetPaths []string,
	context string,
	isDangerous bool,
) []SemanticOperation {

	builder := bsog.utils.SemanticOperationBuilder()

	for _, target := range targetPaths {
		opBuilder := builder.AddWriteOperation(target, context)
		opBuilder = opBuilder.WithCommandInfo(bsog.commandName)

		if isDangerous {
			opBuilder = opBuilder.WithDangerous()
		}

		// Conservative: mark as over-approximated unless we know exactly what's written
		opBuilder = opBuilder.WithOverApproximated()
	}

	return builder.Build()
}

// GenerateEditOperations generates edit operations (for in-place editing)
func (bsog *BaseSemanticOperationGenerator) GenerateEditOperations(
	files []string,
	context string,
) []SemanticOperation {

	builder := bsog.utils.SemanticOperationBuilder()

	for _, file := range files {
		if bsog.utils.FilePathUtils().IsStdPath(file) {
			continue // Don't edit stdin
		}

		builder.AddEditOperation(file, context)
		builder = builder.WithParameter("dangerous", true) // Editing is always dangerous
		builder = builder.WithParameter("precise", true)   // We know exactly which file
		builder = builder.WithCommandInfo(bsog.commandName)
	}

	return builder.Build()
}

// GenerateCreateOperations generates create operations
func (bsog *BaseSemanticOperationGenerator) GenerateCreateOperations(
	targetPatterns []string,
	context string,
) []SemanticOperation {

	builder := bsog.utils.SemanticOperationBuilder()

	for _, pattern := range targetPatterns {
		builder.AddCreateOperation(pattern, context)
		builder = builder.WithParameter("over_approximated", true) // Conservative
		builder = builder.WithCommandInfo(bsog.commandName)
	}

	return builder.Build()
}

// CommonParser provides a complete base parser that can be used directly
// or extended for simple commands
type CommonParser struct {
	*BaseParser
	*BaseSemanticOperationGenerator
}

// NewCommonParser creates a new CommonParser
func NewCommonParser(commandName string) *CommonParser {
	return &CommonParser{
		BaseParser:                    NewBaseParser(commandName),
		BaseSemanticOperationGenerator: NewBaseSemanticOperationGenerator(commandName),
	}
}

// ParseArguments implements the CommandParser interface
func (cp *CommonParser) ParseArguments(args []string) (interface{}, error) {
	// Skip the command name if it's the first argument
	startIndex := 0
	if len(args) > 0 && args[0] == cp.BaseParser.commandName {
		startIndex = 1
	}

	baseCmd, _, err := cp.ParseBasicArguments(args[startIndex:])
	if err != nil {
		return nil, err
	}

	// Separate files and directories
	files, directories := cp.ParseFilesAndDirectories(baseCmd.Arguments)

	// Add default files/directories if none specified
	if len(files) == 0 && len(directories) == 0 {
		files = cp.GetDefaultFiles()
		directories = cp.GetDefaultDirectories()
	}

	// Update the command with parsed files and directories
	for _, file := range files {
		baseCmd.AddFile(file)
	}
	for _, dir := range directories {
		baseCmd.AddDirectory(dir)
	}

	return baseCmd, nil
}

// GetSemanticOperations implements the CommandParser interface
func (cp *CommonParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	baseCmd, ok := parsed.(*BaseCommand)
	if !ok {
		return nil, fmt.Errorf("invalid command type for common parser")
	}

	// Generate read operations for all files and directories
	operations := cp.BaseSemanticOperationGenerator.GenerateReadOperations(
		baseCmd.Files,
		baseCmd.Directories,
		"input_"+cp.BaseParser.commandName,
		baseCmd.Options,
	)

	// Check for dangerous options and add appropriate operations
	if cp.hasDangerousOptions(baseCmd.Options) {
		// For simple parsers, we'll be conservative and assume writes might happen
		writeTargets := make([]string, 0)
		for _, file := range baseCmd.Files {
			if !cp.BaseParser.utils.FilePathUtils().IsStdPath(file) {
				writeTargets = append(writeTargets, file)
			}
		}
		for _, dir := range baseCmd.Directories {
			writeTargets = append(writeTargets, dir)
		}

		if len(writeTargets) > 0 {
			writeOps := cp.BaseSemanticOperationGenerator.GenerateWriteOperations(writeTargets, "output_"+cp.BaseParser.commandName, true)
			operations = append(operations, writeOps...)
		}
	}

	return operations, nil
}

// GetOperationGraph implements the enhanced CommandParser interface
func (cp *CommonParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*BaseCommand)
	if !ok {
		return nil, fmt.Errorf("invalid command type for common parser")
	}

	// Get basic semantic operations
	operations, err := cp.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph(cp.BaseParser.commandName, operations, []SemanticOperation{})

	return graph, nil
}

// hasDangerousOptions checks if any options indicate dangerous operations
func (cp *CommonParser) hasDangerousOptions(options map[string]interface{}) bool {
	for opt := range options {
		if cp.BaseParser.utils.CommandValidationUtils().IsDangerousOption(opt) {
			return true
		}
	}
	return false
}

// Global instance for easy access
var CommonParserInstance = NewCommonParser("")