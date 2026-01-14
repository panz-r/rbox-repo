package semantic

import (
	"fmt"
)

// SimpleCommand represents a simple command that can use the common parser utilities
type SimpleCommand struct {
	*BaseCommand
	// Add any command-specific fields here
	IsDangerous bool `json:"is_dangerous"`
}

// SimpleParser demonstrates how to create a parser using the common utilities
type SimpleParser struct {
	*CommonParser
	commandSpecificLogic func(*SimpleCommand) error
}

// NewSimpleParser creates a new SimpleParser for a specific command
func NewSimpleParser(commandName string, customLogic func(*SimpleCommand) error) *SimpleParser {
	return &SimpleParser{
		CommonParser:         NewCommonParser(commandName),
		commandSpecificLogic: customLogic,
	}
}

// ParseArguments implements CommandParser interface using common utilities
func (sp *SimpleParser) ParseArguments(args []string) (interface{}, error) {
	// Use the base parser for common parsing
	baseCmd, err := sp.CommonParser.ParseArguments(args)
	if err != nil {
		return nil, err
	}

	// Convert to SimpleCommand
	simpleCmd := &SimpleCommand{
		BaseCommand: baseCmd.(*BaseCommand),
	}

	// Apply command-specific logic if provided
	if sp.commandSpecificLogic != nil {
		if err := sp.commandSpecificLogic(simpleCmd); err != nil {
			return nil, err
		}
	}

	return simpleCmd, nil
}

// GetSemanticOperations implements CommandParser interface
func (sp *SimpleParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*SimpleCommand)
	if !ok {
		return nil, fmt.Errorf("invalid command type for simple parser")
	}

	// Use the base semantic operation generator
	ops, err := sp.CommonParser.GetSemanticOperations(cmd.BaseCommand)
	if err != nil {
		return nil, err
	}
	operations := ops

	// Add command-specific semantic operations if needed
	if cmd.IsDangerous {
		// Add additional operations or modify existing ones for dangerous commands
		builder := ParserUtilsInstance.SemanticOperationBuilder()

		// Example: add warning operations for dangerous commands
		for _, file := range cmd.Files {
			if !ParserUtilsInstance.FilePathUtils().IsStdPath(file) {
				builder.AddReadOperation(file, "dangerous_operation_warning")
				builder = builder.WithParameter("warning", "This command may modify files")
				builder = builder.WithParameter("dangerous", true)
				builder = builder.WithCommandInfo(sp.BaseParser.commandName)
			}
		}

		operations = append(operations, builder.Build()...)
	}

	return operations, nil
}

// Example: Create a specific parser for a hypothetical 'transform' command
type TransformCommand struct {
	*SimpleCommand
	TransformType string `json:"transform_type"`
}

// TransformParser demonstrates a more specific parser built on SimpleParser
type TransformParser struct {
	*SimpleParser
}

// NewTransformParser creates a new TransformParser
func NewTransformParser() *TransformParser {
	customLogic := func(cmd *SimpleCommand) error {
		// Add transform-specific logic
		if cmd.HasOption("-t") || cmd.HasOption("--type") {
			transformType, ok := cmd.GetOptionString("-t")
			if !ok {
				transformType, _ = cmd.GetOptionString("--type")
			}
			// In a real implementation, we'd store this in the TransformCommand
			cmd.AddOption("transform_type", transformType)
		}
		return nil
	}

	return &TransformParser{
		SimpleParser: NewSimpleParser("transform", customLogic),
	}
}

// ParseArguments implements CommandParser for transform command
func (tp *TransformParser) ParseArguments(args []string) (interface{}, error) {
	// Parse using the simple parser
	cmd, err := tp.SimpleParser.ParseArguments(args)
	if err != nil {
		return nil, err
	}

	// Convert to TransformCommand
	simpleCmd := cmd.(*SimpleCommand)
	transformCmd := &TransformCommand{
		SimpleCommand: simpleCmd,
	}

	// Extract transform type if specified
	if transformType, ok := simpleCmd.GetOptionString("transform_type"); ok {
		transformCmd.TransformType = transformType
	}

	return transformCmd, nil
}

// GetSemanticOperations implements CommandParser for transform command
func (tp *TransformParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*TransformCommand)
	if !ok {
		return nil, fmt.Errorf("invalid transform command type")
	}

	// Get base operations from simple parser
	operations, err := tp.SimpleParser.GetSemanticOperations(cmd.SimpleCommand)
	if err != nil {
		return nil, err
	}

	// Add transform-specific operations
	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// Transform operations depend on the transform type
	switch cmd.TransformType {
	case "uppercase", "lowercase":
		// Text transformations - add edit operations for files
		for _, file := range cmd.Files {
			if !ParserUtilsInstance.FilePathUtils().IsStdPath(file) {
				builder.AddEditOperation(file, "text_transform")
				builder = builder.WithParameter("transform_type", cmd.TransformType)
				builder = builder.WithParameter("dangerous", true)
				builder = builder.WithCommandInfo("transform")
			}
		}

	case "encrypt", "decrypt":
		// Crypto operations - more dangerous
		for _, file := range cmd.Files {
			if !ParserUtilsInstance.FilePathUtils().IsStdPath(file) {
				builder.AddEditOperation(file, "crypto_transform")
				builder = builder.WithParameter("transform_type", cmd.TransformType)
				builder = builder.WithParameter("dangerous", true)
				builder = builder.WithParameter("high_risk", true)
				builder = builder.WithCommandInfo("transform")
			}
		}

	default:
		// Unknown transform type - be conservative
		for _, file := range cmd.Files {
			if !ParserUtilsInstance.FilePathUtils().IsStdPath(file) {
				builder.AddEditOperation(file, "unknown_transform")
				builder = builder.WithParameter("transform_type", cmd.TransformType)
				builder = builder.WithParameter("dangerous", true)
				builder = builder.WithParameter("over_approximated", true)
				builder = builder.WithCommandInfo("transform")
			}
		}
	}

	operations = append(operations, builder.Build()...)

	return operations, nil
}

// Example: Create a parser for a hypothetical 'backup' command
type BackupCommand struct {
	*SimpleCommand
	BackupDirectory string `json:"backup_directory"`
	Compression     string `json:"compression"`
}

// BackupParser demonstrates another specific parser
type BackupParser struct {
	*SimpleParser
}

// NewBackupParser creates a new BackupParser
func NewBackupParser() *BackupParser {
	customLogic := func(cmd *SimpleCommand) error {
		// Backup commands are generally safe (read-only)
		cmd.IsDangerous = false
		return nil
	}

	return &BackupParser{
		SimpleParser: NewSimpleParser("backup", customLogic),
	}
}

// ParseArguments implements CommandParser for backup command
func (bp *BackupParser) ParseArguments(args []string) (interface{}, error) {
	cmd, err := bp.SimpleParser.ParseArguments(args)
	if err != nil {
		return nil, err
	}

	simpleCmd := cmd.(*SimpleCommand)
	backupCmd := &BackupCommand{
		SimpleCommand: simpleCmd,
	}

	// Parse backup-specific options
	if backupDir, ok := simpleCmd.GetOptionString("-d"); ok {
		backupCmd.BackupDirectory = backupDir
	}

	if comp, ok := simpleCmd.GetOptionString("-c"); ok {
		backupCmd.Compression = comp
	}

	return backupCmd, nil
}

// GetSemanticOperations implements CommandParser for backup command
func (bp *BackupParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*BackupCommand)
	if !ok {
		return nil, fmt.Errorf("invalid backup command type")
	}

	// Backup operations are primarily read operations
	operations, err := bp.SimpleParser.GetSemanticOperations(cmd.SimpleCommand)
	if err != nil {
		return nil, err
	}

	// Add backup-specific operations
	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// Read operations for backup directory
	if cmd.BackupDirectory != "" {
		builder.AddReadOperation(cmd.BackupDirectory, "backup_target")
		builder = builder.WithCommandInfo("backup")

		// Conservative: assume we might create backup files
		builder.AddCreateOperation(cmd.BackupDirectory+"/*.backup", "backup_files")
		builder = builder.WithParameter("over_approximated", true)
		builder = builder.WithCommandInfo("backup")
	}

	operations = append(operations, builder.Build()...)

	return operations, nil
}
// GetOperationGraph implements the enhanced CommandParser interface for simple commands
func (p *SimpleParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*SimpleCommand)
	if !ok {
		return nil, fmt.Errorf("invalid simple command type")
	}

	// Get basic semantic operations
	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("simple", operations, []SemanticOperation{})

	return graph, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for simple commands
