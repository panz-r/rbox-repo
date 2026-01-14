package semantic

import (
	"fmt"
	"strings"
)

// ParserUtils provides common utilities for command parsers
type ParserUtils struct{}

// ParseOptions parses command line options and returns a map
// Handles both short (-x) and long (--option) options
// Supports combined short options (-abc = -a -b -c)
// Returns the options map and the index where option parsing stopped
func (pu *ParserUtils) ParseOptions(args []string, startIndex int) (map[string]interface{}, int, error) {
	options := make(map[string]interface{})
	i := startIndex

	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		// Handle "--" argument terminator
		if opt == "--" {
			i++
			break
		}

		// Handle long options (--option)
		if strings.HasPrefix(opt, "--") {
			options[opt] = true
			i++
			continue
		}

		// Handle combined short options (-abc)
		if len(opt) > 2 && !strings.HasPrefix(opt, "--") {
			// Process each character in the combined option
			for j, ch := range opt[1:] {
				shortOpt := "-" + string(ch)

				// Check if this option takes an argument and if it's the last option in the combined set
				if pu.optionTakesArgument(shortOpt) && j == len(opt[1:])-1 && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					options[shortOpt] = args[i+1]
					i++ // Consume the argument
					break
				} else {
					options[shortOpt] = true
				}
			}
			i++
			continue
		}

		// Handle single short options with potential arguments
		if len(opt) == 2 {
			options[opt] = true

			// Check if this option typically takes an argument
			if pu.optionTakesArgument(opt) && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				options[opt] = args[i+1]
				i += 2
				continue
			}
			i++
		}
	}

	return options, i, nil
}

// optionTakesArgument returns true if the option typically takes an argument
func (pu *ParserUtils) optionTakesArgument(opt string) bool {
	takesArgOptions := map[string]bool{
		"-j": true, "-C": true, "-G": true, "-f": true, "-o": true,
		"-e": true, "-U": true, "-p": true, "-D": true,
		"-x": true, // For testing
		"--max-depth": true, "--build": true, "--target": true,
		"-n": true, "-c": true, "-L": true, // For wc, head, tail
		"-m": true, // For wc (chars)
	}
	return takesArgOptions[opt]
}

// ParseOptionWithArgument handles options that require arguments
// Returns the argument value and the new index
func (pu *ParserUtils) ParseOptionWithArgument(args []string, i int, opt string) (string, int, error) {
	if i+1 >= len(args) {
		return "", i, fmt.Errorf("missing argument after %s", opt)
	}
	if strings.HasPrefix(args[i+1], "-") {
		return "", i, fmt.Errorf("missing argument after %s", opt)
	}
	return args[i+1], i + 2, nil
}

// ParseOptionWithOptionalArgument handles options that may have arguments
// Returns the argument value (empty if none) and the new index
func (pu *ParserUtils) ParseOptionWithOptionalArgument(args []string, i int, opt string) (string, int, error) {
	if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
		return args[i+1], i + 2, nil
	}
	return "", i + 1, nil
}

// ParseBooleanOption handles simple boolean flags
func (pu *ParserUtils) ParseBooleanOption(options map[string]interface{}, opt string, fieldName string) {
	if _, exists := options[opt]; exists {
		options[fieldName] = true
	}
}

// ParseStringOption handles string options
func (pu *ParserUtils) ParseStringOption(options map[string]interface{}, opt string, fieldName string) {
	if val, exists := options[opt]; exists {
		if _, ok := val.(string); ok {
			options[fieldName] = val
		}
	}
}

// ParseIntOption handles integer options (simple parsing, use strconv.Atoi for real implementation)
func (pu *ParserUtils) ParseIntOption(options map[string]interface{}, opt string, fieldName string) {
	if val, exists := options[opt]; exists {
		if _, ok := val.(string); ok {
			// Simple parsing - in real implementation use strconv.Atoi
			options[fieldName] = 1 // Default value
		}
	}
}

// ParseInt parses a string to an integer (simple implementation)
func (pu *ParserUtils) ParseInt(s string) int {
	// Simple parsing - in real implementation use strconv.Atoi
	// For now, return the string as a simple int representation
	// This handles basic numeric strings
	if s == "" {
		return 0
	}

	// Simple digit parsing
	result := 0
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			result = result*10 + int(ch-'0')
		} else {
			// If non-digit found, return 1 as default
			return 1
		}
	}

	if result == 0 {
		return 1 // Default value for empty or zero
	}
	return result
}

// ParseStringSliceOption handles options with comma-separated values
func (pu *ParserUtils) ParseStringSliceOption(options map[string]interface{}, opt string, fieldName string) {
	if val, exists := options[opt]; exists {
		if strVal, ok := val.(string); ok {
			options[fieldName] = strings.Split(strVal, ",")
		}
	}
}

// SemanticOperationBuilder helps build semantic operations with common patterns
func (pu *ParserUtils) SemanticOperationBuilder() *SemanticOperationBuilder {
	return &SemanticOperationBuilder{
		operations: make([]SemanticOperation, 0),
	}
}

// SemanticOperationBuilder provides a fluent interface for building semantic operations
type SemanticOperationBuilder struct {
	operations []SemanticOperation
}

// AddReadOperation adds a read operation to the builder
func (sob *SemanticOperationBuilder) AddReadOperation(targetPath string, context string) *SemanticOperationBuilder {
	sob.operations = append(sob.operations, SemanticOperation{
		OperationType: OpRead,
		TargetPath:    targetPath,
		Context:       context,
		Parameters:    make(map[string]interface{}),
	})
	return sob
}

// AddWriteOperation adds a write operation to the builder
func (sob *SemanticOperationBuilder) AddWriteOperation(targetPath string, context string) *SemanticOperationBuilder {
	sob.operations = append(sob.operations, SemanticOperation{
		OperationType: OpWrite,
		TargetPath:    targetPath,
		Context:       context,
		Parameters:    make(map[string]interface{}),
	})
	return sob
}

// AddCreateOperation adds a create operation to the builder
func (sob *SemanticOperationBuilder) AddCreateOperation(targetPath string, context string) *SemanticOperationBuilder {
	sob.operations = append(sob.operations, SemanticOperation{
		OperationType: OpCreate,
		TargetPath:    targetPath,
		Context:       context,
		Parameters:    make(map[string]interface{}),
	})
	return sob
}

// AddEditOperation adds an edit operation to the builder
func (sob *SemanticOperationBuilder) AddEditOperation(targetPath string, context string) *SemanticOperationBuilder {
	sob.operations = append(sob.operations, SemanticOperation{
		OperationType: OpEdit,
		TargetPath:    targetPath,
		Context:       context,
		Parameters:    make(map[string]interface{}),
	})
	return sob
}

	// AddExecuteOperation adds an execute operation to the builder
	func (sob *SemanticOperationBuilder) AddExecuteOperation(targetPath string, context string) *SemanticOperationBuilder {
		sob.operations = append(sob.operations, SemanticOperation{
			OperationType: OpExecute,
			TargetPath:    targetPath,
			Context:       context,
			Parameters:    make(map[string]interface{}),
		})
		return sob
	}

// WithParameter adds a parameter to the last operation
func (sob *SemanticOperationBuilder) WithParameter(key string, value interface{}) *SemanticOperationBuilder {
	if len(sob.operations) > 0 {
		lastIndex := len(sob.operations) - 1
		if sob.operations[lastIndex].Parameters == nil {
			sob.operations[lastIndex].Parameters = make(map[string]interface{})
		}
		sob.operations[lastIndex].Parameters[key] = value
	}
	return sob
}

// WithCommandInfo adds common command information to the last operation
func (sob *SemanticOperationBuilder) WithCommandInfo(command string) *SemanticOperationBuilder {
	if len(sob.operations) > 0 {
		lastIndex := len(sob.operations) - 1
		if sob.operations[lastIndex].Parameters == nil {
			sob.operations[lastIndex].Parameters = make(map[string]interface{})
		}
		sob.operations[lastIndex].Parameters["command"] = command
	}
	return sob
}

// WithPrecise marks the last operation as precise
func (sob *SemanticOperationBuilder) WithPrecise() *SemanticOperationBuilder {
	return sob.WithParameter("precise", true)
}

// WithOverApproximated marks the last operation as over-approximated
func (sob *SemanticOperationBuilder) WithOverApproximated() *SemanticOperationBuilder {
	return sob.WithParameter("over_approximated", true)
}

// WithSafe marks the last operation as safe
func (sob *SemanticOperationBuilder) WithSafe() *SemanticOperationBuilder {
	return sob.WithParameter("safe", true)
}

// WithDangerous marks the last operation as dangerous
func (sob *SemanticOperationBuilder) WithDangerous() *SemanticOperationBuilder {
	return sob.WithParameter("dangerous", true)
}

// Build returns the built operations
func (sob *SemanticOperationBuilder) Build() []SemanticOperation {
	return sob.operations
}

// AddFileReadOperations adds read operations for multiple files with common parameters
func (sob *SemanticOperationBuilder) AddFileReadOperations(files []string, context string, command string, precise bool) *SemanticOperationBuilder {
	for _, file := range files {
		sob.AddReadOperation(file, context)
		sob.WithCommandInfo(command)
		if precise {
			sob.WithPrecise()
		} else {
			sob.WithOverApproximated()
		}
	}
	return sob
}

// AddStdinReadOperation adds a stdin read operation with common parameters
func (sob *SemanticOperationBuilder) AddStdinReadOperation(command string) *SemanticOperationBuilder {
	sob.AddReadOperation("/dev/stdin", "stdin")
	sob.WithCommandInfo(command)
	sob.WithOverApproximated() // stdin is always over-approximated
	return sob
}

// AddSystemInfoReadOperation adds a system information read operation
func (sob *SemanticOperationBuilder) AddSystemInfoReadOperation(command string) *SemanticOperationBuilder {
	sob.AddReadOperation("/proc/sys/kernel/version", "system_info")
	sob.WithCommandInfo(command)
	sob.WithOverApproximated() // System info is always over-approximated
	return sob
}

// FilePathUtils provides utilities for handling file paths in semantic operations
func (pu *ParserUtils) FilePathUtils() *FilePathUtils {
	return &FilePathUtils{}
}

// FilePathUtils provides utilities for file path manipulation
type FilePathUtils struct{}

// EnsureAbsolutePath ensures a path is absolute, converting relative paths if needed
func (fpu *FilePathUtils) EnsureAbsolutePath(basePath string, targetPath string) string {
	if strings.HasPrefix(targetPath, "/") {
		return targetPath
	}
	// Simple implementation - in real use would handle path joining properly
	if basePath == "." || basePath == "" {
		return "./" + targetPath
	}
	return basePath + "/" + targetPath
}

// AddWildcard adds wildcard patterns to paths for conservative approximation
func (fpu *FilePathUtils) AddWildcard(path string) string {
	if strings.HasSuffix(path, "/") {
		return path + "*"
	}
	return path + "/*"
}

// AddRecursiveWildcard adds recursive wildcard patterns
func (fpu *FilePathUtils) AddRecursiveWildcard(path string) string {
	if strings.HasSuffix(path, "/") {
		return path + "**/*"
	}
	return path + "/**/*"
}

// IsStdPath checks if a path is a standard input/output path
func (fpu *FilePathUtils) IsStdPath(path string) bool {
	return path == "/dev/stdin" || path == "/dev/stdout" || path == "/dev/stderr"
}

// CommandValidationUtils provides utilities for validating command safety
func (pu *ParserUtils) CommandValidationUtils() *CommandValidationUtils {
	return &CommandValidationUtils{}
}

// CommandValidationUtils provides utilities for command validation
type CommandValidationUtils struct{}

// IsDangerousOption checks if an option is potentially dangerous
func (cvu *CommandValidationUtils) IsDangerousOption(opt string) bool {
	dangerousOptions := map[string]bool{
		"--install": true,
		"-i": true, // in-place editing
		"--in-place": true,
		"-f": true, // script file (potentially dangerous)
		"--exec": true,
		"--delete": true,
	}
	return dangerousOptions[opt]
}

// IsWriteOperation checks if an operation type is a write operation
func (cvu *CommandValidationUtils) IsWriteOperation(opType OperationType) bool {
	return opType == OpWrite || opType == OpCreate || opType == OpEdit
}

// GetOperationRiskScore calculates a risk score for an operation
func (cvu *CommandValidationUtils) GetOperationRiskScore(op SemanticOperation) int {
	riskScore := 0

	// Base score by operation type
	switch op.OperationType {
	case OpRead:
		riskScore = 1
	case OpWrite, OpEdit:
		riskScore = 3
	case OpCreate:
		riskScore = 2
	case OpExecute:
		riskScore = 5 // Execute operations are very risky
	}

	// Adjust for parameters
	if op.Parameters != nil {
		if dangerous, ok := op.Parameters["dangerous"].(bool); ok && dangerous {
			riskScore += 5
		}
		if overApprox, ok := op.Parameters["over_approximated"].(bool); ok && overApprox {
			riskScore += 2
		}
		if precise, ok := op.Parameters["precise"].(bool); ok && precise {
			riskScore -= 1 // Precise operations are slightly less risky
		}
	}

	// Adjust for target path patterns
	if strings.Contains(op.TargetPath, "*") || strings.Contains(op.TargetPath, "*") {
		riskScore += 1
	}

	return riskScore
}

// ShellParsingUtils provides utilities for parsing shell commands
func (pu *ParserUtils) ShellParsingUtils() *ShellParsingUtils {
	return &ShellParsingUtils{}
}

// ShellParsingUtils provides utilities for parsing shell commands
type ShellParsingUtils struct{}

// ParseShellCommand parses a simple shell command line
func (spu *ShellParsingUtils) ParseShellCommand(command string) (string, []string, error) {
	// Simple shell command parsing - split on whitespace
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("empty command")
	}

	cmd := parts[0]
	args := []string{}
	if len(parts) > 1 {
		args = parts[1:]
	}

	return cmd, args, nil
}

// IsShellCommandSafe checks if a shell command is potentially safe
func (spu *ShellParsingUtils) IsShellCommandSafe(command string) bool {
	// Basic safety check - look for dangerous patterns
	dangerousPatterns := []string{
		";", "&&", "||", "|", "`", "$", ">", "<", "&",
		"rm", "mv", "cp", "chmod", "chown", "dd", "mkfs", "fdisk",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(command, pattern) {
			return false
		}
	}

	return true
}

// ExtractShellCommandsFromHereDoc extracts shell commands from HERE document content
func (spu *ShellParsingUtils) ExtractShellCommandsFromHereDoc(content string) []string {
	lines := strings.Split(content, "\n")
	commands := []string{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Skip comments
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Look for lines that start with commands
		if !strings.HasPrefix(trimmed, "$") && !strings.Contains(trimmed, "=") {
			commands = append(commands, trimmed)
		}
	}

	return commands
}

// PythonParsingUtils provides utilities for parsing Python code
func (pu *ParserUtils) PythonParsingUtils() *PythonParsingUtils {
	return &PythonParsingUtils{}
}

// PythonParsingUtils provides utilities for parsing Python code
type PythonParsingUtils struct{}

// ParsePythonCode parses Python code to extract basic information
func (ppu *PythonParsingUtils) ParsePythonCode(code string) ([]string, []string, error) {
	lines := strings.Split(code, "\n")
	imports := []string{}
	statements := []string{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Skip comments
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Extract imports
		if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "from ") {
			imports = append(imports, trimmed)
		} else if strings.Contains(trimmed, "=") || strings.HasPrefix(trimmed, "def ") ||
			strings.HasPrefix(trimmed, "class ") || strings.HasPrefix(trimmed, "if ") ||
			strings.HasPrefix(trimmed, "for ") || strings.HasPrefix(trimmed, "while ") {
			statements = append(statements, trimmed)
		}
	}

	return imports, statements, nil
}

// IsPythonCodeSafe checks if Python code is potentially safe
func (ppu *PythonParsingUtils) IsPythonCodeSafe(code string) bool {
	// Basic safety check - look for dangerous patterns
	dangerousPatterns := []string{
		"__import__", "exec(", "eval(", "open(", "os.", "subprocess.",
		"system(", "popen(", "remove(", "unlink(", "rmdir(", "mkdir(",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(code, pattern) {
			return false
		}
	}

	return true
}

// ExtractPythonCodeFromHereDoc extracts Python code from HERE document content
func (ppu *PythonParsingUtils) ExtractPythonCodeFromHereDoc(content string) []string {
	lines := strings.Split(content, "\n")
	pythonLines := []string{}

	inPythonBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Look for Python code markers
		if strings.Contains(trimmed, "python3 -c") || strings.Contains(trimmed, "python -c") {
			inPythonBlock = true
			continue
		}

		if inPythonBlock {
			if trimmed == "" {
				continue
			}

			// End of Python block - simplified check
			if strings.HasSuffix(trimmed, "\\") || strings.HasSuffix(trimmed, "'") {
				pythonLines = append(pythonLines, trimmed)
				inPythonBlock = false
				continue
			}

			pythonLines = append(pythonLines, trimmed)
		}
	}

	return pythonLines
}

// HereDocUtils provides utilities for parsing HERE documents
func (pu *ParserUtils) HereDocUtils() *HereDocUtils {
	return &HereDocUtils{}
}

// HereDocUtils provides utilities for HERE document parsing
type HereDocUtils struct{}

// ExtractHereDocContent extracts content from HERE document syntax
func (hdu *HereDocUtils) ExtractHereDocContent(command string) (string, string, bool) {
	// Look for HERE document patterns: command << DELIMITER ... DELIMITER
	lines := strings.Split(command, "\n")
	if len(lines) < 2 {
		return "", "", false
	}

	// Check for << operator
	for i, line := range lines {
		if strings.Contains(line, "<<") {
			// Extract delimiter
			parts := strings.Fields(line)
			if len(parts) < 2 {
				return "", "", false
			}

			delimiter := parts[len(parts)-1]
			if delimiter == "-" && len(parts) > 2 {
				delimiter = parts[len(parts)-2]
			}

			// Find content until delimiter
			contentLines := []string{}
			for j := i + 1; j < len(lines); j++ {
				if strings.TrimSpace(lines[j]) == delimiter {
					return strings.TrimSpace(lines[i]), strings.Join(contentLines, "\n"), true
				}
				contentLines = append(contentLines, lines[j])
			}
		}
	}

	return "", "", false
}

// IsHereDocSafe checks if HERE document content is potentially safe
func (hdu *HereDocUtils) IsHereDocSafe(content string) bool {
	// Basic safety check - look for dangerous patterns
	dangerousPatterns := []string{
		"rm -rf", "mv ", "cp ", "chmod ", "chown ", "dd ", "mkfs ", "fdisk ",
		"`", "$", ">", "<", "&", "|", ";", "&&", "||",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(content, pattern) {
			return false
		}
	}

	return true
}

// Global instance for easy access
var ParserUtilsInstance = &ParserUtils{}
