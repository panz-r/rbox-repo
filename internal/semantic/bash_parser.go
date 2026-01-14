package semantic

import (
	"fmt"
	"strings"
)

// BashCommand represents a parsed bash command
type BashCommand struct {
	Script       string
	Options      map[string]interface{}
	CommandLine  string
	HasExecution bool
	HasSubshell  bool
}

// BashParser parses bash commands
type BashParser struct{}

// ParseArguments implements CommandParser for bash commands
func (b *BashParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for bash")
	}

	cmd := &BashCommand{
		Options: make(map[string]interface{}),
	}

	// Parse bash options
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-c":
			// Command string follows
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing command after -c option")
			}
			cmd.Script = args[i+1]
			cmd.CommandLine = args[i+1]
			cmd.Options["command"] = args[i+1]
			i += 2
			continue
		case "-s":
			cmd.Options["read_from_stdin"] = true
		case "-i":
			cmd.Options["interactive"] = true
		case "-l":
			cmd.Options["login"] = true
		case "-r":
			cmd.Options["restricted"] = true
		default:
			// Unknown option, store it
			cmd.Options[opt] = true
		}
		i++
	}

	// If no -c option, remaining arguments form the command
	if cmd.Script == "" && i < len(args) {
		cmd.CommandLine = strings.Join(args[i:], " ")
		cmd.Script = cmd.CommandLine
		cmd.Options["command"] = cmd.CommandLine
	}

	// Analyze script for dangerous patterns
	if cmd.Script != "" {
		cmd.HasExecution = b.hasExecutionPatterns(cmd.Script)
		cmd.HasSubshell = b.hasSubshellPatterns(cmd.Script)
	}

	return cmd, nil
}

// hasExecutionPatterns checks if script contains execution patterns
func (b *BashParser) hasExecutionPatterns(script string) bool {
	dangerousPatterns := []string{
		"exec", "eval", "source", ". ", "`", "$(",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(script, pattern) {
			return true
		}
	}
	return false
}

// hasSubshellPatterns checks if script contains subshell patterns
func (b *BashParser) hasSubshellPatterns(script string) bool {
	subshellPatterns := []string{
		"(", "`", "$(",
	}

	for _, pattern := range subshellPatterns {
		if strings.Contains(script, pattern) {
			return true
		}
	}
	return false
}

// GetSemanticOperations implements CommandParser for bash commands
func (b *BashParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*BashCommand)
	if !ok {
		return nil, fmt.Errorf("invalid bash command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// Bash commands are inherently dangerous due to execution capabilities
	builder.AddExecuteOperation("bash_script", "bash_execution")
	builder.WithCommandInfo("bash")
	builder.WithParameter("script", cmd.Script)
	builder.WithParameter("has_execution", cmd.HasExecution)
	builder.WithParameter("has_subshell", cmd.HasSubshell)
	builder.WithParameter("dangerous", true)
	builder.WithParameter("over_approximated", true)

	// If there's a script file reference, add read operation
	if scriptFile, ok := cmd.Options["command_file"]; ok {
		builder.AddReadOperation(scriptFile.(string), "bash_script_file")
		builder.WithCommandInfo("bash")
		builder.WithOverApproximated()
	}

	// Conservative: assume bash might read/write various files
	builder.AddReadOperation("*", "bash_potential_reads")
	builder.WithCommandInfo("bash")
	builder.WithParameter("over_approximated", true)

	builder.AddWriteOperation("*", "bash_potential_writes")
	builder.WithCommandInfo("bash")
	builder.WithParameter("over_approximated", true)
	builder.WithParameter("dangerous", true)

	return builder.Build(), nil
}

// NewBashParser creates a new BashParser instance
func NewBashParser() *BashParser {
	return &BashParser{}
}