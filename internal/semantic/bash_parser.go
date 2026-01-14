package semantic

import (
	"fmt"
	"strings"
)

// BashCommand represents a parsed bash command
type BashCommand struct {
	Script              string
	Options             map[string]interface{}
	CommandLine         string
	HasExecution        bool
	HasSubshell         bool
	HasChaining         bool
	HasPipes            bool
	HasRedirections     bool
	HasEnvironmentVariables bool
	HasSourceCommands   bool
	HasLoops            bool
	HasConditionals     bool
	IndividualCommands []string
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
		cmd.HasChaining = b.hasCommandChaining(cmd.Script)
		cmd.HasPipes = b.hasPipes(cmd.Script)
		cmd.HasRedirections = b.hasRedirections(cmd.Script)
		cmd.HasEnvironmentVariables = b.hasEnvironmentVariables(cmd.Script)
		cmd.HasSourceCommands = b.hasSourceCommands(cmd.Script)
		cmd.HasLoops = b.hasLoops(cmd.Script)
		cmd.HasConditionals = b.hasConditionals(cmd.Script)

		// Parse individual commands for more detailed analysis
		cmd.IndividualCommands = b.parseComplexScript(cmd.Script)
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

// hasCommandChaining checks if script contains command chaining patterns
func (b *BashParser) hasCommandChaining(script string) bool {
	chainingPatterns := []string{
		"&&", "||", ";", "&",
	}

	for _, pattern := range chainingPatterns {
		if strings.Contains(script, pattern) {
			return true
		}
	}
	return false
}

// hasPipes checks if script contains pipe patterns
func (b *BashParser) hasPipes(script string) bool {
	return strings.Contains(script, "|")
}

// hasRedirections checks if script contains redirection patterns
func (b *BashParser) hasRedirections(script string) bool {
	redirectionPatterns := []string{
		">", "<", ">>", "2>", "&>",
	}

	for _, pattern := range redirectionPatterns {
		if strings.Contains(script, pattern) {
			return true
		}
	}
	return false
}

// hasEnvironmentVariables checks if script contains environment variable patterns
func (b *BashParser) hasEnvironmentVariables(script string) bool {
	// Look for export statements and variable assignments
	return strings.Contains(script, "export ") ||
	       strings.Contains(script, "=") && strings.Contains(script, "$") ||
	       strings.Contains(script, "PATH=") ||
	       strings.Contains(script, "VENV=") ||
	       strings.Contains(script, "PYTHON=")
}

// hasSourceCommands checks if script contains source commands
func (b *BashParser) hasSourceCommands(script string) bool {
	// Look for source commands: ., source
	lines := strings.Split(script, "\n")
	for _, line := range lines {
			trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ". ") ||
		   strings.HasPrefix(trimmed, "source ") ||
		   strings.HasPrefix(trimmed, "./") ||
		   strings.Contains(trimmed, " . ") ||
		   strings.Contains(trimmed, " source ") {
			return true
		}
	}
	return false
}

// hasLoops checks if script contains loop patterns
func (b *BashParser) hasLoops(script string) bool {
	loopPatterns := []string{
		"for ", "while ", "until ", "do", "done",
	}

	for _, pattern := range loopPatterns {
		if strings.Contains(script, pattern) {
			return true
		}
	}
	return false
}

// hasConditionals checks if script contains conditional patterns
func (b *BashParser) hasConditionals(script string) bool {
	// Check for conditional patterns with more context to avoid false positives
	conditionalPatterns := []string{
		"if ", "then", "else ", "elif ", " fi",
		"case ", " esac", "[[ ", "[ ", "]]",
	}

	for _, pattern := range conditionalPatterns {
		if strings.Contains(script, pattern) {
			return true
		}
	}
	return false
}

// HasPythonCommands checks if script contains Python commands
func (b *BashParser) HasPythonCommands(script string) bool {
	pythonPatterns := []string{
		"python ", "python3 ", "python -c", "python3 -c",
	}

	for _, pattern := range pythonPatterns {
		if strings.Contains(script, pattern) {
			return true
		}
	}
	return false
}

// parseComplexScript breaks down complex bash scripts into individual commands
func (b *BashParser) parseComplexScript(script string) []string {
	// This is a simplified parser that splits on common separators
	// For a full implementation, a proper shell parser would be needed

	commands := []string{}

	// Replace common chaining operators with temporary tokens to preserve them
	tempScript := strings.ReplaceAll(script, "&&", " __AND__ ")
	tempScript = strings.ReplaceAll(tempScript, "||", " __OR__ ")

	// Split on newlines first
	lines := strings.Split(tempScript, "\n")

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Split on semicolons
		semiParts := strings.Split(line, ";")
		for _, semiPart := range semiParts {
			if strings.TrimSpace(semiPart) == "" {
				continue
			}

			// Split on our temporary AND token
			andParts := strings.Split(semiPart, "__AND__")
			for _, andPart := range andParts {
				if strings.TrimSpace(andPart) == "" {
					continue
				}

				// Split on pipes
				pipeParts := strings.Split(andPart, "|")
				for i, pipePart := range pipeParts {
					trimmed := strings.TrimSpace(pipePart)
					if trimmed != "" {
						if i > 0 {
							commands = append(commands, "|")
						}
						commands = append(commands, trimmed)
					}
				}
			}
		}
	}

	return commands
}

// GetSemanticOperations implements CommandParser for bash commands
func (b *BashParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*BashCommand)
	if !ok {
		return nil, fmt.Errorf("invalid bash command type")
	}

	builder := ParserUtilsInstance.SemanticOperationBuilder()

	// Detect additional patterns in the script
	hasChaining := b.hasCommandChaining(cmd.Script)
	hasPipes := b.hasPipes(cmd.Script)
	hasRedirections := b.hasRedirections(cmd.Script)
	hasEnvironmentVariables := b.hasEnvironmentVariables(cmd.Script)
	hasSourceCommands := b.hasSourceCommands(cmd.Script)
	hasLoops := b.hasLoops(cmd.Script)
	hasConditionals := b.hasConditionals(cmd.Script)

	// Parse complex scripts into individual commands for more precise analysis
	individualCommands := b.parseComplexScript(cmd.Script)

	// Bash commands are inherently dangerous due to execution capabilities
	builder.AddExecuteOperation("bash_script", "bash_execution")
	builder.WithCommandInfo("bash")
	builder.WithParameter("script", cmd.Script)
	builder.WithParameter("has_execution", cmd.HasExecution)
	builder.WithParameter("has_subshell", cmd.HasSubshell)
	builder.WithParameter("has_chaining", hasChaining)
	builder.WithParameter("has_pipes", hasPipes)
	builder.WithParameter("has_redirections", hasRedirections)
	builder.WithParameter("has_environment_variables", hasEnvironmentVariables)
	builder.WithParameter("has_source_commands", hasSourceCommands)
	builder.WithParameter("has_loops", hasLoops)
	builder.WithParameter("has_conditionals", hasConditionals)
	builder.WithParameter("dangerous", true)
	builder.WithParameter("over_approximated", true)

	// Add operations for each individual command in the script
	for i, individualCmd := range individualCommands {
		if individualCmd == "|" {
			// Pipe operation
			builder.AddExecuteOperation("pipe_operation", "bash_pipe")
			builder.WithCommandInfo("bash")
			builder.WithParameter("command_index", i)
			builder.WithParameter("dangerous", true)
			continue
		}

		// For each command, add appropriate operations
		builder.AddExecuteOperation(individualCmd, "bash_individual_command")
		builder.WithCommandInfo("bash")
		builder.WithParameter("command_index", i)
		builder.WithParameter("original_script", cmd.Script)

		// Check if this individual command contains dangerous patterns
		if b.hasExecutionPatterns(individualCmd) || b.hasSubshellPatterns(individualCmd) {
			builder.WithParameter("dangerous", true)
		} else {
			builder.WithParameter("dangerous", false)
		}
	}

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

	// If environment variables are detected, add specific operations
	if hasEnvironmentVariables {
		builder.AddReadOperation("$ENV", "bash_environment_variables")
		builder.WithCommandInfo("bash")
		builder.WithParameter("dangerous", true)
		builder.WithParameter("over_approximated", true)
		builder.WithParameter("description", "Environment variable manipulation")
	}

	// If source commands are detected, add specific operations
	if hasSourceCommands {
		builder.AddExecuteOperation("source_script", "bash_source_command")
		builder.WithCommandInfo("bash")
		builder.WithParameter("dangerous", true)
		builder.WithParameter("over_approximated", true)
		builder.WithParameter("description", "Script sourcing can execute arbitrary code")
	}

	// If loops are detected, add specific operations
	if hasLoops {
		builder.AddExecuteOperation("loop_construct", "bash_loop")
		builder.WithCommandInfo("bash")
		builder.WithParameter("dangerous", true)
		builder.WithParameter("over_approximated", true)
		builder.WithParameter("description", "Loops can execute commands repeatedly")
	}

	// If conditionals are detected, add specific operations
	if hasConditionals {
		builder.AddExecuteOperation("conditional_construct", "bash_conditional")
		builder.WithCommandInfo("bash")
		builder.WithParameter("dangerous", true)
		builder.WithParameter("over_approximated", true)
		builder.WithParameter("description", "Conditionals can execute different code paths")
	}

	// If redirections are detected, add specific operations
	if hasRedirections {
		builder.AddWriteOperation("redirection_target", "bash_redirection")
		builder.WithCommandInfo("bash")
		builder.WithParameter("dangerous", true)
		builder.WithParameter("over_approximated", true)
	}

	// Check for Python commands and add specific Python analysis
	if b.HasPythonCommands(cmd.Script) {
		pythonUtils := ParserUtilsInstance.PythonParsingUtils()
		pythonLines := pythonUtils.ExtractPythonCodeFromHereDoc(cmd.Script)

		if len(pythonLines) > 0 {
			// Analyze the extracted Python code
			pythonCode := strings.Join(pythonLines, "\n")
			isSafe := pythonUtils.IsPythonCodeSafe(pythonCode)

			builder.AddExecuteOperation("python_code", "bash_python_execution")
			builder.WithCommandInfo("bash")
			builder.WithParameter("python_code_detected", true)
			builder.WithParameter("python_code_safe", isSafe)
			builder.WithParameter("dangerous", !isSafe)
			builder.WithParameter("over_approximated", true)
			builder.WithParameter("description", "Python code execution detected")

			// Add more detailed analysis
			imports, statements, _ := pythonUtils.ParsePythonCode(pythonCode)
			if len(imports) > 0 {
				builder.WithParameter("python_imports", imports)
			}
			if len(statements) > 0 {
				builder.WithParameter("python_statements", statements)
			}
		}
	}

	return builder.Build(), nil
}

// NewBashParser creates a new BashParser instance
func NewBashParser() *BashParser {
	return &BashParser{}
}