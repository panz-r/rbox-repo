package semantic

import (
	"fmt"
	"regexp"
	"strings"
)

// ShellCodeAnalyzer defines the interface for shell code analysis
type ShellCodeAnalyzer interface {
	Parse(code string) ([]ShellCommand, error)
	IsSafe(code string) (bool, SafetyReport)
	ExtractDangerousPatterns(code string) []DangerousPattern
	GetSemanticOperations(code string) ([]SemanticOperation, error)
}

// ShellCommand represents a parsed shell command
type ShellCommand struct {
	Command              string
	Arguments            []string
	Redirections         []Redirection
	Pipes                []Pipe
	Subshells            []ShellCommand
	IsDangerous          bool
	DangerousPatterns    []string
	Line                 int
	Column               int
	EndLine              int
	CommandSubstitutions []string
}

// Redirection represents shell I/O redirection
type Redirection struct {
	Type        string // ">", "<", ">>", "2>", etc.
	Target      string
	IsDangerous bool
	Line        int
}

// Pipe represents shell command piping
type Pipe struct {
	FromCommand string
	ToCommand   string
	Position    int
}

// DangerousPattern describes a dangerous pattern found in code
type DangerousPattern struct {
	Pattern     string
	Location    CodeLocation
	Severity    string // "low", "medium", "high", "critical"
	Description string
	Category    string // "execution", "file_operation", "network", etc.
}

// CodeLocation specifies where a pattern was found
type CodeLocation struct {
	Line   int
	Column int
	Length int
}

// SafetyReport provides detailed safety analysis
type SafetyReport struct {
	IsSafe            bool
	DangerousPatterns []DangerousPattern
	RiskScore         int // 0-100
	Recommendations   []string
}

// NewShellCodeAnalyzer creates a new shell code analyzer
func NewShellCodeAnalyzer() ShellCodeAnalyzer {
	return &shellAnalyzer{
		dangerousCommands: map[string]bool{
			"rm": true, "mv": true, "cp": true, "dd": true, "chmod": true, "chown": true,
			"mkdir": true, "rmdir": true, "ln": true, "touch": true,
			"wget": true, "curl": true, "scp": true, "rsync": true, "ssh": true,
			"mkfs": true, "fdisk": true, "format": true,
			"systemctl": true, "service": true,
			"kill": true, "pkill": true, "killall": true,
			"mount": true, "umount": true,
			"eval": true, "exec": true, "source": true,
			"tee": true,
		},
		dangerousPatterns: []*regexp.Regexp{
			regexp.MustCompile(`rm\s+-rf?\s+/\*?`),
			regexp.MustCompile(`rm\s+-rf?\s+\S+`),
			regexp.MustCompile(`>\s*/\S+`),
			regexp.MustCompile(`>>\s*/\S+`),
			regexp.MustCompile(`\|\s*tee\s`),
			regexp.MustCompile(`\$\(\s*(?:rm|cp|mv|dd|chmod|chown|wget|curl)`),
			regexp.MustCompile("`\\s*(?:rm|cp|mv|dd|chmod|chown|wget|curl)\\s"),
			regexp.MustCompile(`chmod\s+[0-7][0-7][0-7][0-7]\s`),
			regexp.MustCompile(`dd\s+if=/dev/\w+`),
			regexp.MustCompile(`sed\s+-i\s+[^;]*`),
			regexp.MustCompile(`find\s+.*-exec\s+.*\{}\s*;`),
			regexp.MustCompile(`find\s+.*-delete\b`),
			regexp.MustCompile(`find\s+.*-execdir\b`),
			regexp.MustCompile(`find\s+.*-okdir\b`),
			regexp.MustCompile(`find\s+.*-exec\s+.*\;`),
			regexp.MustCompile(`>\s*\|`),
			regexp.MustCompile(`\|\s*>\s*\S+`),
			regexp.MustCompile(`exec\s+`),
			regexp.MustCompile(`nohup\s+`),
			regexp.MustCompile(`source\s+\./`),
			regexp.MustCompile(`\.\s+\./`),
		},
		safeCommands: map[string]bool{
			"cat": true, "less": true, "more": true, "head": true, "tail": true,
			"grep": true, "egrep": true, "fgrep": true, "awk": true, "sed": true,
			"sort": true, "uniq": true, "wc": true, "cut": true, "tr": true,
			"find": true, "xargs": true, "echo": true, "printf": true,
			"pwd": true, "ls": true, "cd": true, "true": true, "false": true,
			"test": true, "[": true, "]": true, "expr": true,
			"basename": true, "dirname": true, "realpath": true,
			"stat": true, "file": true,
			"column": true, "paste": true, "join": true,
			"diff": true, "cmp": true,
			"tar": true, "gzip": true, "bzip2": true, "xz": true, "zip": true,
		},
	}
}

type shellAnalyzer struct {
	dangerousCommands map[string]bool
	dangerousPatterns []*regexp.Regexp
	safeCommands      map[string]bool
}

// Parse extracts commands and structure from shell code
func (sa *shellAnalyzer) Parse(code string) ([]ShellCommand, error) {
	commands := make([]ShellCommand, 0)

	// Handle command chaining with && and ||
	chainedCommands := sa.splitByChaining(code)
	lineNum := 0

	for _, chunk := range chainedCommands {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}

		// Handle for loops specially
		if strings.HasPrefix(chunk, "for ") {
			forCmds := sa.parseForLoop(chunk)
			for i := range forCmds {
				forCmds[i].Line = lineNum
			}
			commands = append(commands, forCmds...)
			lineNum++
			continue
		}

		// Handle while/until loops
		if strings.HasPrefix(chunk, "while ") || strings.HasPrefix(chunk, "until ") {
			whileCmds := sa.parseWhileLoop(chunk)
			for i := range whileCmds {
				whileCmds[i].Line = lineNum
			}
			commands = append(commands, whileCmds...)
			lineNum++
			continue
		}

		// Handle if statements
		if strings.HasPrefix(chunk, "if ") {
			ifCmds := sa.parseIfStatement(chunk)
			for i := range ifCmds {
				ifCmds[i].Line = lineNum
			}
			commands = append(commands, ifCmds...)
			lineNum++
			continue
		}

		// Handle case statements
		if strings.HasPrefix(chunk, "case ") {
			caseCmds := sa.parseCaseStatement(chunk)
			for i := range caseCmds {
				caseCmds[i].Line = lineNum
			}
			commands = append(commands, caseCmds...)
			lineNum++
			continue
		}

		// Handle function definitions
		if strings.HasPrefix(chunk, "function ") || strings.HasPrefix(chunk, "() {") {
			lineNum++
			continue // Skip function definitions for now
		}

		// Handle export statements
		if strings.HasPrefix(chunk, "export ") {
			exportCmd := sa.parseExportStatement(chunk)
			exportCmd.Line = lineNum
			commands = append(commands, exportCmd)
			lineNum++
			continue
		}

		// Handle source (.) commands - check for dangerous source
		if strings.HasPrefix(chunk, "source ") || (len(chunk) > 1 && chunk[0] == '.' && (chunk[1] == ' ' || chunk[1] == '\t')) {
			sourceCmd := sa.parseSourceCommand(chunk)
			sourceCmd.Line = lineNum
			commands = append(commands, sourceCmd)
			lineNum++
			continue
		}

		// Handle cd commands
		if strings.HasPrefix(chunk, "cd ") {
			cdCmd := sa.parseCdCommand(chunk)
			cdCmd.Line = lineNum
			commands = append(commands, cdCmd)
			lineNum++
			continue
		}

		// Handle regular commands
		cmd := sa.parseLine(chunk, lineNum)
		commands = append(commands, cmd)
		lineNum++
	}

	return commands, nil
}

// splitByChaining splits code by && and || operators
func (sa *shellAnalyzer) splitByChaining(code string) []string {
	var result []string
	current := ""
	depth := 0
	inSingleQuote := false
	inDoubleQuote := false

	for _, c := range code {
		switch c {
		case '\'':
			if !inDoubleQuote {
				inSingleQuote = !inSingleQuote
			}
		case '"':
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
		case '(':
			if !inSingleQuote && !inDoubleQuote {
				depth++
			}
		case ')':
			if !inSingleQuote && !inDoubleQuote && depth > 0 {
				depth--
			}
		case ';':
			if !inSingleQuote && !inDoubleQuote && depth == 0 {
				if strings.TrimSpace(current) != "" {
					result = append(result, current)
				}
				current = ""
				continue
			}
		case '&':
			if !inSingleQuote && !inDoubleQuote && depth == 0 {
				if len(current) > 0 && current[len(current)-1] == '&' {
					// Found && or &
					if strings.TrimSpace(current[:len(current)-1]) != "" {
						result = append(result, current[:len(current)-1])
					}
					current = ""
					continue
				}
			}
		case '|':
			if !inSingleQuote && !inDoubleQuote && depth == 0 {
				if len(current) > 0 && current[len(current)-1] == '|' {
					// Found ||
					if strings.TrimSpace(current[:len(current)-1]) != "" {
						result = append(result, current[:len(current)-1])
					}
					current = ""
					continue
				}
			}
		}
		current += string(c)
	}

	if strings.TrimSpace(current) != "" {
		result = append(result, current)
	}

	return result
}

// parseForLoop parses a bash for loop
func (sa *shellAnalyzer) parseForLoop(code string) []ShellCommand {
	commands := make([]ShellCommand, 0)

	// Extract variable and items
	forPattern := regexp.MustCompile(`for\s+(\w+)\s+in\s+(.+?)\s*(?:;|do|$)`)
	matches := forPattern.FindStringSubmatch(code)

	if len(matches) >= 3 {
		variable := matches[1]
		items := matches[2]

		// Create a command representing the for loop
		cmd := ShellCommand{
			Command:           "for",
			Arguments:         []string{variable, "in", items},
			IsDangerous:       false,
			DangerousPatterns: make([]string, 0),
			Line:              1,
		}

		// Check if loop body contains dangerous commands
		bodyPattern := regexp.MustCompile(`do\s+(.+?)\s+done`)
		bodyMatches := bodyPattern.FindStringSubmatch(code)
		if len(bodyMatches) >= 2 {
			body := bodyMatches[1]
			for _, pattern := range sa.dangerousPatterns {
				if pattern.MatchString(body) {
					cmd.IsDangerous = true
					cmd.DangerousPatterns = append(cmd.DangerousPatterns, "for loop with dangerous body")
					break
				}
			}

			// Check for dangerous commands in body
			for cmdName := range sa.dangerousCommands {
				if strings.Contains(body, cmdName+" ") || strings.Contains(body, cmdName+";") {
					cmd.IsDangerous = true
					cmd.DangerousPatterns = append(cmd.DangerousPatterns, fmt.Sprintf("for loop contains dangerous command: %s", cmdName))
				}
			}
		}

		commands = append(commands, cmd)
	}

	return commands
}

// parseWhileLoop parses a bash while/until loop
func (sa *shellAnalyzer) parseWhileLoop(code string) []ShellCommand {
	commands := make([]ShellCommand, 0)

	cmd := ShellCommand{
		Command:           "while",
		Arguments:         []string{code},
		IsDangerous:       false,
		DangerousPatterns: make([]string, 0),
		Line:              1,
	}

	// Check for dangerous commands in loop body
	bodyPattern := regexp.MustCompile(`do\s+(.+?)\s+done`)
	bodyMatches := bodyPattern.FindStringSubmatch(code)
	if len(bodyMatches) >= 2 {
		body := bodyMatches[1]
		for cmdName := range sa.dangerousCommands {
			if strings.Contains(body, cmdName+" ") || strings.Contains(body, cmdName+";") {
				cmd.IsDangerous = true
				cmd.DangerousPatterns = append(cmd.DangerousPatterns, fmt.Sprintf("while loop contains dangerous command: %s", cmdName))
			}
		}
	}

	commands = append(commands, cmd)
	return commands
}

// parseIfStatement parses a bash if statement
func (sa *shellAnalyzer) parseIfStatement(code string) []ShellCommand {
	commands := make([]ShellCommand, 0)

	cmd := ShellCommand{
		Command:           "if",
		Arguments:         []string{code},
		IsDangerous:       false,
		DangerousPatterns: make([]string, 0),
		Line:              1,
	}

	// Check for dangerous commands in then/fi blocks
	thenPattern := regexp.MustCompile(`then\s+(.+?)(?:elif|else|fi)`)
	thenMatches := thenPattern.FindStringSubmatch(code)
	if len(thenMatches) >= 2 {
		thenBody := thenMatches[1]
		for cmdName := range sa.dangerousCommands {
			if strings.Contains(thenBody, cmdName+" ") || strings.Contains(thenBody, cmdName+";") {
				cmd.IsDangerous = true
				cmd.DangerousPatterns = append(cmd.DangerousPatterns, fmt.Sprintf("if statement contains dangerous command: %s", cmdName))
			}
		}
	}

	commands = append(commands, cmd)
	return commands
}

// parseCaseStatement parses a bash case statement
func (sa *shellAnalyzer) parseCaseStatement(code string) []ShellCommand {
	commands := make([]ShellCommand, 0)

	cmd := ShellCommand{
		Command:           "case",
		Arguments:         []string{code},
		IsDangerous:       false,
		DangerousPatterns: make([]string, 0),
		Line:              1,
	}

	commands = append(commands, cmd)
	return commands
}

// parseExportStatement parses an export statement
func (sa *shellAnalyzer) parseExportStatement(code string) ShellCommand {
	// Extract variable names from export
	exportPattern := regexp.MustCompile(`export\s+([\w=-]+(?:\s+[\w=-]+)*)`)
	matches := exportPattern.FindStringSubmatch(code)

	cmd := ShellCommand{
		Command:           "export",
		Arguments:         []string{code},
		IsDangerous:       false,
		DangerousPatterns: make([]string, 0),
		Line:              1,
	}

	if len(matches) >= 2 {
		vars := strings.Fields(matches[1])
		cmd.Arguments = vars

		// Check for dangerous exports
		for _, v := range vars {
			if strings.HasPrefix(v, "PATH=") || strings.HasPrefix(v, "LD_") {
				cmd.IsDangerous = true
				cmd.DangerousPatterns = append(cmd.DangerousPatterns, fmt.Sprintf("export of sensitive variable: %s", v))
			}
		}
	}

	return cmd
}

// parseSourceCommand parses a source (.) command
func (sa *shellAnalyzer) parseSourceCommand(code string) ShellCommand {
	cmd := ShellCommand{
		Command:           "source",
		Arguments:         strings.Fields(code),
		IsDangerous:       false,
		DangerousPatterns: make([]string, 0),
		Line:              1,
	}

	// Check if sourcing a relative path (potentially dangerous)
	for _, arg := range cmd.Arguments {
		if strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") {
			cmd.IsDangerous = true
			cmd.DangerousPatterns = append(cmd.DangerousPatterns, fmt.Sprintf("source command with relative path: %s", arg))
			break
		}
	}

	return cmd
}

// parseCdCommand parses a cd command
func (sa *shellAnalyzer) parseCdCommand(code string) ShellCommand {
	cmd := ShellCommand{
		Command:           "cd",
		Arguments:         strings.Fields(code),
		IsDangerous:       false,
		DangerousPatterns: make([]string, 0),
		Line:              1,
	}

	// Check if cd to absolute path outside safe areas
	if len(cmd.Arguments) > 1 {
		path := cmd.Arguments[1]
		if strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "/tmp/") && path != "/tmp" {
			dangerousPrefixes := []string{"/etc/", "/root/", "/boot/", "/proc/", "/sys/", "/dev/"}
			for _, prefix := range dangerousPrefixes {
				if strings.HasPrefix(path, prefix) {
					cmd.IsDangerous = true
					cmd.DangerousPatterns = append(cmd.DangerousPatterns, fmt.Sprintf("cd to dangerous path: %s", path))
					break
				}
			}
		}
	}

	return cmd
}

func (sa *shellAnalyzer) parseLine(line string, lineNum int) ShellCommand {
	cmd := ShellCommand{
		Line:              lineNum,
		DangerousPatterns: make([]string, 0),
	}

	// Check for here documents
	if strings.HasSuffix(line, "<<") || strings.HasSuffix(line, "<<") {
		line = strings.TrimSuffix(strings.TrimSuffix(line, "<<"), "<<")
		line = strings.TrimSpace(line)
	}

	// Check for command substitution
	line = sa.stripCommandSubstitution(line)

	// Parse pipes first
	pipeParts := strings.Split(line, "|")
	if len(pipeParts) > 1 {
		for i, part := range pipeParts {
			part = strings.TrimSpace(part)
			if i == 0 {
				cmd.Command = sa.extractBaseCommand(part)
				cmd.Arguments = sa.extractArgs(part)
			} else {
				nextCmd := sa.extractBaseCommand(part)
				cmd.Pipes = append(cmd.Pipes, Pipe{
					FromCommand: cmd.Command,
					ToCommand:   nextCmd,
					Position:    i,
				})
				cmd.Command = nextCmd
			}
		}
	} else {
		cmd.Command = sa.extractBaseCommand(line)
		cmd.Arguments = sa.extractArgs(line)
	}

	// Parse redirections
	sa.parseRedirections(line, lineNum, &cmd)

	// Check for dangerous patterns
	cmd.IsDangerous = sa.checkForDanger(&cmd)

	return cmd
}

func (sa *shellAnalyzer) extractBaseCommand(part string) string {
	part = strings.TrimSpace(part)
	if idx := strings.IndexAny(part, " \t|<>"); idx >= 0 {
		return part[:idx]
	}
	return part
}

func (sa *shellAnalyzer) extractArgs(part string) []string {
	part = strings.TrimSpace(part)
	if idx := strings.IndexAny(part, " \t|<>"); idx >= 0 {
		part = strings.TrimSpace(part[idx:])
	}
	if part == "" {
		return nil
	}
	return strings.Fields(part)
}

func (sa *shellAnalyzer) parseRedirections(line string, lineNum int, cmd *ShellCommand) {
	redirectionPattern := regexp.MustCompile(`([<>]|>>|2>|&>)\s*(\S+)`)
	matches := redirectionPattern.FindAllStringSubmatch(line, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			cmd.Redirections = append(cmd.Redirections, Redirection{
				Type:        match[1],
				Target:      match[2],
				IsDangerous: !shellAnalyzerIsSafePath(match[2]),
				Line:        lineNum,
			})
		}
	}
}

func (sa *shellAnalyzer) stripCommandSubstitution(line string) string {
	result := regexp.MustCompile(`\$\([^)]*\)`).ReplaceAllString(line, "")
	result = regexp.MustCompile("`[^`]+`").ReplaceAllString(result, "")
	return result
}

func (sa *shellAnalyzer) checkForDanger(cmd *ShellCommand) bool {
	if sa.dangerousCommands[cmd.Command] {
		cmd.DangerousPatterns = append(cmd.DangerousPatterns, fmt.Sprintf("dangerous command: %s", cmd.Command))
		return true
	}

	for _, arg := range cmd.Arguments {
		for _, pattern := range sa.dangerousPatterns {
			if pattern.MatchString(arg) {
				cmd.DangerousPatterns = append(cmd.DangerousPatterns, pattern.String())
				return true
			}
		}
	}

	for _, redir := range cmd.Redirections {
		if redir.IsDangerous {
			cmd.DangerousPatterns = append(cmd.DangerousPatterns, fmt.Sprintf("dangerous redirection: %s %s", redir.Type, redir.Target))
			return true
		}
	}

	return false
}

// IsSafe performs safety analysis on shell code
func (sa *shellAnalyzer) IsSafe(code string) (bool, SafetyReport) {
	report := SafetyReport{
		RiskScore:         0,
		DangerousPatterns: make([]DangerousPattern, 0),
		Recommendations:   make([]string, 0),
	}

	commands, err := sa.Parse(code)
	if err != nil {
		report.Recommendations = append(report.Recommendations, fmt.Sprintf("Parse error: %v", err))
		return false, report
	}

	hasDangerous := false
	for _, cmd := range commands {
		if cmd.IsDangerous {
			hasDangerous = true
			report.RiskScore += 30

			for _, pattern := range cmd.DangerousPatterns {
				report.DangerousPatterns = append(report.DangerousPatterns, DangerousPattern{
					Pattern:     pattern,
					Location:    CodeLocation{Line: cmd.Line},
					Severity:    "high",
					Description: fmt.Sprintf("Dangerous pattern in command '%s'", cmd.Command),
					Category:    "shell_command",
				})
			}
		}

		for _, redir := range cmd.Redirections {
			if redir.Type == ">" || redir.Type == ">>" {
				report.RiskScore += 10
				if redir.IsDangerous {
					report.RiskScore += 20
				}
			}
		}

		if len(cmd.Pipes) > 0 {
			report.RiskScore += 5 * len(cmd.Pipes)
		}

		// Check for export of dangerous variables
		if cmd.Command == "export" {
			report.RiskScore += 5
		}
	}

	if report.RiskScore > 50 {
		report.Recommendations = append(report.Recommendations, "High risk detected - review required")
	}

	report.IsSafe = !hasDangerous && report.RiskScore < 30
	return report.IsSafe, report
}

// ExtractDangerousPatterns identifies specific dangerous patterns
func (sa *shellAnalyzer) ExtractDangerousPatterns(code string) []DangerousPattern {
	patterns := make([]DangerousPattern, 0)
	lines := strings.Split(code, "\n")
	lineNum := 0

	for _, line := range lines {
		lineNum++
		trimmed := strings.TrimSpace(line)

		for _, pattern := range sa.dangerousPatterns {
			if pattern.MatchString(trimmed) {
				matches := pattern.FindAllString(trimmed, -1)
				for _, match := range matches {
					patterns = append(patterns, DangerousPattern{
						Pattern:     match,
						Location:    CodeLocation{Line: lineNum},
						Severity:    "high",
						Description: "Dangerous shell pattern detected",
						Category:    "shell_command",
					})
				}
			}
		}
	}

	return patterns
}

// GetSemanticOperations converts shell code to semantic operations
func (sa *shellAnalyzer) GetSemanticOperations(code string) ([]SemanticOperation, error) {
	operations := make([]SemanticOperation, 0)
	commands, err := sa.Parse(code)
	if err != nil {
		return nil, err
	}

	for _, cmd := range commands {
		if shellAnalyzerIsReadCommand(cmd.Command) {
			for _, arg := range cmd.Arguments {
				if shellAnalyzerIsFilePath(arg) {
					operations = append(operations, SemanticOperation{
						OperationType: OpRead,
						TargetPath:    arg,
						Context:       fmt.Sprintf("shell_command:%s", cmd.Command),
						Parameters:    map[string]interface{}{"line": cmd.Line},
					})
				}
			}
		}

		for _, redir := range cmd.Redirections {
			if redir.Type == ">" || redir.Type == ">>" {
				opType := OpWrite
				if redir.Type == ">>" {
					opType = OpRedirect
				}
				operations = append(operations, SemanticOperation{
					OperationType: opType,
					TargetPath:    redir.Target,
					Context:       fmt.Sprintf("shell_redirection:%s", cmd.Command),
					Parameters: map[string]interface{}{
						"line":     redir.Line,
						"operator": redir.Type,
						"append":   redir.Type == ">>",
					},
				})
			} else if redir.Type == "<" {
				operations = append(operations, SemanticOperation{
					OperationType: OpRead,
					TargetPath:    redir.Target,
					Context:       fmt.Sprintf("shell_redirection:%s", cmd.Command),
					Parameters:    map[string]interface{}{"line": redir.Line},
				})
			}
		}

		for _, pipe := range cmd.Pipes {
			operations = append(operations, SemanticOperation{
				OperationType: OpRedirect,
				TargetPath:    pipe.ToCommand,
				Context:       fmt.Sprintf("shell_pipe:%s", cmd.Command),
				Parameters: map[string]interface{}{
					"line":         cmd.Line,
					"from_command": pipe.FromCommand,
				},
			})
		}

		if cmd.IsDangerous {
			operations = append(operations, SemanticOperation{
				OperationType: OpExecute,
				TargetPath:    cmd.Command,
				Context:       "dangerous_shell_command",
				Parameters: map[string]interface{}{
					"line":            cmd.Line,
					"danger_patterns": cmd.DangerousPatterns,
				},
			})
		}

		// Handle export statements
		if cmd.Command == "export" {
			for _, arg := range cmd.Arguments {
				if strings.Contains(arg, "=") {
					varName := strings.Split(arg, "=")[0]
					operations = append(operations, SemanticOperation{
						OperationType: OpRead,
						TargetPath:    varName,
						Context:       "export_variable",
						Parameters:    map[string]interface{}{"line": cmd.Line},
					})
				}
			}
		}
	}

	return operations, nil
}

// Helper functions (avoiding name conflicts with existing functions)

func shellAnalyzerIsSafePath(path string) bool {
	dangerousPrefixes := []string{
		"/etc/", "/root/", "/boot/", "/proc/", "/sys/", "/dev/",
		"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
	}
	for _, prefix := range dangerousPrefixes {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}
	// Allow relative paths like ./tmp
	if strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") || !strings.HasPrefix(path, "/") {
		return true
	}
	// Only /tmp is allowed as absolute path
	return path == "/tmp" || strings.HasPrefix(path, "/tmp/")
}

func shellAnalyzerIsReadCommand(cmd string) bool {
	readCmds := map[string]bool{
		"cat": true, "less": true, "more": true, "head": true, "tail": true,
		"grep": true, "egrep": true, "fgrep": true, "awk": true, "sed": true,
		"sort": true, "uniq": true, "wc": true, "cut": true, "tr": true,
	}
	return readCmds[cmd]
}

func shellAnalyzerIsFilePath(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")
}
