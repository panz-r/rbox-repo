package semantic

import (
	"fmt"
	"regexp"
	"strings"
)

type ShellScript struct {
	Commands  []ShellStatement
	Variables map[string]string
	Functions map[string]ShellFunction
	HereDocs  []HereDoc
	LineCount int
}

type ShellStatement struct {
	Type              StatementType
	Line              int
	EndLine           int
	Condition         string
	ThenBody          []ShellStatement
	ElseBody          []ShellStatement
	ElifBodies        []ElifBranch
	IterVariable      string
	IterItems         string
	DoBody            []ShellStatement
	CaseValue         string
	CaseBody          []CaseClause
	Command           string
	Args              []string
	Redirections      []Redirection
	Pipes             []Pipe
	Negated           bool
	SourceInfo        string
	HereDoc           *HereDoc
	ExtractedCommands []string
	PythonOps         []SemanticOperation
	BashOps           []SemanticOperation
}

type StatementType int

const (
	StmtSimple StatementType = iota
	StmtIf
	StmtFor
	StmtWhile
	StmtUntil
	StmtCase
	StmtFunction
	StmtSource
	StmtExport
	StmtCd
)

type ElifBranch struct {
	Condition string
	Body      []ShellStatement
}

type CaseClause struct {
	Pattern string
	Body    []ShellStatement
}

type HereDoc struct {
	Delimiter string
	Content   string
	StripTabs bool
	StartLine int
}

type ShellFunction struct {
	Name       string
	Body       []ShellStatement
	Parameters []string
	Line       int
}

type MultiLineShellParser struct {
	dangerousCommands map[string]bool
	dangerousPatterns []*regexp.Regexp
	pythonAnalyzer    PythonCodeAnalyzer
}

func NewMultiLineShellParser() *MultiLineShellParser {
	return &MultiLineShellParser{
		dangerousCommands: map[string]bool{
			"rm": true, "mv": true, "cp": true, "dd": true, "chmod": true, "chown": true,
			"mkdir": true, "rmdir": true, "ln": true, "touch": true,
			"wget": true, "curl": true, "scp": true, "rsync": true, "ssh": true,
			"mkfs": true, "fdisk": true, "format": true,
			"systemctl": true, "service": true,
			"kill": true, "pkill": true, "killall": true,
			"mount": true, "umount": true,
			"eval": true, "exec": true, "tee": true,
		},
		dangerousPatterns: []*regexp.Regexp{
			regexp.MustCompile(`rm\s+-rf?\s+/\*?`),
			regexp.MustCompile(`rm\s+-rf?\s+\S+`),
			regexp.MustCompile(`>\s*/\S+`),
			regexp.MustCompile(`>>\s*/\S+`),
			regexp.MustCompile(`\|\s*tee\s`),
			regexp.MustCompile(`sed\s+-i\s+[^;]*`),
			regexp.MustCompile(`find\s+.*-exec\s+.*\{}\s*;`),
			regexp.MustCompile(`find\s+.*-delete\b`),
			regexp.MustCompile(`find\s+.*-execdir\b`),
			regexp.MustCompile(`find\s+.*-okdir\b`),
		},
		pythonAnalyzer: NewPythonCodeAnalyzer(),
	}
}

func (p *MultiLineShellParser) ParseScript(script string) (*ShellScript, error) {
	lines := strings.Split(script, "\n")
	scriptObj := &ShellScript{
		Commands:  make([]ShellStatement, 0),
		Variables: make(map[string]string),
		Functions: make(map[string]ShellFunction),
		HereDocs:  make([]HereDoc, 0),
		LineCount: len(lines),
	}

	statements, hereDocs, err := p.parseLines(lines, 0, len(lines))
	if err != nil {
		return nil, err
	}
	scriptObj.Commands = statements
	scriptObj.HereDocs = hereDocs

	return scriptObj, nil
}

func (p *MultiLineShellParser) parseLines(lines []string, startLine, endLine int) ([]ShellStatement, []HereDoc, error) {
	statements := make([]ShellStatement, 0)
	hereDocs := make([]HereDoc, 0)

	for i := startLine; i < endLine && i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if line == "else" || strings.HasPrefix(line, "elif ") || line == "fi" ||
			line == "done" || line == "esac" || line == "}" {
			return statements, hereDocs, nil
		}

		if strings.HasPrefix(line, "if ") {
			stmt, err := p.parseIfStatement(lines, i, endLine)
			if err != nil {
				return nil, nil, err
			}
			statements = append(statements, *stmt)
			i = stmt.EndLine - 1
			continue
		}

		if strings.HasPrefix(line, "for ") {
			stmt, err := p.parseForStatement(lines, i, endLine)
			if err != nil {
				return nil, nil, err
			}
			statements = append(statements, *stmt)
			i = stmt.EndLine - 1
			continue
		}

		if strings.HasPrefix(line, "while ") || strings.HasPrefix(line, "until ") {
			stmt, err := p.parseWhileStatement(lines, i, endLine)
			if err != nil {
				return nil, nil, err
			}
			statements = append(statements, *stmt)
			i = stmt.EndLine - 1
			continue
		}

		if strings.HasPrefix(line, "case ") {
			stmt, err := p.parseCaseStatement(lines, i, endLine)
			if err != nil {
				return nil, nil, err
			}
			statements = append(statements, *stmt)
			i = stmt.EndLine - 1
			continue
		}

		if strings.HasPrefix(line, "function ") || (strings.HasSuffix(line, "() {") && !strings.Contains(line, "if")) {
			stmt, err := p.parseFunctionDefinition(lines, i, endLine)
			if err != nil {
				return nil, nil, err
			}
			if stmt != nil {
				statements = append(statements, *stmt)
				i = stmt.EndLine - 1
			}
			continue
		}

		if strings.HasPrefix(line, "source ") || (len(line) > 1 && (line[0] == '.' && (line[1] == ' ' || line[1] == '\t'))) {
			stmt := p.parseSourceStatement(line, i)
			statements = append(statements, *stmt)
			continue
		}

		if strings.HasPrefix(line, "export ") {
			stmt := p.parseExportStatement(line, i)
			statements = append(statements, *stmt)
			continue
		}

		if strings.HasPrefix(line, "cd ") {
			stmt := p.parseCdStatement(line, i)
			statements = append(statements, *stmt)
			continue
		}

		isPythonCommand := strings.HasPrefix(line, "python") || strings.HasPrefix(line, "python3") || strings.HasPrefix(line, "py")

		if strings.Contains(line, "<<") && !isPythonCommand {
			doc, err := p.parseHereDoc(lines, i, endLine, line)
			if err != nil {
				return nil, nil, err
			}
			if doc != nil && doc.Delimiter != "" {
				stmt := &ShellStatement{
					Type:    StmtSimple,
					Command: "here-doc",
					Line:    i + 1,
				}
				stmt.HereDoc = doc
				hereDocs = append(hereDocs, *doc)
				i = doc.StartLine + strings.Count(doc.Content, "\n")
				statements = append(statements, *stmt)
				continue
			}
		}

		stmt := p.parseSimpleCommand(line, i)
		if isPythonCommand && strings.Contains(line, "<<") {
			doc, err := p.parseHereDoc(lines, i, endLine, line)
			if err == nil && doc != nil && doc.Delimiter != "" {
				stmt.HereDoc = doc
				hereDocs = append(hereDocs, *doc)
				_, pythonReport := p.analyzePythonHereDoc(doc.Content)
				ops := p.pythonReportToOperations(pythonReport)
				stmt.PythonOps = ops
				i = doc.StartLine + strings.Count(doc.Content, "\n") + 1
				statements = append(statements, *stmt)
				continue
			}
		}
		if isPythonCommand && (strings.Contains(line, "-c ") || strings.HasSuffix(line, " -c")) {
			pythonCode := p.extractPythonDashCFromLine(line)
			if pythonCode != "" {
				_, pythonReport := p.analyzePythonHereDoc(pythonCode)
				stmt.PythonOps = p.pythonReportToOperations(pythonReport)
			}
		}

		isBashCommand := strings.HasPrefix(line, "bash") || strings.HasPrefix(line, "sh") || strings.HasPrefix(line, "dash")
		if isBashCommand && (strings.Contains(line, "-c ") || strings.HasSuffix(line, " -c")) {
			bashCode := p.extractBashDashCFromLine(line)
			if bashCode != "" {
				ops := p.bashScriptToOperations(bashCode)
				stmt.BashOps = ops
				if len(ops) > 0 {
					if cmds, ok := ops[0].Parameters["extracted_commands"].([]string); ok {
						stmt.ExtractedCommands = cmds
					}
				}
			}
		}
		statements = append(statements, *stmt)
	}

	return statements, hereDocs, nil
}

func (p *MultiLineShellParser) analyzePythonHereDoc(content string) (bool, *SafetyReport) {
	if p.pythonAnalyzer == nil {
		return true, nil
	}
	safe, report := p.pythonAnalyzer.IsSafe(content)
	return safe, &report
}

func (p *MultiLineShellParser) extractPythonDashCFromLine(line string) string {
	cIdx := strings.Index(line, "-c ")
	if cIdx >= 0 {
		code := strings.TrimSpace(line[cIdx+3:])
		if len(code) > 0 {
			if code[0] == '"' || code[0] == '\'' {
				quoteChar := rune(code[0])
				code = code[1:]
				for j, c := range code {
					if c == quoteChar {
						return code[:j]
					}
				}
				return code
			}
			return code
		}
	}
	return ""
}

func (p *MultiLineShellParser) extractBashDashCFromLine(line string) string {
	cIdx := strings.Index(line, "-c ")
	if cIdx >= 0 {
		code := strings.TrimSpace(line[cIdx+3:])
		if len(code) > 0 {
			if code[0] == '"' || code[0] == '\'' {
				quoteChar := rune(code[0])
				code = code[1:]
				for j, c := range code {
					if c == quoteChar {
						return code[:j]
					}
				}
				return code
			}
			return code
		}
	}
	return ""
}

func (p *MultiLineShellParser) analyzeBashInlineScript(script string) (bool, *SafetyReport) {
	bashParser := NewMultiLineShellParser()
	parsed, err := bashParser.ParseScript(script)
	if err != nil {
		report := SafetyReport{
			IsSafe:    false,
			RiskScore: 30,
			DangerousPatterns: []DangerousPattern{
				{
					Pattern:     "parse error",
					Location:    CodeLocation{Line: 1},
					Severity:    "high",
					Description: "Failed to parse inline bash script",
					Category:    "shell_command",
				},
			},
		}
		return false, &report
	}
	safe, report := bashParser.IsSafe(parsed)
	return safe, &report
}

func (p *MultiLineShellParser) pythonReportToOperations(report *SafetyReport) []SemanticOperation {
	if report == nil {
		return nil
	}
	operations := make([]SemanticOperation, 0)
	for _, pattern := range report.DangerousPatterns {
		op := SemanticOperation{
			OperationType: OpExecute,
			Context:       fmt.Sprintf("Python: %s", pattern.Description),
			Parameters: map[string]interface{}{
				"python_code_safe": report.IsSafe,
				"risk_score":       report.RiskScore,
				"pattern":          pattern.Pattern,
				"severity":         pattern.Severity,
				"category":         pattern.Category,
			},
		}
		if strings.Contains(strings.ToLower(pattern.Description), "write") {
			op.OperationType = OpWrite
		}
		operations = append(operations, op)
	}
	if !report.IsSafe && len(operations) == 0 {
		operations = append(operations, SemanticOperation{
			OperationType: OpExecute,
			Context:       "Python code is not safe",
			Parameters: map[string]interface{}{
				"python_code_safe": false,
				"risk_score":       report.RiskScore,
			},
		})
	}
	return operations
}

func (p *MultiLineShellParser) bashScriptToOperations(script string) []SemanticOperation {
	operations := make([]SemanticOperation, 0)
	bashParser := NewMultiLineShellParser()
	parsed, err := bashParser.ParseScript(script)
	if err != nil {
		operations = append(operations, SemanticOperation{
			OperationType: OpExecute,
			Context:       "Failed to parse inline bash script",
			Parameters: map[string]interface{}{
				"bash_code":   script,
				"parse_error": err.Error(),
				"bash_safe":   false,
			},
		})
		return operations
	}

	extractedCommands := p.extractCommandsFromParsedScript(parsed)

	safe, report := bashParser.IsSafe(parsed)
	params := map[string]interface{}{
		"bash_code":          script,
		"bash_safe":          safe,
		"risk_score":         report.RiskScore,
		"extracted_commands": extractedCommands,
	}
	operations = append(operations, SemanticOperation{
		OperationType: OpExecute,
		Context:       "Inline bash script",
		Parameters:    params,
	})
	for _, pattern := range report.DangerousPatterns {
		opParams := map[string]interface{}{
			"bash_code": script,
			"pattern":   pattern.Pattern,
			"severity":  pattern.Severity,
			"category":  pattern.Category,
		}
		if len(extractedCommands) > 0 {
			opParams["extracted_commands"] = extractedCommands
		}
		op := SemanticOperation{
			OperationType: OpExecute,
			Context:       fmt.Sprintf("Bash: %s", pattern.Description),
			Parameters:    opParams,
		}
		operations = append(operations, op)
	}
	return operations
}

// extractCommandsFromParsedScript extracts individual command strings from a parsed shell script.
// Returns a slice of command strings that can be passed to the caller for further analysis.
func (p *MultiLineShellParser) extractCommandsFromParsedScript(script *ShellScript) []string {
	commands := make([]string, 0)
	for _, stmt := range script.Commands {
		cmd := p.statementToCommandString(&stmt)
		if cmd != "" {
			commands = append(commands, cmd)
		}
	}
	return commands
}

// statementToCommandString converts a parsed ShellStatement back to a command string.
// Returns an empty string if the statement cannot be converted.
func (p *MultiLineShellParser) statementToCommandString(stmt *ShellStatement) string {
	if stmt == nil {
		return ""
	}

	switch stmt.Type {
	case StmtSimple:
		if stmt.Command != "" {
			parts := []string{stmt.Command}
			parts = append(parts, stmt.Args...)
			return strings.Join(parts, " ")
		}
	case StmtSource:
		if len(stmt.Args) > 0 {
			return "source " + strings.Join(stmt.Args, " ")
		}
	case StmtExport:
		if len(stmt.Args) > 0 {
			return "export " + strings.Join(stmt.Args, " ")
		}
	case StmtCd:
		if len(stmt.Args) > 0 {
			return "cd " + stmt.Args[0]
		}
	case StmtFor:
		parts := []string{"for", stmt.IterVariable, "in", stmt.IterItems, ";", "do"}
		for _, bodyStmt := range stmt.DoBody {
			bodyCmd := p.statementToCommandString(&bodyStmt)
			if bodyCmd != "" {
				parts = append(parts, bodyCmd)
			}
		}
		parts = append(parts, "done")
		return strings.Join(parts, " ")
	case StmtWhile:
		parts := []string{"while", stmt.Condition, ";"}
		for _, bodyStmt := range stmt.DoBody {
			bodyCmd := p.statementToCommandString(&bodyStmt)
			if bodyCmd != "" {
				parts = append(parts, bodyCmd)
			}
		}
		parts = append(parts, "done")
		return strings.Join(parts, " ")
	case StmtIf:
		parts := []string{"if", stmt.Condition, ";"}
		for _, bodyStmt := range stmt.ThenBody {
			bodyCmd := p.statementToCommandString(&bodyStmt)
			if bodyCmd != "" {
				parts = append(parts, bodyCmd)
			}
		}
		parts = append(parts, "fi")
		return strings.Join(parts, " ")
	case StmtUntil:
		parts := []string{"until", stmt.Condition, ";"}
		for _, bodyStmt := range stmt.DoBody {
			bodyCmd := p.statementToCommandString(&bodyStmt)
			if bodyCmd != "" {
				parts = append(parts, bodyCmd)
			}
		}
		parts = append(parts, "done")
		return strings.Join(parts, " ")
	case StmtCase:
		return "case " + stmt.CaseValue + " in ... ) ... esac"
	case StmtFunction:
		return stmt.Command + "() { ... }"
	}

	return ""
}

func (p *MultiLineShellParser) parseIfStatement(lines []string, startLine, endLine int) (*ShellStatement, error) {
	stmt := &ShellStatement{
		Type:       StmtIf,
		Line:       startLine + 1,
		ThenBody:   make([]ShellStatement, 0),
		ElseBody:   make([]ShellStatement, 0),
		ElifBodies: make([]ElifBranch, 0),
	}

	ifLine := strings.TrimSpace(lines[startLine])
	thenOnSameLine := false
	if strings.HasPrefix(ifLine, "if ") {
		stmt.Condition = strings.TrimPrefix(ifLine, "if ")
		stmt.Condition = strings.TrimSpace(stmt.Condition)
	}

	if strings.HasSuffix(stmt.Condition, "; then") {
		stmt.Condition = strings.TrimSuffix(stmt.Condition, "; then")
		stmt.Condition = strings.TrimSpace(stmt.Condition)
		thenOnSameLine = true
	} else if strings.HasSuffix(stmt.Condition, " then") {
		stmt.Condition = strings.TrimSuffix(stmt.Condition, " then")
		stmt.Condition = strings.TrimSpace(stmt.Condition)
		thenOnSameLine = true
	} else if strings.HasSuffix(stmt.Condition, "then") {
		stmt.Condition = strings.TrimSuffix(stmt.Condition, "then")
		stmt.Condition = strings.TrimSpace(stmt.Condition)
		thenOnSameLine = true
	}

	thenLine := -1
	if !thenOnSameLine {
		for i := startLine + 1; i < endLine && i < len(lines); i++ {
			if strings.TrimSpace(lines[i]) == "then" {
				thenLine = i
				break
			}
		}
	}

	if thenLine >= 0 {
		thenBody, _, err := p.parseLines(lines, thenLine+1, endLine)
		if err != nil {
			return nil, err
		}
		stmt.ThenBody = thenBody

		i := thenLine + 1 + len(thenBody)
		for i < endLine && i < len(lines) {
			line := strings.TrimSpace(lines[i])
			if line == "fi" {
				stmt.EndLine = i + 1
				return stmt, nil
			}
			if line == "else" {
				elseBody, _, err := p.parseLines(lines, i+1, endLine)
				if err != nil {
					return nil, err
				}
				stmt.ElseBody = elseBody
				stmt.EndLine = i + len(elseBody) + 2
				return stmt, nil
			}
			if strings.HasPrefix(line, "elif ") {
				condition := strings.TrimPrefix(line, "elif ")
				condition = strings.TrimSuffix(condition, ";")
				condition = strings.TrimSpace(condition)
				elifBranch := ElifBranch{
					Condition: condition,
					Body:      make([]ShellStatement, 0),
				}

				elifThenLine := -1
				if strings.HasSuffix(line, "; then") {
					elifThenLine = i
					condition = strings.TrimSuffix(condition, "; then")
					condition = strings.TrimSpace(condition)
					elifBranch.Condition = condition
				} else if strings.HasSuffix(line, " then") {
					elifThenLine = i
					condition = strings.TrimSuffix(condition, " then")
					condition = strings.TrimSpace(condition)
					elifBranch.Condition = condition
				} else if strings.HasSuffix(line, "then") {
					elifThenLine = i
					condition = strings.TrimSuffix(condition, "then")
					condition = strings.TrimSpace(condition)
					elifBranch.Condition = condition
				}

				if elifThenLine < 0 {
					i++
					for i < endLine && i < len(lines) {
						if strings.TrimSpace(lines[i]) == "then" {
							elifThenLine = i
							break
						}
						i++
					}
				}

				body, _, err := p.parseLines(lines, elifThenLine+1, endLine)
				if err != nil {
					return nil, err
				}
				elifBranch.Body = body
				stmt.ElifBodies = append(stmt.ElifBodies, elifBranch)
				i = elifThenLine + len(body)
				continue
			}
			i++
		}
	} else if thenOnSameLine {
		thenBody, _, err := p.parseLines(lines, startLine+1, endLine)
		if err != nil {
			return nil, err
		}
		stmt.ThenBody = thenBody

		i := startLine + 1 + len(thenBody)
		for i < endLine && i < len(lines) {
			line := strings.TrimSpace(lines[i])
			if line == "fi" {
				stmt.EndLine = i + 1
				return stmt, nil
			}
			if line == "else" {
				elseBody, _, err := p.parseLines(lines, i+1, endLine)
				if err != nil {
					return nil, err
				}
				stmt.ElseBody = elseBody
				stmt.EndLine = i + len(elseBody) + 2
				return stmt, nil
			}
			if strings.HasPrefix(line, "elif ") {
				condition := strings.TrimPrefix(line, "elif ")
				condition = strings.TrimSuffix(condition, ";")
				condition = strings.TrimSpace(condition)
				elifBranch := ElifBranch{
					Condition: condition,
					Body:      make([]ShellStatement, 0),
				}

				elifThenLine := -1
				if strings.HasSuffix(line, "; then") {
					elifThenLine = i
					condition = strings.TrimSuffix(condition, "; then")
					condition = strings.TrimSpace(condition)
					elifBranch.Condition = condition
				} else if strings.HasSuffix(line, " then") {
					elifThenLine = i
					condition = strings.TrimSuffix(condition, " then")
					condition = strings.TrimSpace(condition)
					elifBranch.Condition = condition
				} else if strings.HasSuffix(line, "then") {
					elifThenLine = i
					condition = strings.TrimSuffix(condition, "then")
					condition = strings.TrimSpace(condition)
					elifBranch.Condition = condition
				}

				if elifThenLine < 0 {
					i++
					for i < endLine && i < len(lines) {
						if strings.TrimSpace(lines[i]) == "then" {
							elifThenLine = i
							break
						}
						i++
					}
				}

				body, _, err := p.parseLines(lines, elifThenLine+1, endLine)
				if err != nil {
					return nil, err
				}
				elifBranch.Body = body
				stmt.ElifBodies = append(stmt.ElifBodies, elifBranch)
				i = elifThenLine + len(body)
				continue
			}
			i++
		}
	}

	stmt.EndLine = startLine + 1
	return stmt, nil
}

func (p *MultiLineShellParser) parseForStatement(lines []string, startLine, endLine int) (*ShellStatement, error) {
	stmt := &ShellStatement{
		Type:   StmtFor,
		Line:   startLine + 1,
		DoBody: make([]ShellStatement, 0),
	}

	line := strings.TrimSpace(lines[startLine])

	doOnSameLine := false
	if strings.HasSuffix(line, "; do") {
		line = strings.TrimSuffix(line, "; do")
		line = strings.TrimSpace(line)
		doOnSameLine = true
	} else if strings.HasSuffix(line, " do") {
		line = strings.TrimSuffix(line, " do")
		line = strings.TrimSpace(line)
		doOnSameLine = true
	}

	forPattern := regexp.MustCompile(`for\s+(\w+)\s+in\s+(.+)`)
	matches := forPattern.FindStringSubmatch(line)
	if len(matches) >= 3 {
		stmt.IterVariable = matches[1]
		stmt.IterItems = matches[2]
	}

	var doLine int
	if doOnSameLine {
		doLine = startLine
	} else {
		doLine = -1
		for i := startLine + 1; i < endLine && i < len(lines); i++ {
			if strings.TrimSpace(lines[i]) == "do" {
				doLine = i
				break
			}
		}
	}

	if doLine >= 0 {
		body, _, err := p.parseLines(lines, doLine+1, endLine)
		if err != nil {
			return nil, err
		}
		stmt.DoBody = body

		i := doLine + 1 + len(body)
		for i < endLine && i < len(lines) {
			if strings.TrimSpace(lines[i]) == "done" {
				stmt.EndLine = i + 1
				return stmt, nil
			}
			i++
		}
	}

	stmt.EndLine = startLine + 1
	return stmt, nil
}

func (p *MultiLineShellParser) parseWhileStatement(lines []string, startLine, endLine int) (*ShellStatement, error) {
	line := strings.TrimSpace(lines[startLine])

	stmt := &ShellStatement{
		Type:   StmtWhile,
		Line:   startLine + 1,
		DoBody: make([]ShellStatement, 0),
	}

	doOnSameLine := false
	if strings.HasSuffix(line, "; do") {
		line = strings.TrimSuffix(line, "; do")
		line = strings.TrimSpace(line)
		doOnSameLine = true
	} else if strings.HasSuffix(line, " do") {
		line = strings.TrimSuffix(line, " do")
		line = strings.TrimSpace(line)
		doOnSameLine = true
	}

	if strings.HasPrefix(line, "until ") {
		stmt.Type = StmtUntil
		stmt.Condition = strings.TrimPrefix(line, "until ")
	} else {
		stmt.Condition = strings.TrimPrefix(line, "while ")
	}
	stmt.Condition = strings.TrimSuffix(stmt.Condition, ";")
	stmt.Condition = strings.TrimSpace(stmt.Condition)

	var doLine int
	if doOnSameLine {
		doLine = startLine
	} else {
		doLine = -1
		for i := startLine + 1; i < endLine && i < len(lines); i++ {
			if strings.TrimSpace(lines[i]) == "do" {
				doLine = i
				break
			}
		}
	}

	if doLine >= 0 {
		body, _, err := p.parseLines(lines, doLine+1, endLine)
		if err != nil {
			return nil, err
		}
		stmt.DoBody = body

		i := doLine + 1 + len(body)
		for i < endLine && i < len(lines) {
			if strings.TrimSpace(lines[i]) == "done" {
				stmt.EndLine = i + 1
				return stmt, nil
			}
			i++
		}
	}

	stmt.EndLine = startLine + 1
	return stmt, nil
}

func (p *MultiLineShellParser) parseCaseStatement(lines []string, startLine, endLine int) (*ShellStatement, error) {
	stmt := &ShellStatement{
		Type:     StmtCase,
		Line:     startLine + 1,
		CaseBody: make([]CaseClause, 0),
	}

	line := strings.TrimSpace(lines[startLine])
	casePattern := regexp.MustCompile(`case\s+(\w+)\s+in`)
	matches := casePattern.FindStringSubmatch(line)
	if len(matches) >= 2 {
		stmt.CaseValue = matches[1]
	}

	for i := startLine + 1; i < endLine && i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "esac" {
			stmt.EndLine = i + 1
			return stmt, nil
		}
		if strings.HasSuffix(strings.TrimSpace(lines[i]), ")") {
			clause := &CaseClause{
				Pattern: strings.TrimSpace(lines[i]),
				Body:    make([]ShellStatement, 0),
			}
			stmt.CaseBody = append(stmt.CaseBody, *clause)
		}
	}

	stmt.EndLine = startLine + 1
	return stmt, nil
}

func (p *MultiLineShellParser) parseFunctionDefinition(lines []string, startLine, endLine int) (*ShellStatement, error) {
	line := strings.TrimSpace(lines[startLine])

	funcName := ""
	if strings.HasPrefix(line, "function ") {
		namePattern := regexp.MustCompile(`function\s+(\w+)`)
		matches := namePattern.FindStringSubmatch(line)
		if len(matches) >= 2 {
			funcName = matches[1]
		}
	} else if strings.HasSuffix(line, "() {") {
		namePattern := regexp.MustCompile(`^(\w+)\s*\(\)`)
		matches := namePattern.FindStringSubmatch(line)
		if len(matches) >= 2 {
			funcName = matches[1]
		}
	}

	if funcName == "" {
		return nil, nil
	}

	stmt := &ShellStatement{
		Type: StmtFunction,
		Line: startLine + 1,
		Args: []string{funcName},
	}

	for i := startLine + 1; i < endLine && i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "}" {
			stmt.EndLine = i + 1
			return stmt, nil
		}
	}

	stmt.EndLine = startLine + 1
	return stmt, nil
}

func (p *MultiLineShellParser) parseHereDoc(lines []string, startLine, endLine int, firstLine string) (*HereDoc, error) {
	doc := &HereDoc{
		StartLine: startLine + 1,
	}

	stripTabs := strings.HasPrefix(firstLine, "<<-")
	if stripTabs {
		doc.StripTabs = true
	}

	delimPattern := regexp.MustCompile(`<<-?\s*['"]?(\w+)['"]?`)
	matches := delimPattern.FindStringSubmatch(firstLine)
	if len(matches) >= 2 {
		doc.Delimiter = matches[1]
	}

	if doc.Delimiter == "" {
		return nil, nil
	}

	contentLines := make([]string, 0)
	for i := startLine + 1; i < endLine && i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == doc.Delimiter {
			doc.Content = strings.Join(contentLines, "\n")
			return doc, nil
		}
		contentLines = append(contentLines, lines[i])
	}

	return doc, nil
}

func (p *MultiLineShellParser) parseSourceStatement(line string, lineNum int) *ShellStatement {
	stmt := &ShellStatement{
		Type: StmtSource,
		Line: lineNum + 1,
	}

	if strings.HasPrefix(line, "source ") {
		stmt.Args = strings.Fields(strings.TrimPrefix(line, "source "))
	} else if len(line) > 1 {
		stmt.Args = strings.Fields(line[1:])
	}

	return stmt
}

func (p *MultiLineShellParser) parseExportStatement(line string, lineNum int) *ShellStatement {
	stmt := &ShellStatement{
		Type: StmtExport,
		Line: lineNum + 1,
	}

	stmt.Args = strings.Fields(strings.TrimPrefix(line, "export "))
	for _, arg := range stmt.Args {
		if strings.Contains(arg, "=") {
			parts := strings.SplitN(arg, "=", 2)
			if len(parts) == 2 {
				stmt.SourceInfo = parts[0]
			}
		}
	}

	return stmt
}

func (p *MultiLineShellParser) parseCdStatement(line string, lineNum int) *ShellStatement {
	stmt := &ShellStatement{
		Type: StmtCd,
		Line: lineNum + 1,
	}

	stmt.Args = strings.Fields(strings.TrimPrefix(line, "cd "))
	if len(stmt.Args) > 0 {
		stmt.SourceInfo = stmt.Args[0]
	}

	return stmt
}

func (p *MultiLineShellParser) parseSimpleCommand(line string, lineNum int) *ShellStatement {
	stmt := &ShellStatement{
		Type: StmtSimple,
		Line: lineNum + 1,
		Args: make([]string, 0),
	}

	cmd, args := extractCommandAndArgs(line)
	stmt.Command = cmd
	stmt.Args = args

	p.parseRedirections(line, stmt)
	p.parsePipes(line, stmt)

	return stmt
}

func extractCommandAndArgs(line string) (string, []string) {
	depth := 0
	inSingleQuote := false
	inDoubleQuote := false

	for i, c := range line {
		switch c {
		case '\'':
			if !inDoubleQuote {
				inSingleQuote = !inSingleQuote
			}
		case '"':
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
		case '(', '{':
			if !inSingleQuote && !inDoubleQuote {
				depth++
			}
		case ')', '}':
			if !inSingleQuote && !inDoubleQuote && depth > 0 {
				depth--
			}
		case ' ', '\t':
			if depth == 0 && !inSingleQuote && !inDoubleQuote {
				cmd := strings.TrimSpace(line[:i])
				args := strings.Fields(strings.TrimSpace(line[i+1:]))
				return cmd, args
			}
		}
	}

	return strings.TrimSpace(line), nil
}

func (p *MultiLineShellParser) parseRedirections(line string, stmt *ShellStatement) {
	redirPattern := regexp.MustCompile(`([<>]|>>|2>|&>)\s*(\S+)`)
	matches := redirPattern.FindAllStringSubmatch(line, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			stmt.Redirections = append(stmt.Redirections, Redirection{
				Type:   match[1],
				Target: match[2],
				Line:   stmt.Line,
			})
		}
	}
}

func (p *MultiLineShellParser) parsePipes(line string, stmt *ShellStatement) {
	parts := strings.Split(line, "|")
	if len(parts) > 1 {
		for i, part := range parts {
			part = strings.TrimSpace(part)
			if i == 0 {
				cmd, _ := extractCommandAndArgs(part)
				stmt.Command = cmd
			} else {
				nextCmd, _ := extractCommandAndArgs(part)
				stmt.Pipes = append(stmt.Pipes, Pipe{
					FromCommand: stmt.Command,
					ToCommand:   nextCmd,
					Position:    i,
				})
				stmt.Command = nextCmd
			}
		}
	}
}

func (p *MultiLineShellParser) IsSafe(script *ShellScript) (bool, SafetyReport) {
	report := SafetyReport{
		RiskScore:         0,
		DangerousPatterns: make([]DangerousPattern, 0),
		Recommendations:   make([]string, 0),
	}

	p.analyzeStatements(script.Commands, &report)

	report.IsSafe = report.RiskScore < 30 && len(report.DangerousPatterns) == 0
	return report.IsSafe, report
}

func (p *MultiLineShellParser) analyzeStatements(stmts []ShellStatement, report *SafetyReport) {
	for _, stmt := range stmts {
		p.analyzeStatement(&stmt, report)
	}
}

func (p *MultiLineShellParser) analyzeStatement(stmt *ShellStatement, report *SafetyReport) {
	if stmt.Type == StmtSimple {
		if p.dangerousCommands[stmt.Command] {
			report.RiskScore += 30
			report.DangerousPatterns = append(report.DangerousPatterns, DangerousPattern{
				Pattern:     stmt.Command,
				Location:    CodeLocation{Line: stmt.Line},
				Severity:    "high",
				Description: fmt.Sprintf("Dangerous command: %s", stmt.Command),
				Category:    "shell_command",
			})
		}

		fullLine := stmt.Command
		for _, arg := range stmt.Args {
			fullLine += " " + arg
			for _, pattern := range p.dangerousPatterns {
				if pattern.MatchString(arg) {
					report.RiskScore += 20
					report.DangerousPatterns = append(report.DangerousPatterns, DangerousPattern{
						Pattern:     pattern.String(),
						Location:    CodeLocation{Line: stmt.Line},
						Severity:    "high",
						Description: "Dangerous pattern in argument",
						Category:    "shell_command",
					})
				}
			}
		}

		for _, pattern := range p.dangerousPatterns {
			if pattern.MatchString(fullLine) {
				report.RiskScore += 20
				report.DangerousPatterns = append(report.DangerousPatterns, DangerousPattern{
					Pattern:     pattern.String(),
					Location:    CodeLocation{Line: stmt.Line},
					Severity:    "high",
					Description: "Dangerous pattern in command",
					Category:    "shell_command",
				})
			}
		}

		for _, redir := range stmt.Redirections {
			if redir.Type == ">" || redir.Type == ">>" {
				report.RiskScore += 10
				if strings.HasPrefix(redir.Target, "/etc/") ||
					strings.HasPrefix(redir.Target, "/root/") ||
					strings.HasPrefix(redir.Target, "/boot/") {
					report.RiskScore += 20
				}
			}
		}

		for range stmt.Pipes {
			report.RiskScore += 5
		}
	}

	if stmt.Type == StmtIf || stmt.Type == StmtWhile || stmt.Type == StmtUntil {
		p.analyzeStatements(stmt.ThenBody, report)
		p.analyzeStatements(stmt.ElseBody, report)
		for _, elif := range stmt.ElifBodies {
			p.analyzeStatements(elif.Body, report)
		}
	}

	if stmt.Type == StmtFor {
		p.analyzeStatements(stmt.DoBody, report)
	}

	if stmt.Type == StmtSource {
		for _, arg := range stmt.Args {
			if strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") {
				report.RiskScore += 15
				report.DangerousPatterns = append(report.DangerousPatterns, DangerousPattern{
					Pattern:     arg,
					Location:    CodeLocation{Line: stmt.Line},
					Severity:    "medium",
					Description: "Source command with relative path",
					Category:    "shell_command",
				})
			}
		}
	}

	if stmt.Type == StmtExport {
		for _, arg := range stmt.Args {
			if strings.HasPrefix(arg, "PATH=") || strings.HasPrefix(arg, "LD_") {
				report.RiskScore += 10
			}
		}
	}

	if stmt.Type == StmtSimple {
		if strings.HasPrefix(stmt.Command, "./") || strings.HasPrefix(stmt.Command, "../") {
			report.RiskScore += 15
			report.DangerousPatterns = append(report.DangerousPatterns, DangerousPattern{
				Pattern:     stmt.Command,
				Location:    CodeLocation{Line: stmt.Line},
				Severity:    "medium",
				Description: "Command with relative path",
				Category:    "shell_command",
			})
		}
	}

	if stmt.PythonOps != nil && len(stmt.PythonOps) > 0 {
		for _, op := range stmt.PythonOps {
			if risk, ok := op.Parameters["risk_score"].(int); ok {
				report.RiskScore += risk
			}
			report.DangerousPatterns = append(report.DangerousPatterns, DangerousPattern{
				Pattern:     "",
				Location:    CodeLocation{Line: stmt.Line},
				Severity:    "medium",
				Description: op.Context,
				Category:    "python_code",
			})
		}
	}

	if stmt.BashOps != nil && len(stmt.BashOps) > 0 {
		for _, op := range stmt.BashOps {
			if risk, ok := op.Parameters["risk_score"].(int); ok {
				report.RiskScore += risk
			}
			report.DangerousPatterns = append(report.DangerousPatterns, DangerousPattern{
				Pattern:     "",
				Location:    CodeLocation{Line: stmt.Line},
				Severity:    "medium",
				Description: op.Context,
				Category:    "shell_command",
			})
		}
	}
}
