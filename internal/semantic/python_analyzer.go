package semantic

import (
	"fmt"
	"regexp"
	"strings"
)

// PythonCodeAnalyzer defines the interface for Python code analysis
type PythonCodeAnalyzer interface {
	Parse(code string) (PythonStructure, error)
	IsSafe(code string) (bool, SafetyReport)
	ExtractDangerousPatterns(code string) []DangerousPattern
	GetSemanticOperations(code string) ([]SemanticOperation, error)
}

// PythonStructure represents parsed Python code structure
type PythonStructure struct {
	Imports        []string
	Functions      []PythonFunction
	Classes        []PythonClass
	Statements     []PythonStatement
	DangerousCalls []DangerousCall
	WithStatements []WithStatement
}

// WithStatement represents a Python with statement
type WithStatement struct {
	Resource      string
	Variable      string
	BodyLines     []string
	Line          int
	OpensForWrite bool
}

// PythonFunction represents a Python function
type PythonFunction struct {
	Name        string
	Parameters  []string
	Body        string
	Calls       []FunctionCall
	IsDangerous bool
	Line        int
}

// PythonClass represents a Python class
type PythonClass struct {
	Name       string
	Methods    []PythonFunction
	Attributes []string
	Line       int
}

// PythonStatement represents a Python statement
type PythonStatement struct {
	Type   string
	Line   int
	Target string
}

// FunctionCall represents a function call
type FunctionCall struct {
	Name        string
	Arguments   []string
	IsDangerous bool
	DangerLevel string // "low", "medium", "high"
	Line        int
}

// DangerousCall represents a dangerous function call
type DangerousCall struct {
	FunctionCall
	Reason string
}

// NewPythonCodeAnalyzer creates a new Python code analyzer
func NewPythonCodeAnalyzer() PythonCodeAnalyzer {
	return &pythonAnalyzer{
		dangerousFunctions: map[string]bool{
			"open":          true,
			"os.system":     true,
			"os.popen":      true,
			"subprocess":    true,
			"eval":          true,
			"exec":          true,
			"compile":       true,
			"__import__":    true,
			"importlib":     true,
			"pickle.load":   true,
			"yaml.load":     true,
			"marshal.loads": true,
			"shelve":        true,
			"xml.etree":     true,
			"tempfile":      true,
		},
		dangerousPatterns: []*regexp.Regexp{
			regexp.MustCompile(`os\.system\s*\(`),
			regexp.MustCompile(`os\.popen\s*\(`),
			regexp.MustCompile(`subprocess\.(call|run|Popen|check_call|check_output)\s*\(`),
			regexp.MustCompile(`eval\s*\([^)]*\)`),
			regexp.MustCompile(`exec\s*\([^)]*\)`),
			regexp.MustCompile(`compile\s*\([^)]*\)`),
			regexp.MustCompile(`__import__\s*\(`),
			regexp.MustCompile(`pickle\.loads?\s*\(`),
			regexp.MustCompile(`yaml\.load\s*\([^)]*Loader=(?:None|SafeLoader)`),
			regexp.MustCompile(`eval\s*\(\s*input\s*\(`),
			regexp.MustCompile(`exec\s*\(\s*compile\s*\(`),
			regexp.MustCompile(`open\s*\([^)]*[\"']w[\"'][^)]*\)`),
			regexp.MustCompile(`open\s*\([^)]*[\"']a[\"'][^)]*\)`),
			regexp.MustCompile(`tempfile\.(mktemp|NamedTemporaryFile)\s*\(`),
			regexp.MustCompile(`os\.chmod\s*\(`),
			regexp.MustCompile(`os\.chown\s*\(`),
			regexp.MustCompile(`os\.remove\s*\(`),
			regexp.MustCompile(`os\.unlink\s*\(`),
			regexp.MustCompile(`os\.rmdir\s*\(`),
			regexp.MustCompile(`os\.mkfifo\s*\(`),
		},
		safeModules: map[string]bool{
			"os":          true,
			"sys":         true,
			"json":        true,
			"re":          true,
			"math":        true,
			"datetime":    true,
			"collections": true,
			"itertools":   true,
			"functools":   true,
			"string":      true,
			"pathlib":     true,
			"typing":      true,
			"enum":        true,
			"abc":         true,
		},
	}
}

type pythonAnalyzer struct {
	dangerousFunctions map[string]bool
	dangerousPatterns  []*regexp.Regexp
	safeModules        map[string]bool
}

var (
	osSystemPattern           = regexp.MustCompile(`os\.system\s*\(\s*([^)]+)\s*\)`)
	subprocessCallPattern     = regexp.MustCompile(`subprocess\.(call|run|Popen|check_call|check_output)\s*\(\s*(\[.*?\]|".*?"|'.*?')\s*(?:,\s*[^)]+)?\)`)
	subprocessShellCmdPattern = regexp.MustCompile(`subprocess\.(call|run|Popen|check_call|check_output)\s*\(\s*shell\s*=\s*(?:True|true)\s*,\s*cmd\s*=\s*(\[.*?\]|".*?"|'.*?')\s*(?:,|\))`)
)

// Parse extracts imports, functions, and structure from Python code
func (pa *pythonAnalyzer) Parse(code string) (PythonStructure, error) {
	structure := PythonStructure{
		Imports:        make([]string, 0),
		Functions:      make([]PythonFunction, 0),
		Classes:        make([]PythonClass, 0),
		Statements:     make([]PythonStatement, 0),
		DangerousCalls: make([]DangerousCall, 0),
		WithStatements: make([]WithStatement, 0),
	}

	lines := strings.Split(code, "\n")
	inFunction := false
	inClass := false
	currentFunc := PythonFunction{}
	currentClass := PythonClass{}

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Parse imports
		if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "from ") {
			pa.parseImport(trimmed, &structure)
			continue
		}

		// Parse with statement
		if strings.HasPrefix(trimmed, "with ") {
			pa.parseWithStatement(trimmed, lineNum, &structure)
			continue
		}

		// Parse class definition
		if strings.HasPrefix(trimmed, "class ") {
			if inClass && currentClass.Name != "" {
				structure.Classes = append(structure.Classes, currentClass)
			}
			inClass = true
			inFunction = false
			className := pa.extractClassName(trimmed)
			currentClass = PythonClass{
				Name:       className,
				Methods:    make([]PythonFunction, 0),
				Attributes: make([]string, 0),
				Line:       lineNum + 1,
			}
			continue
		}

		// Parse function definition
		if strings.HasPrefix(trimmed, "def ") {
			if inFunction && currentFunc.Name != "" {
				if inClass {
					currentClass.Methods = append(currentClass.Methods, currentFunc)
				} else {
					structure.Functions = append(structure.Functions, currentFunc)
				}
			}
			inFunction = true
			funcName := pa.extractFunctionName(trimmed)
			params := pa.extractParameters(trimmed)
			currentFunc = PythonFunction{
				Name:        funcName,
				Parameters:  params,
				Body:        "",
				Calls:       make([]FunctionCall, 0),
				IsDangerous: false,
				Line:        lineNum + 1,
			}
			continue
		}

		// Parse function calls within code
		pa.parseFunctionCalls(trimmed, lineNum+1, &structure)

		// Parse open() calls
		if strings.Contains(trimmed, "open(") {
			pa.parseOpenCall(trimmed, lineNum+1, &structure)
		}

		// Update current function body
		if inFunction {
			currentFunc.Body += line + "\n"
			pa.parseFunctionCalls(line, lineNum+1, &structure)
		}
	}

	// Add last function/class if in progress
	if inFunction && currentFunc.Name != "" {
		if inClass {
			currentClass.Methods = append(currentClass.Methods, currentFunc)
		} else {
			structure.Functions = append(structure.Functions, currentFunc)
		}
	}
	if inClass && currentClass.Name != "" {
		structure.Classes = append(structure.Classes, currentClass)
	}

	return structure, nil
}

func (pa *pythonAnalyzer) parseImport(line string, structure *PythonStructure) {
	if strings.HasPrefix(line, "import ") {
		parts := strings.Split(strings.TrimPrefix(line, "import "), ",")
		for _, part := range parts {
			module := strings.TrimSpace(part)
			structure.Imports = append(structure.Imports, "import "+module)
		}
	} else if strings.HasPrefix(line, "from ") {
		structure.Imports = append(structure.Imports, line)
	}
}

func (pa *pythonAnalyzer) extractClassName(line string) string {
	line = strings.TrimPrefix(line, "class ")
	if idx := strings.IndexAny(line, "(:"); idx >= 0 {
		line = line[:idx]
	}
	return strings.TrimSpace(line)
}

func (pa *pythonAnalyzer) extractFunctionName(line string) string {
	line = strings.TrimPrefix(line, "def ")
	if idx := strings.Index(line, "("); idx >= 0 {
		line = line[:idx]
	}
	return strings.TrimSpace(line)
}

func (pa *pythonAnalyzer) extractParameters(line string) []string {
	if idx := strings.Index(line, "("); idx >= 0 {
		line = line[idx+1:]
		if idx := strings.Index(line, ")"); idx >= 0 {
			line = line[:idx]
		}
		params := strings.Split(line, ",")
		result := make([]string, 0)
		for _, p := range params {
			p = strings.TrimSpace(p)
			if p != "" {
				result = append(result, p)
			}
		}
		return result
	}
	return nil
}

func (pa *pythonAnalyzer) parseFunctionCalls(line string, lineNum int, structure *PythonStructure) {
	// Match function calls like func(...) or obj.method(...)
	callPattern := regexp.MustCompile(`(\w+(?:\.\w+)?)\s*\(([^)]*)\)`)
	matches := callPattern.FindAllStringSubmatch(line, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			funcName := match[1]
			args := pa.splitArgs(match[2])
			isDangerous := pa.dangerousFunctions[funcName]
			dangerLevel := "low"

			if isDangerous {
				dangerLevel = "high"
			} else if strings.Contains(funcName, "system") || strings.Contains(funcName, "popen") {
				isDangerous = true
				dangerLevel = "high"
			}

			structure.Statements = append(structure.Statements, PythonStatement{
				Type:   "function_call",
				Line:   lineNum,
				Target: funcName,
			})

			if isDangerous {
				structure.DangerousCalls = append(structure.DangerousCalls, DangerousCall{
					FunctionCall: FunctionCall{
						Name:        funcName,
						Arguments:   args,
						IsDangerous: true,
						DangerLevel: dangerLevel,
						Line:        lineNum,
					},
					Reason: fmt.Sprintf("Dangerous function: %s", funcName),
				})
			}
		}
	}
}

func (pa *pythonAnalyzer) parseOpenCall(line string, lineNum int, structure *PythonStructure) {
	openPattern := regexp.MustCompile(`open\s*\(\s*([^\s,()]+)\s*,\s*([^\s,()]+)\s*\)`)
	matches := openPattern.FindAllStringSubmatch(line, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			path := strings.Trim(match[1], "'\"")
			mode := strings.Trim(match[2], "'\"")

			isWrite := strings.ContainsAny(mode, "wa")
			structure.Statements = append(structure.Statements, PythonStatement{
				Type:   "file_operation",
				Line:   lineNum,
				Target: path,
			})

			if isWrite {
				structure.DangerousCalls = append(structure.DangerousCalls, DangerousCall{
					FunctionCall: FunctionCall{
						Name:        "open",
						Arguments:   []string{path, mode},
						IsDangerous: true,
						DangerLevel: "medium",
						Line:        lineNum,
					},
					Reason: fmt.Sprintf("File write operation: open(%s, %s)", path, mode),
				})
			}
		}
	}
}

func (pa *pythonAnalyzer) parseWithStatement(line string, lineNum int, structure *PythonStructure) {
	withPattern := regexp.MustCompile(`with\s+(?:(?:open|file)\s*\([^)]*\)|[\w.]+)\s*(?:as\s+(\w+))?\s*:`)
	matches := withPattern.FindStringSubmatch(line)

	resource := ""
	variable := ""
	opensForWrite := false

	if len(matches) >= 2 {
		variable = matches[1]
	}

	if strings.Contains(line, "open(") {
		openPattern := regexp.MustCompile(`open\s*\(\s*([^,\s()]+)`)
		if openMatches := openPattern.FindStringSubmatch(line); len(openMatches) >= 2 {
			resource = strings.Trim(openMatches[1], "'\"")
		}
		if strings.Contains(line, "\"w\"") || strings.Contains(line, "'w'") ||
			strings.Contains(line, "\"a\"") || strings.Contains(line, "'a'") ||
			strings.Contains(line, "\"w+\"") || strings.Contains(line, "'w+'") {
			opensForWrite = true
		}
	} else {
		resource = strings.TrimPrefix(strings.TrimPrefix(line, "with "), " ")
		if idx := strings.Index(resource, " "); idx > 0 {
			resource = resource[:idx]
		}
		if idx := strings.Index(resource, " as"); idx > 0 {
			resource = resource[:idx]
		}
	}

	structure.WithStatements = append(structure.WithStatements, WithStatement{
		Resource:      resource,
		Variable:      variable,
		BodyLines:     make([]string, 0),
		Line:          lineNum + 1,
		OpensForWrite: opensForWrite,
	})

	if opensForWrite {
		structure.DangerousCalls = append(structure.DangerousCalls, DangerousCall{
			FunctionCall: FunctionCall{
				Name:        "with_open",
				Arguments:   []string{resource, "w"},
				IsDangerous: true,
				DangerLevel: "medium",
				Line:        lineNum + 1,
			},
			Reason: fmt.Sprintf("with statement opens file for writing: %s", resource),
		})
	}
}

func (pa *pythonAnalyzer) splitArgs(args string) []string {
	if args == "" {
		return nil
	}
	result := make([]string, 0)
	current := ""
	depth := 0

	for _, c := range args {
		if c == '(' {
			depth++
			current += string(c)
		} else if c == ')' {
			depth--
			current += string(c)
		} else if c == ',' && depth == 0 {
			result = append(result, strings.TrimSpace(current))
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, strings.TrimSpace(current))
	}
	return result
}

// extractOsSystemCommand extracts shell commands passed to os.system() calls.
// Returns a slice of command strings found in the code.
func (pa *pythonAnalyzer) extractOsSystemCommand(code string) []string {
	commands := make([]string, 0)
	matches := osSystemPattern.FindAllStringSubmatch(code, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			cmd := strings.Trim(match[1], " \"'")
			if cmd != "" {
				commands = append(commands, cmd)
			}
		}
	}
	return commands
}

// extractSubprocessCommands extracts shell commands from subprocess calls.
// Handles subprocess.run(), subprocess.call(), subprocess.Popen(), etc.
// Returns a slice of command argument strings found in the code.
func (pa *pythonAnalyzer) extractSubprocessCommands(code string) []string {
	commands := make([]string, 0)

	callMatches := subprocessCallPattern.FindAllStringSubmatch(code, -1)

	for _, match := range callMatches {
		if len(match) >= 3 {
			cmdArgs := strings.Trim(match[2], " \"'")
			commands = append(commands, cmdArgs)
		}
	}

	shellMatches := subprocessShellCmdPattern.FindAllStringSubmatch(code, -1)

	for _, match := range shellMatches {
		if len(match) >= 3 {
			cmdArgs := strings.Trim(match[2], " \"'")
			commands = append(commands, cmdArgs)
		}
	}

	return commands
}

// extractPythonShellCommands combines extraction from os.system and subprocess calls.
// Returns all extracted shell commands for further analysis.
func (pa *pythonAnalyzer) extractPythonShellCommands(code string) []string {
	commands := make([]string, 0)

	commands = append(commands, pa.extractOsSystemCommand(code)...)
	commands = append(commands, pa.extractSubprocessCommands(code)...)

	return commands
}

// IsSafe performs safety analysis on Python code
func (pa *pythonAnalyzer) IsSafe(code string) (bool, SafetyReport) {
	report := SafetyReport{
		RiskScore:         0,
		DangerousPatterns: make([]DangerousPattern, 0),
		Recommendations:   make([]string, 0),
	}

	structure, err := pa.Parse(code)
	if err != nil {
		report.Recommendations = append(report.Recommendations, fmt.Sprintf("Parse error: %v", err))
		return false, report
	}

	// Check for dangerous imports
	for _, imp := range structure.Imports {
		for danger := range pa.dangerousFunctions {
			module := strings.Split(danger, ".")[0]
			if strings.Contains(imp, module) && !pa.safeModules[module] {
				report.RiskScore += 15
				report.DangerousPatterns = append(report.DangerousPatterns, DangerousPattern{
					Pattern:     imp,
					Location:    CodeLocation{Line: 1},
					Severity:    "medium",
					Description: fmt.Sprintf("Dangerous import: %s", imp),
					Category:    "import",
				})
			}
		}
	}

	// Check for dangerous calls
	for _, call := range structure.DangerousCalls {
		report.RiskScore += 20
		report.DangerousPatterns = append(report.DangerousPatterns, DangerousPattern{
			Pattern:     call.Name,
			Location:    CodeLocation{Line: call.Line},
			Severity:    call.DangerLevel,
			Description: call.Reason,
			Category:    "function_call",
		})
	}

	// Check for file write operations
	for _, stmt := range structure.Statements {
		if stmt.Type == "file_operation" {
			report.RiskScore += 10
		}
	}

	if report.RiskScore > 50 {
		report.Recommendations = append(report.Recommendations, "High risk detected - review required")
	}

	report.IsSafe = report.RiskScore < 30 && len(structure.DangerousCalls) == 0
	return report.IsSafe, report
}

// ExtractDangerousPatterns identifies specific dangerous patterns
func (pa *pythonAnalyzer) ExtractDangerousPatterns(code string) []DangerousPattern {
	patterns := make([]DangerousPattern, 0)
	lines := strings.Split(code, "\n")
	lineNum := 0

	for _, line := range lines {
		lineNum++
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		for _, pattern := range pa.dangerousPatterns {
			if pattern.MatchString(trimmed) {
				matches := pattern.FindAllString(trimmed, -1)
				for _, match := range matches {
					patterns = append(patterns, DangerousPattern{
						Pattern:     match,
						Location:    CodeLocation{Line: lineNum},
						Severity:    "high",
						Description: "Dangerous Python pattern detected",
						Category:    "python_code",
					})
				}
			}
		}
	}

	return patterns
}

// GetSemanticOperations converts Python code to semantic operations
func (pa *pythonAnalyzer) GetSemanticOperations(code string) ([]SemanticOperation, error) {
	operations := make([]SemanticOperation, 0)
	structure, err := pa.Parse(code)
	if err != nil {
		return nil, err
	}

	// Add operations for file reads
	for _, stmt := range structure.Statements {
		if stmt.Type == "file_operation" {
			if strings.Contains(stmt.Target, "r") || !strings.Contains(stmt.Target, "w") {
				operations = append(operations, SemanticOperation{
					OperationType: OpRead,
					TargetPath:    stmt.Target,
					Context:       "python_file_read",
					Parameters:    map[string]interface{}{"line": stmt.Line},
				})
			} else {
				operations = append(operations, SemanticOperation{
					OperationType: OpWrite,
					TargetPath:    stmt.Target,
					Context:       "python_file_write",
					Parameters:    map[string]interface{}{"line": stmt.Line},
				})
			}
		}
	}

	// Add operations for dangerous function calls
	for _, call := range structure.DangerousCalls {
		params := map[string]interface{}{
			"line":         call.Line,
			"danger_level": call.DangerLevel,
			"reason":       call.Reason,
		}

		nestedCmds := pa.extractPythonShellCommands(code)
		if len(nestedCmds) > 0 {
			params["nested_commands"] = nestedCmds
		}

		operations = append(operations, SemanticOperation{
			OperationType: OpExecute,
			TargetPath:    call.Name,
			Context:       "python_dangerous_call",
			Parameters:    params,
		})
	}

	// Add read operations for imports
	for _, imp := range structure.Imports {
		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    imp,
			Context:       "python_import",
			Parameters:    map[string]interface{}{},
		})
	}

	return operations, nil
}
