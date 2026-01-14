package semantic

import (
	"fmt"
	"strconv"
	"strings"
)

// FindCommand represents a parsed find command
type FindCommand struct {
	StartPaths     []string
	Options        map[string]interface{}
	Expressions    []FindExpression
	MaxDepth       int
	MinDepth       int
	FollowSymlinks bool
	IgnoreErrors   bool
}

// FindExpression represents a find expression (test, action, etc.)
type FindExpression struct {
	Type       string // "test", "action", "operator"
	Name       string // e.g., "name", "type", "exec"
	Value      string // e.g., "*.txt", "f"
	Parameters map[string]interface{}
}

// FindParser parses find commands
type FindParser struct{}

// ParseArguments implements CommandParser for find commands
func (f *FindParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for find")
	}

	cmd := &FindCommand{
		Options: make(map[string]interface{}),
		Expressions: make([]FindExpression, 0),
	}

	i := 0
	// Parse start paths
	for i < len(args) && !strings.HasPrefix(args[i], "-") && !isFindExpression(args[i]) {
		cmd.StartPaths = append(cmd.StartPaths, args[i])
		i++
	}

	// Parse options and expressions
	for i < len(args) {
		arg := args[i]

		if strings.HasPrefix(arg, "-") {
			// Check if it's a find expression first
			if isFindExpression(arg) {
				// Parse find expression
				expr, argsConsumed, err := parseFindExpression(args[i:])
				if err != nil {
					return nil, fmt.Errorf("failed to parse find expression: %v", err)
				}
				cmd.Expressions = append(cmd.Expressions, expr)
				i += argsConsumed
				continue
			}

			// Handle options
			switch arg {
			case "-maxdepth":
				if i+1 >= len(args) {
					return nil, fmt.Errorf("missing value after -maxdepth")
				}
				depth, err := strconv.Atoi(args[i+1])
				if err != nil {
					return nil, fmt.Errorf("invalid maxdepth value: %s", args[i+1])
				}
				cmd.MaxDepth = depth
				cmd.Options["maxdepth"] = depth
				i += 2
				continue
			case "-mindepth":
				if i+1 >= len(args) {
					return nil, fmt.Errorf("missing value after -mindepth")
				}
				depth, err := strconv.Atoi(args[i+1])
				if err != nil {
					return nil, fmt.Errorf("invalid mindepth value: %s", args[i+1])
				}
				cmd.MinDepth = depth
				cmd.Options["mindepth"] = depth
				i += 2
				continue
			case "-L":
				cmd.FollowSymlinks = true
				cmd.Options["follow_symlinks"] = true
			case "-P":
				cmd.FollowSymlinks = false
				cmd.Options["follow_symlinks"] = false
			case "-H":
				cmd.Options["follow_symlinks"] = true
			case "-D":
				cmd.IgnoreErrors = true
				cmd.Options["ignore_errors"] = true
			default:
				// Handle other options or unknown options
				cmd.Options[arg] = true
			}
		} else {
			// Should not reach here, but handle gracefully
			i++
			continue
		}
		i++
	}

	return cmd, nil
}

// isFindExpression checks if a string looks like a find expression
func isFindExpression(arg string) bool {
	// Common find expressions
	commonExprs := []string{"name", "type", "path", "regex", "size", "mtime", "atime", "ctime", "exec", "ok", "print", "delete", "prune"}
	for _, expr := range commonExprs {
		if arg == "-"+expr {
			return true
		}
	}
	return false
}

// parseFindExpression parses a find expression and returns the expression and number of arguments consumed
func parseFindExpression(args []string) (FindExpression, int, error) {
	if len(args) == 0 {
		return FindExpression{}, 0, fmt.Errorf("empty expression")
	}

	expr := FindExpression{
		Parameters: make(map[string]interface{}),
	}

	arg := args[0]
	if !strings.HasPrefix(arg, "-") {
		return FindExpression{}, 0, fmt.Errorf("expression must start with -")
	}

	expr.Name = arg[1:] // Remove the -
	expr.Type = getFindExpressionType(expr.Name)

	// Determine if this expression takes a value
	if takesValue(expr.Name) {
		if len(args) < 2 {
			return FindExpression{}, 0, fmt.Errorf("missing value for expression -%s", expr.Name)
		}
		expr.Value = args[1]
		return expr, 2, nil
	}

	return expr, 1, nil
}

// getFindExpressionType determines the type of find expression
func getFindExpressionType(name string) string {
	// Tests
	tests := []string{"name", "type", "path", "regex", "size", "mtime", "atime", "ctime", "perm", "user", "group", "links", "newer", "anewer", "cnewer"}
	for _, test := range tests {
		if name == test {
			return "test"
		}
	}

	// Actions
	actions := []string{"exec", "ok", "print", "printf", "fprintf", "ls", "delete", "prune", "quit"}
	for _, action := range actions {
		if name == action {
			return "action"
		}
	}

	// Operators
	operators := []string{"and", "or", "not", "(", ")"}
	for _, op := range operators {
		if name == op {
			return "operator"
		}
	}

	return "unknown"
}

// takesValue returns true if the expression takes a value argument
func takesValue(name string) bool {
	// Expressions that take values
	withValues := []string{"name", "type", "path", "regex", "size", "mtime", "atime", "ctime", "perm", "user", "group", "links", "newer", "anewer", "cnewer", "exec", "ok", "printf", "fprintf"}
	for _, expr := range withValues {
		if name == expr {
			return true
		}
	}
	return false
}

// GetSemanticOperations implements CommandParser for find commands
func (f *FindParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*FindCommand)
	if !ok {
		return nil, fmt.Errorf("invalid find command type")
	}

	operations := make([]SemanticOperation, 0)

	// Add read operations for each start path
	for _, path := range cmd.StartPaths {
		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    path,
			Context:       "start_path",
			Parameters: map[string]interface{}{
				"command": "find",
				"options": cmd.Options,
			},
		})
	}

	// Analyze expressions for additional operations
	for _, expr := range cmd.Expressions {
		if expr.Type == "action" {
			switch expr.Name {
			case "exec", "ok":
				// These are dangerous operations that execute commands
				// The actual command to execute is in expr.Value
				if expr.Value != "" {
					operations = append(operations, SemanticOperation{
						OperationType: OpExecute,
						TargetPath:    expr.Value,
						Context:       "exec_action",
						Parameters: map[string]interface{}{
							"command": "find",
							"dangerous": true,
						},
					})
				}
			case "delete":
				// Delete is a dangerous operation
				operations = append(operations, SemanticOperation{
					OperationType: OpExecute,
					TargetPath:    "*", // Affects all found files
					Context:       "delete_action",
					Parameters: map[string]interface{}{
						"command": "find",
						"dangerous": true,
					},
				})
			case "print", "printf", "fprintf", "ls":
				// These are generally safe read operations
				operations = append(operations, SemanticOperation{
					OperationType: OpRead,
					TargetPath:    "*", // Affects all found files
					Context:       "print_action",
					Parameters: map[string]interface{}{
						"command": "find",
					},
				})
			}
		}
	}

	return operations, nil
}

// GetOperationGraph implements the enhanced CommandParser interface for find commands
func (f *FindParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*FindCommand)
	if !ok {
		return nil, fmt.Errorf("invalid find command type")
	}

	// Get basic semantic operations
	operations, err := f.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	// Build complete operation graph
	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("find", operations, []SemanticOperation{})

	return graph, nil
}