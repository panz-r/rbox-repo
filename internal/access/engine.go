package access

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/panz/openroutertest/internal/dsl"
)

// AccessControlEngine is the core access control decision engine
type AccessControlEngine struct {
	Rules       []dsl.AccessRule
	TempFiles   map[string]TempFileInfo
	BaseDir     string
	Config      dsl.AST
}

// TempFileInfo stores metadata about temporary files
type TempFileInfo struct {
	Path        string
	Size        int64
	CreatedByUs bool
	LastUsed    int64
}

// NewAccessControlEngine creates a new access control engine
func NewAccessControlEngine(config dsl.AST) *AccessControlEngine {
	return &AccessControlEngine{
		Rules:       config.Rules,
		TempFiles:   make(map[string]TempFileInfo),
		BaseDir:     config.BaseDir,
		Config:      config,
	}
}

// CanPerform checks if a command can perform an operation on a target
func (ace *AccessControlEngine) CanPerform(cmd string, op dsl.FileOperation, context string) (bool, error) {
	// 1. Find matching command rules
	var matchingRules []dsl.AccessRule
	for _, rule := range ace.Rules {
		if rule.Command == cmd || rule.Command == "*" {
			matchingRules = append(matchingRules, rule)
		}
	}

	if len(matchingRules) == 0 {
		return false, fmt.Errorf("no rules found for command: %s", cmd)
	}

	// Track if we found matching directory/operation rules
	foundMatchingRules := false

	// 2. Check directory access
	for _, rule := range matchingRules {
		for _, dirAccess := range rule.Directories {
			if checkDirectoryAccess(context, dirAccess) {
				foundMatchingRules = true
				// 3. Check operation type
				for _, allowedOp := range rule.Operations {
					if allowedOp.OpType == op.OpType {
						// 4. Check temp file rules if applicable
						if op.IsTemp && !ace.checkTempFile(op, allowedOp) {
							continue
						}
						return true, nil
					}
				}
			}
		}
	}

	if foundMatchingRules {
		return false, nil // Access denied by rules, not by missing rules
	}
	return false, fmt.Errorf("access denied: %s %s in %s", cmd, op.OpType, context)
}

// checkDirectoryAccess checks if target path is accessible according to directory access rules
func checkDirectoryAccess(targetPath string, dirAccess dsl.DirectoryAccess) bool {
	// Normalize paths
	absTarget := path.Clean(targetPath)
	absBase := path.Clean(dirAccess.Path)

	// Check access level
	switch dirAccess.Level {
	case dsl.AccessAt:
		return absTarget == absBase

	case dsl.AccessSuper:
		// Check if target is within N parent levels
		for i := 0; i <= dirAccess.Depth; i++ {
			parent := getNthParent(absBase, i)
			if absTarget == parent {
				return true
			}
		}
		return false

	case dsl.AccessSub:
		// Check if target is within N subdirectory levels
		relPath, err := filepath.Rel(absBase, absTarget)
		if err != nil {
			return false
		}
		depth := countPathDepth(relPath)
		return depth <= dirAccess.Depth && !strings.Contains(relPath, "..")
	}

	return false
}

// getNthParent returns the Nth parent directory
func getNthParent(filePath string, n int) string {
	cleanPath := path.Clean(filePath)
	for i := 0; i < n; i++ {
		cleanPath = path.Dir(cleanPath)
	}
	return cleanPath
}

// countPathDepth counts the depth of a relative path
func countPathDepth(path string) int {
	if path == "." {
		return 0
	}
	return len(strings.Split(path, string(filepath.Separator)))
}

// checkTempFile checks temporary file access rules
func (ace *AccessControlEngine) checkTempFile(op dsl.FileOperation, allowedOp dsl.FileOperation) bool {
	// Check if operation matches allowed pattern
	if allowedOp.Path != "" {
		matched, err := path.Match(allowedOp.Path, op.Path)
		if err != nil || !matched {
			return false
		}
	}

	// Check ownership if required
	if allowedOp.CreatedByUs && !op.CreatedByUs {
		return false
	}

	// Check if file is in our temp file registry
	if info, exists := ace.TempFiles[op.Path]; exists {
		return info.CreatedByUs
	}

	return true
}

// RegisterTempFile registers a temporary file created by ReadOnlyBox
func (ace *AccessControlEngine) RegisterTempFile(path string, size int64) {
	ace.TempFiles[path] = TempFileInfo{
		Path:        path,
		Size:        size,
		CreatedByUs: true,
		LastUsed:    0,
	}
}

// CanAccess checks if a command can access a specific path with a given operation
func (ace *AccessControlEngine) CanAccess(cmd string, filePath string, opType dsl.OperationType) (bool, error) {
	// Create a file operation
	fileOp := dsl.FileOperation{
		OpType: opType,
		Path:   filePath,
		IsTemp: strings.HasPrefix(filePath, "/tmp/readonlybox_"),
	}

	// Check if we created this temp file
	if fileOp.IsTemp {
		if info, exists := ace.TempFiles[filePath]; exists {
			fileOp.CreatedByUs = info.CreatedByUs
		}
	}

	// Get the directory context
	var context string
	if fileOp.IsTemp {
		// For temp files, use the base directory context
		context = ace.BaseDir
	} else {
		context = path.Dir(filePath)
		if context == "." {
			context = ace.BaseDir
		}
	}

	return ace.CanPerform(cmd, fileOp, context)
}

// GetAllowedCommands returns the list of commands that have access rules
func (ace *AccessControlEngine) GetAllowedCommands() []string {
	commands := make(map[string]bool)
	for _, rule := range ace.Rules {
		commands[rule.Command] = true
	}

	var result []string
	for cmd := range commands {
		if cmd != "*" {
			result = append(result, cmd)
		}
	}

	return result
}

// GetCommandRules returns the access rules for a specific command
func (ace *AccessControlEngine) GetCommandRules(cmd string) []dsl.AccessRule {
	var rules []dsl.AccessRule
	for _, rule := range ace.Rules {
		if rule.Command == cmd || rule.Command == "*" {
			rules = append(rules, rule)
		}
	}
	return rules
}