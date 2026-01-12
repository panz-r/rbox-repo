package semantic

import (
	"fmt"
	"strings"
)

// GitCommand represents a parsed git command
type GitCommand struct {
	Subcommand    string
	Options       map[string]interface{}
	Arguments     []string
	IsReadOnly    bool
	AffectsRemote bool
	AffectsRepo   bool
}

// GitParser parses git commands
type GitParser struct{}

// ParseArguments implements CommandParser for git commands
func (g *GitParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for git")
	}

	cmd := &GitCommand{
		Options: make(map[string]interface{}),
	}

	// First argument is the git subcommand
	cmd.Subcommand = args[0]

	// Determine command characteristics based on subcommand
	cmd.determineCommandCharacteristics()

	// Parse options and arguments
	i := 1
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		// Handle common git options
		switch opt {
		case "--help", "-h":
			cmd.Options["help"] = true
		case "--version", "-v":
			cmd.Options["version"] = true
		case "--verbose":
			cmd.Options["verbose"] = true
		case "--quiet", "-q":
			cmd.Options["quiet"] = true
		case "--dry-run":
			cmd.Options["dry_run"] = true
		case "--all", "-a":
			cmd.Options["all"] = true
		case "--force", "-f":
			cmd.Options["force"] = true
			// Force flag can make commands dangerous
			if cmd.IsReadOnly {
				cmd.IsReadOnly = false
			}
		default:
			// Handle subcommand-specific options
			if len(opt) > 1 {
				cmd.Options[opt] = true
			}
		}
		i++
	}

	// Remaining arguments
	if i < len(args) {
		cmd.Arguments = args[i:]
	}

	return cmd, nil
}

// determineCommandCharacteristics sets command properties based on subcommand
func (g *GitCommand) determineCommandCharacteristics() {
	// Read-only commands (safe)
	readOnlyCommands := []string{
		"log", "show", "diff", "status", "grep", "blame", "annotate",
		"branch", "tag", "ls-files", "ls-tree", "cat-file",
		"config", "remote", "ls-remote", "archive",
	}

	// Commands that affect remote (potentially dangerous)
	remoteCommands := []string{
		"push", "fetch", "pull", "clone", "ls-remote",
	}

	// Commands that affect repository (potentially dangerous)
	repoCommands := []string{
		"add", "commit", "reset", "rebase", "merge", "cherry-pick", "revert",
		"am", "apply", "checkout", "clean", "stash", "submodule", "worktree",
	}

	// Check if command is read-only
	for _, safeCmd := range readOnlyCommands {
		if g.Subcommand == safeCmd {
			g.IsReadOnly = true
			return
		}
	}

	// Check if command affects remote
	for _, remoteCmd := range remoteCommands {
		if g.Subcommand == remoteCmd {
			g.AffectsRemote = true
			g.AffectsRepo = true
			return
		}
	}

	// Check if command affects repository
	for _, repoCmd := range repoCommands {
		if g.Subcommand == repoCmd {
			g.AffectsRepo = true
			return
		}
	}

	// Default: assume it might affect repository (conservative)
	g.AffectsRepo = true
}

// GetSemanticOperations implements CommandParser for git commands
func (g *GitParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*GitCommand)
	if !ok {
		return nil, fmt.Errorf("invalid git command type")
	}

	operations := make([]SemanticOperation, 0)

	// Add operations based on command type
	if cmd.IsReadOnly {
		// Read-only commands only read from repository
		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    ".git",
			Context:       "git_read",
			Parameters: map[string]interface{}{
				"command":      "git",
				"subcommand":   cmd.Subcommand,
				"read_only":    true,
				"safe":         true,
			},
		})
	} else {
		// Non read-only commands may write to repository
		operations = append(operations, SemanticOperation{
			OperationType: OpWrite,
			TargetPath:    ".git",
			Context:       "git_write",
			Parameters: map[string]interface{}{
				"command":      "git",
				"subcommand":   cmd.Subcommand,
				"read_only":    false,
				"affects_repo": cmd.AffectsRepo,
				"affects_remote": cmd.AffectsRemote,
			},
		})

		// If it affects remote, add network operation
		if cmd.AffectsRemote {
			operations = append(operations, SemanticOperation{
				OperationType: OpExecute,
				TargetPath:    "network",
				Context:       "git_network",
				Parameters: map[string]interface{}{
					"command":      "git",
					"subcommand":   cmd.Subcommand,
					"network":      true,
					"dangerous":    true,
				},
			})
		}
	}

	// Handle specific subcommands with special semantics
	switch cmd.Subcommand {
	case "log", "show", "diff":
		// These commands read commit history and file contents
		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    "*", // Can read any file in repo
			Context:       "git_content_read",
			Parameters: map[string]interface{}{
				"command": "git",
				"subcommand": cmd.Subcommand,
			},
		})
	case "add":
		// Add files to staging area
		for _, arg := range cmd.Arguments {
			if arg != "." && arg != "-A" && arg != "--all" {
				operations = append(operations, SemanticOperation{
					OperationType: OpRead,
					TargetPath:    arg,
					Context:       "git_add",
					Parameters: map[string]interface{}{
						"command": "git",
						"staging": true,
					},
				})
			}
		}
	case "commit":
		// Commit creates a new commit object
		operations = append(operations, SemanticOperation{
			OperationType: OpCreate,
			TargetPath:    ".git/objects",
			Context:       "git_commit",
			Parameters: map[string]interface{}{
				"command": "git",
				"dangerous": false, // Commit is generally safe
			},
		})
	case "push":
		// Push sends data to remote
		operations = append(operations, SemanticOperation{
			OperationType: OpExecute,
			TargetPath:    "remote",
			Context:       "git_push",
			Parameters: map[string]interface{}{
				"command": "git",
				"dangerous": true,
				"remote": true,
			},
		})
	case "pull", "fetch":
		// Pull/fetch gets data from remote
		operations = append(operations, SemanticOperation{
			OperationType: OpRead,
			TargetPath:    "remote",
			Context:       "git_fetch",
			Parameters: map[string]interface{}{
				"command": "git",
				"remote": true,
			},
		})
	case "clone":
		// Clone creates a new repository
		if len(cmd.Arguments) > 0 {
			operations = append(operations, SemanticOperation{
				OperationType: OpCreate,
				TargetPath:    cmd.Arguments[len(cmd.Arguments)-1], // Last arg is usually directory
				Context:       "git_clone",
				Parameters: map[string]interface{}{
					"command": "git",
					"remote": true,
				},
			})
		}
	case "checkout":
		// Checkout can modify working directory
		operations = append(operations, SemanticOperation{
			OperationType: OpEdit,
			TargetPath:    "*",
			Context:       "git_checkout",
			Parameters: map[string]interface{}{
				"command": "git",
				"dangerous": true, // Can overwrite files
			},
		})
	case "reset":
		// Reset can be dangerous depending on options
		if _, hardReset := cmd.Options["--hard"]; hardReset {
			operations = append(operations, SemanticOperation{
				OperationType: OpOverwrite,
				TargetPath:    "*",
				Context:       "git_reset_hard",
				Parameters: map[string]interface{}{
					"command": "git",
					"dangerous": true,
				},
			})
		}
	}

	return operations, nil
}