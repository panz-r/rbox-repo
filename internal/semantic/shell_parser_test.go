package semantic

import (
	"testing"
)

func TestShellParser(t *testing.T) {
	parser := &ShellParser{}

	testCases := []struct {
		name     string
		tokens   []Token
		expected *ShellStructure
	}{
		{
			name: "simple command",
			tokens: []Token{
				{Type: TokenCommand, Value: "cat"},
				{Type: TokenArgument, Value: "file.txt"},
			},
			expected: &ShellStructure{
				BaseCommand: "cat",
				Arguments:   []string{"file.txt"},
			},
		},
		{
			name: "command with pipe",
			tokens: []Token{
				{Type: TokenCommand, Value: "cat"},
				{Type: TokenArgument, Value: "file.txt"},
				{Type: TokenPipe, Value: "|"},
				{Type: TokenCommand, Value: "grep"},
				{Type: TokenArgument, Value: "pattern"},
			},
			expected: &ShellStructure{
				BaseCommand: "grep",
				Arguments:   []string{"pattern"},
				Pipes: []PipeInfo{
					{
						FromCommand: "cat",
						ToCommand:   "grep",
						Position:    2,
					},
				},
			},
		},
		{
			name: "command with redirection",
			tokens: []Token{
				{Type: TokenCommand, Value: "cat"},
				{Type: TokenArgument, Value: "file.txt"},
				{Type: TokenRedirection, Value: ">"},
				{Type: TokenArgument, Value: "output.txt"},
			},
			expected: &ShellStructure{
				BaseCommand:  "cat",
				Arguments:    []string{"file.txt"},
				Redirections: []RedirectionInfo{
					{
						Operator: ">",
						Target:   "output.txt",
						Position: 2,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parser.ParseShellStructures(tc.tokens)
			if err != nil {
				t.Fatalf("Parsing failed: %v", err)
			}

			if result.BaseCommand != tc.expected.BaseCommand {
				t.Errorf("Expected base command %q, got %q", tc.expected.BaseCommand, result.BaseCommand)
			}

			if len(result.Arguments) != len(tc.expected.Arguments) {
				t.Errorf("Expected %d arguments, got %d", len(tc.expected.Arguments), len(result.Arguments))
			} else {
				for i, arg := range result.Arguments {
					if arg != tc.expected.Arguments[i] {
						t.Errorf("Argument %d: expected %q, got %q", i, tc.expected.Arguments[i], arg)
					}
				}
			}

			if len(result.Pipes) != len(tc.expected.Pipes) {
				t.Errorf("Expected %d pipes, got %d", len(tc.expected.Pipes), len(result.Pipes))
			} else {
				for i, pipe := range result.Pipes {
					if pipe.FromCommand != tc.expected.Pipes[i].FromCommand {
						t.Errorf("Pipe %d: expected from command %q, got %q", i, tc.expected.Pipes[i].FromCommand, pipe.FromCommand)
					}
					if pipe.ToCommand != tc.expected.Pipes[i].ToCommand {
						t.Errorf("Pipe %d: expected to command %q, got %q", i, tc.expected.Pipes[i].ToCommand, pipe.ToCommand)
					}
				}
			}

			if len(result.Redirections) != len(tc.expected.Redirections) {
				t.Errorf("Expected %d redirections, got %d", len(tc.expected.Redirections), len(result.Redirections))
			} else {
				for i, redir := range result.Redirections {
					if redir.Operator != tc.expected.Redirections[i].Operator {
						t.Errorf("Redirection %d: expected operator %q, got %q", i, tc.expected.Redirections[i].Operator, redir.Operator)
					}
					if redir.Target != tc.expected.Redirections[i].Target {
						t.Errorf("Redirection %d: expected target %q, got %q", i, tc.expected.Redirections[i].Target, redir.Target)
					}
				}
			}
		})
	}
}