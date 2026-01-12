package semantic

import (
	"testing"
)

func TestTokenizer(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected []Token
	}{
		{
			name:  "simple command",
			input: "cat file.txt",
			expected: []Token{
				{Type: TokenCommand, Value: "cat", Pos: 0},
				{Type: TokenArgument, Value: "file.txt", Pos: 4},
			},
		},
		{
			name:  "command with pipe",
			input: "cat file.txt | grep pattern",
			expected: []Token{
				{Type: TokenCommand, Value: "cat", Pos: 0},
				{Type: TokenArgument, Value: "file.txt", Pos: 4},
				{Type: TokenPipe, Value: "|", Pos: 13},
				{Type: TokenCommand, Value: "grep", Pos: 15},
				{Type: TokenArgument, Value: "pattern", Pos: 20},
			},
		},
		{
			name:  "command with redirection",
			input: "cat file.txt > output.txt",
			expected: []Token{
				{Type: TokenCommand, Value: "cat", Pos: 0},
				{Type: TokenArgument, Value: "file.txt", Pos: 4},
				{Type: TokenRedirection, Value: ">", Pos: 13},
				{Type: TokenArgument, Value: "output.txt", Pos: 15},
			},
		},
	}

	tokenizer := &Tokenizer{}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokens, err := tokenizer.Tokenize(tc.input)
			if err != nil {
				t.Fatalf("Tokenization failed: %v", err)
			}

			if len(tokens) != len(tc.expected) {
				t.Errorf("Expected %d tokens, got %d", len(tc.expected), len(tokens))
			}

			for i, token := range tokens {
				if token.Type != tc.expected[i].Type {
					t.Errorf("Token %d: expected type %v, got %v", i, tc.expected[i].Type, token.Type)
				}
				if token.Value != tc.expected[i].Value {
					t.Errorf("Token %d: expected value %q, got %q", i, tc.expected[i].Value, token.Value)
				}
			}
		})
	}
}