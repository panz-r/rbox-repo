package dsl

import (
	"testing"
)

func TestLexer(t *testing.T) {
	input := `read at "/home/user/"`

	lexer := NewLexer(input)

	tests := []struct {
		expectedType    TokenType
		expectedLiteral string
	}{
		{TokenIdentifier, "read"},
		{TokenIdentifier, "at"},
		{TokenString, "/home/user/"},
		{TokenEOF, ""},
	}

	for i, tt := range tests {
		tok := lexer.NextToken()

		if tok.Type != tt.expectedType {
			t.Errorf("tests[%d] - tokentype wrong. expected=%q, got=%q",
				i, tt.expectedType, tok.Type)
		}

		if tok.Value != tt.expectedLiteral {
			t.Errorf("tests[%d] - literal wrong. expected=%q, got=%q",
				i, tt.expectedLiteral, tok.Value)
		}
	}
}

func TestParser(t *testing.T) {
	input := `commands:
  ls:
    - read at "/home/user/project/"
    - read sub[2] "/home/user/project/src/"
  cat:
    - read at "/home/user/project/"
    - read super[1] "/home/user/project/"
`

	lexer := NewLexer(input)
	parser := NewParser(lexer)
	ast, err := parser.Parse()

	if err != nil {
		t.Fatalf("parser error: %v", err)
	}

	if len(ast.Rules) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(ast.Rules))
	}

	// Check ls rules
	lsRules := []AccessRule{}
	for _, rule := range ast.Rules {
		if rule.Command == "ls" {
			lsRules = append(lsRules, rule)
		}
	}

	if len(lsRules) != 2 {
		t.Fatalf("expected 2 ls rules, got %d", len(lsRules))
	}

	// Check first ls rule
	if lsRules[0].Directories[0].Path != "/home/user/project/" {
		t.Errorf("expected path '/home/user/project/', got '%s'", lsRules[0].Directories[0].Path)
	}

	if lsRules[0].Directories[0].Level != AccessAt {
		t.Errorf("expected AccessAt, got %v", lsRules[0].Directories[0].Level)
	}

	// Check second ls rule
	if lsRules[1].Directories[0].Path != "/home/user/project/src/" {
		t.Errorf("expected path '/home/user/project/src/', got '%s'", lsRules[1].Directories[0].Path)
	}

	if lsRules[1].Directories[0].Level != AccessSub {
		t.Errorf("expected AccessSub, got %v", lsRules[1].Directories[0].Level)
	}

	if lsRules[1].Directories[0].Depth != 2 {
		t.Errorf("expected depth 2, got %d", lsRules[1].Directories[0].Depth)
	}
}

func TestParserErrorHandling(t *testing.T) {
	input := `commands:
  ls:
    - invalid at "/home/user/project/"
`

	lexer := NewLexer(input)
	parser := NewParser(lexer)
	_, err := parser.Parse()

	if err == nil {
		t.Fatal("expected parser error, got nil")
	}

	if err.Error() != "parse errors: [line 3, col 15: unknown operation type: invalid]" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}