package semantic

import (
	"strings"
)

// TokenType represents the type of a token
type TokenType int

const (
	TokenCommand TokenType = iota
	TokenArgument
	TokenPipe
	TokenRedirection
	TokenOther
)

// Token represents a parsed token from the command line
type Token struct {
	Type  TokenType
	Value string
	Pos   int
}

// Tokenizer splits a command line into tokens
type Tokenizer struct {
	// Configuration can be added here
}

// Tokenize splits a command line into tokens
func (t *Tokenizer) Tokenize(commandLine string) ([]Token, error) {
	tokens := make([]Token, 0)
	currentToken := ""
	inQuotes := false
	quoteChar := '"'
	escapeNext := false

	for i, char := range commandLine {
		if escapeNext {
			currentToken += string(char)
			escapeNext = false
			continue
		}

		switch char {
		case '\\':
			escapeNext = true
			continue

		case '"', '\'':
			if inQuotes {
				if char == quoteChar {
					inQuotes = false
					tokens = append(tokens, Token{Type: TokenArgument, Value: currentToken, Pos: i - len(currentToken)})
					currentToken = ""
				}
			} else {
				inQuotes = true
				quoteChar = char
			}

		case ' ', '\t':
			if inQuotes {
				currentToken += string(char)
			} else {
				if currentToken != "" {
					tokenType := getTokenType(currentToken)
					tokens = append(tokens, Token{Type: tokenType, Value: currentToken, Pos: i - len(currentToken)})
					currentToken = ""
				}
			}

		case '|':
			if inQuotes {
				currentToken += string(char)
			} else {
				if currentToken != "" {
					tokenType := getTokenType(currentToken)
					tokens = append(tokens, Token{Type: tokenType, Value: currentToken, Pos: i - len(currentToken)})
					currentToken = ""
				}
				tokens = append(tokens, Token{Type: TokenPipe, Value: "|", Pos: i})
			}

		case '>', '<':
			if inQuotes {
				currentToken += string(char)
			} else {
				if currentToken != "" {
					tokenType := getTokenType(currentToken)
					tokens = append(tokens, Token{Type: tokenType, Value: currentToken, Pos: i - len(currentToken)})
					currentToken = ""
				}

				// Handle multi-character operators
				redirOp := string(char)
				if i+1 < len(commandLine) && commandLine[i+1] == '>' {
					redirOp += ">"
					i++
				}

				tokens = append(tokens, Token{Type: TokenRedirection, Value: redirOp, Pos: i - len(redirOp) + 1})
			}

		default:
			currentToken += string(char)
		}
	}

	// Add the last token if there is one
	if currentToken != "" {
		tokenType := getTokenType(currentToken)
		tokens = append(tokens, Token{Type: tokenType, Value: currentToken, Pos: len(commandLine) - len(currentToken)})
	}

	return tokens, nil
}

func getTokenType(value string) TokenType {
	if value == "|" {
		return TokenPipe
	}
	if strings.ContainsAny(value, "><") {
		return TokenRedirection
	}
	if isCommand(value) {
		return TokenCommand
	}
	return TokenArgument
}

func isCommand(value string) bool {
	// Simple heuristic: commands are usually short and don't start with -
	if len(value) == 0 {
		return false
	}
	if value[0] == '-' {
		return false
	}
	if strings.Contains(value, "/") {
		return false
	}

	// Common command patterns - this is a simple heuristic
	commonCommands := map[string]bool{
		"cat": true, "ls": true, "grep": true, "find": true, "sort": true,
		"git": true, "bash": true, "sh": true, "echo": true, "rm": true,
		"cp": true, "mv": true, "ps": true, "df": true, "du": true,
		"chmod": true, "chown": true, "mkdir": true, "rmdir": true, "touch": true,
		"head": true, "tail": true, "wc": true, "sed": true, "awk": true,
	}

	return commonCommands[value]
}