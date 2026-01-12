package dsl

import (
	"fmt"
	"strconv"
)

// Token represents a lexical token in the DSL
type Token struct {
	Type    TokenType
	Value   string
	Literal string
	Line    int
	Column  int
}

// TokenType represents the type of token
type TokenType int

const (
	TokenUnknown TokenType = iota
	TokenEOF
	TokenIdentifier
	TokenNumber
	TokenString
	TokenSymbol
	TokenComment
)

// Lexer tokenizes the DSL input
type Lexer struct {
	input        string
	position     int
	readPosition int
	ch           byte
	line         int
	column       int
}

func NewLexer(input string) *Lexer {
	l := &Lexer{
		input:    input,
		line:     1,
		column:   1,
	}
	l.readChar()
	return l
}

func (l *Lexer) readChar() {
	if l.readPosition >= len(l.input) {
		l.ch = 0
	} else {
		l.ch = l.input[l.readPosition]
	}
	l.position = l.readPosition
	l.readPosition++
	l.column++
}

func (l *Lexer) NextToken() Token {
	var tok Token

	l.skipWhitespace()

	switch l.ch {
	case 0:
		tok = Token{Type: TokenEOF, Line: l.line, Column: l.column}
	case 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
		'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
		'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '_':
		tok.Literal = l.readIdentifier()
		tok.Type = TokenIdentifier
		tok.Value = tok.Literal
		tok.Line = l.line
		tok.Column = l.column
		return tok
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		tok.Type = TokenNumber
		tok.Literal = l.readNumber()
		tok.Value = tok.Literal
		tok.Line = l.line
		tok.Column = l.column
		return tok
	case '"':
		tok.Type = TokenString
		tok.Literal = l.readString()
		tok.Value = tok.Literal
		tok.Line = l.line
		tok.Column = l.column
		return tok
	case '#':
		tok.Type = TokenComment
		tok.Literal = l.readComment()
		tok.Value = tok.Literal
		tok.Line = l.line
		tok.Column = l.column
		return tok
	case ':', '[', ']', '-', '.', '/', '*':
		tok.Type = TokenSymbol
		tok.Literal = string(l.ch)
		tok.Value = tok.Literal
		tok.Line = l.line
		tok.Column = l.column
		l.readChar()
		return tok
	default:
		tok = Token{Type: TokenUnknown, Value: string(l.ch), Line: l.line, Column: l.column}
		l.readChar()
		return tok
	}

	return Token{Type: TokenEOF, Line: l.line, Column: l.column}
}

func (l *Lexer) readIdentifier() string {
	position := l.position
	for isLetter(l.ch) {
		l.readChar()
	}
	return l.input[position:l.position]
}

func (l *Lexer) readNumber() string {
	position := l.position
	for isDigit(l.ch) {
		l.readChar()
	}
	return l.input[position:l.position]
}

func (l *Lexer) readString() string {
	position := l.position + 1
	for {
		l.readChar()
		if l.ch == '"' || l.ch == 0 {
			break
		}
	}
	// Extract string content (excluding the closing quote)
	strContent := l.input[position:l.position]
	// Consume the closing quote if present
	if l.ch == '"' {
		l.readChar()
	}
	return strContent
}

func (l *Lexer) readComment() string {
	position := l.position
	for l.ch != '\n' && l.ch != 0 {
		l.readChar()
	}
	return l.input[position:l.position]
}

func (l *Lexer) skipWhitespace() {
	for l.ch == ' ' || l.ch == '\t' || l.ch == '\n' || l.ch == '\r' {
		if l.ch == '\n' {
			l.line++
			l.column = 1
		}
		l.readChar()
	}
}

func isLetter(ch byte) bool {
	return 'a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || ch == '_'
}

func isDigit(ch byte) bool {
	return '0' <= ch && ch <= '9'
}

// Parser parses the DSL tokens into AST
type Parser struct {
	l         *Lexer
	curToken  Token
	peekToken Token
	errors    []string
}

func NewParser(l *Lexer) *Parser {
	p := &Parser{
		l:      l,
		errors: []string{},
	}

	// Read two tokens to initialize
	p.nextToken()
	p.nextToken()

	return p
}

func (p *Parser) nextToken() {
	p.curToken = p.peekToken
	p.peekToken = p.l.NextToken()
}

func (p *Parser) Parse() (*AST, error) {
	ast := &AST{
		Rules:      []AccessRule{},
		Workflows:  []Workflow{},
		TempConfig: nil,
	}

	for p.curToken.Type != TokenEOF {
		if p.curToken.Type == TokenComment {
			p.nextToken()
			continue
		}

		if p.curToken.Type == TokenIdentifier && p.curToken.Value == "commands" {
			p.nextToken()
			if p.curToken.Type == TokenSymbol && p.curToken.Value == ":" {
				p.nextToken()
				ast.Rules = p.parseCommands()
			} else {
				p.addError(fmt.Sprintf("expected ':' after 'commands', got %s", p.curToken.Value))
			}
		} else if p.curToken.Type == TokenIdentifier && p.curToken.Value == "workflows" {
			p.nextToken()
			if p.curToken.Type == TokenSymbol && p.curToken.Value == ":" {
				p.nextToken()
				ast.Workflows = p.parseWorkflows()
			} else {
				p.addError(fmt.Sprintf("expected ':' after 'workflows', got %s", p.curToken.Value))
			}
		} else if p.curToken.Type == TokenIdentifier && p.curToken.Value == "temp_files" {
			p.nextToken()
			if p.curToken.Type == TokenSymbol && p.curToken.Value == ":" {
				p.nextToken()
				ast.TempConfig = p.parseTempConfig()
			} else {
				p.addError(fmt.Sprintf("expected ':' after 'temp_files', got %s", p.curToken.Value))
			}
		} else {
			p.addError(fmt.Sprintf("unexpected token: %s", p.curToken.Value))
			p.nextToken()
		}
	}

	if len(p.errors) > 0 {
		return nil, fmt.Errorf("parse errors: %v", p.errors)
	}

	return ast, nil
}

func (p *Parser) parseCommands() []AccessRule {
	var rules []AccessRule

	for p.curToken.Type != TokenEOF && p.curToken.Type != TokenSymbol && p.curToken.Value != "workflows:" && p.curToken.Value != "temp_files:" {
		if p.curToken.Type == TokenIdentifier {
			cmdName := p.curToken.Value
			p.nextToken()

			if p.curToken.Type == TokenSymbol && p.curToken.Value == ":" {
				p.nextToken()
				rules = append(rules, p.parseCommandRules(cmdName)...)
			}
		} else {
			p.nextToken()
		}
	}

	return rules
}

func (p *Parser) parseWorkflows() []Workflow {
	var workflows []Workflow

	for p.curToken.Type != TokenEOF && p.curToken.Type != TokenSymbol && p.curToken.Value != "temp_files:" {
		if p.curToken.Type == TokenIdentifier {
			name := p.curToken.Value
			p.nextToken()

			if p.curToken.Type == TokenSymbol && p.curToken.Value == ":" {
				p.nextToken()
				workflow := Workflow{Name: name}
				workflow.Rules = p.parseWorkflowRules()
				workflows = append(workflows, workflow)
			}
		} else {
			p.nextToken()
		}
	}

	return workflows
}

func (p *Parser) parseWorkflowRules() []AccessRule {
	var rules []AccessRule

	for p.curToken.Type != TokenEOF && p.curToken.Value != "temp_files:" {
		if p.curToken.Type == TokenSymbol && p.curToken.Value == "-" {
			p.nextToken() // consume "-"
			if p.curToken.Type == TokenIdentifier && p.curToken.Value == "allow" {
				p.nextToken() // consume "allow"
				if p.curToken.Type == TokenIdentifier {
					cmdName := p.curToken.Value
					p.nextToken()
					rules = append(rules, p.parseCommandRules(cmdName)...)
				}
			}
		} else {
			break
		}
	}

	return rules
}

func (p *Parser) parseTempConfig() *TempConfig {
	if p.curToken.Type != TokenIdentifier {
		return nil
	}

	config := &TempConfig{}

	for p.curToken.Type != TokenEOF {
		if p.curToken.Type == TokenIdentifier {
			key := p.curToken.Value
			p.nextToken()

			if p.curToken.Type == TokenSymbol && p.curToken.Value == ":" {
				p.nextToken()
				if p.curToken.Type == TokenString || p.curToken.Type == TokenNumber {
					value := p.curToken.Value
					p.nextToken()

					switch key {
					case "pattern":
						config.Pattern = value
					case "max_size":
						config.MaxSize = value
					case "max_count":
						if num, err := strconv.Atoi(value); err == nil {
							config.MaxCount = num
						}
					case "auto_cleanup":
						config.AutoCleanup = value
					}
				}
			}
		} else {
			break
		}
	}

	return config
}

func (p *Parser) parseCommandRules(cmdName string) []AccessRule {
	var rules []AccessRule

	for p.curToken.Type != TokenEOF && p.curToken.Value != "workflows:" && p.curToken.Value != "temp_files:" {
		if p.curToken.Type == TokenSymbol && p.curToken.Value == "-" {
			p.nextToken() // consume "-"
			if p.curToken.Type == TokenIdentifier {
				rule := p.parseAccessRule(cmdName)
				rules = append(rules, rule)
			}
		} else {
			break
		}
	}

	return rules
}

func (p *Parser) parseAccessRule(cmdName string) AccessRule {
	rule := AccessRule{
		Command: cmdName,
	}

	// Parse operation type
	if p.curToken.Type == TokenIdentifier {
		opType := p.parseOperationType(p.curToken.Value)
		p.nextToken()

		// Parse directory access or redirect target
		if p.curToken.Type == TokenIdentifier && (p.curToken.Value == "at" || p.curToken.Value == "super" || p.curToken.Value == "sub") {
			accessType := p.curToken.Value
			p.nextToken()

			if accessType == "at" {
				if p.curToken.Type == TokenString {
					path := p.curToken.Value
					p.nextToken()
					rule.Directories = append(rule.Directories, DirectoryAccess{
						Path:  path,
						Level: AccessAt,
					})
					rule.Operations = append(rule.Operations, FileOperation{
						OpType: opType,
					})
				}
			} else if accessType == "super" || accessType == "sub" {
				if p.curToken.Type == TokenSymbol && p.curToken.Value == "[" {
					p.nextToken()
					if p.curToken.Type == TokenNumber {
						depth, _ := strconv.Atoi(p.curToken.Value)
						p.nextToken()
						if p.curToken.Type == TokenSymbol && p.curToken.Value == "]" {
							p.nextToken()
							if p.curToken.Type == TokenString {
								path := p.curToken.Value
								p.nextToken()
								level := AccessSuper
								if accessType == "sub" {
									level = AccessSub
								}
								rule.Directories = append(rule.Directories, DirectoryAccess{
									Path:  path,
									Level: level,
									Depth: depth,
								})
								rule.Operations = append(rule.Operations, FileOperation{
									OpType: opType,
								})
							}
						}
					}
				}
			}
		} else if opType == OpRedirect && p.curToken.Type == TokenIdentifier && p.curToken.Value == "to" {
			p.nextToken() // consume "to"
			if p.curToken.Type == TokenString {
				path := p.curToken.Value
				p.nextToken()
				rule.Operations = append(rule.Operations, FileOperation{
					OpType: opType,
					Path:   path,
					IsTemp: true,
				})
			}
		} else if opType == OpOverwrite && p.curToken.Type == TokenIdentifier && p.curToken.Value == "if" {
			p.nextToken() // consume "if"
			if p.curToken.Type == TokenIdentifier && p.curToken.Value == "created-by" {
				p.nextToken() // consume "created-by"
				if p.curToken.Type == TokenIdentifier {
					p.nextToken() // consume identifier (should be "readonlybox")
					if p.curToken.Type == TokenString {
						path := p.curToken.Value
						p.nextToken()
						rule.Operations = append(rule.Operations, FileOperation{
							OpType:      opType,
							Path:        path,
							IsTemp:      true,
							CreatedByUs: true,
						})
					}
				}
			}
		}
	}

	return rule
}

func (p *Parser) parseOperationType(value string) OperationType {
	switch value {
	case "read":
		return OpRead
	case "edit":
		return OpEdit
	case "create":
		return OpCreate
	case "write":
		return OpWrite
	case "redirect":
		return OpRedirect
	case "overwrite":
		return OpOverwrite
	default:
		p.addError(fmt.Sprintf("unknown operation type: %s", value))
		return OpRead // default to read but report error
	}
}

func (p *Parser) addError(msg string) {
	p.errors = append(p.errors, fmt.Sprintf("line %d, col %d: %s", p.curToken.Line, p.curToken.Column, msg))
}