package semantic

import (
	"fmt"
	"testing"
)

func TestShellAnalyzer(t *testing.T) {
	analyzer := NewShellCodeAnalyzer()

	// Test 1: Simple command
	t.Run("simple command", func(t *testing.T) {
		cmds, err := analyzer.Parse("cat ./etc/hosts")
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if len(cmds) == 0 {
			t.Error("Expected at least one command")
		}
		if cmds[0].Command != "cat" {
			t.Errorf("Expected 'cat', got '%s'", cmds[0].Command)
		}
	})

	// Test 2: Pipe
	t.Run("pipe", func(t *testing.T) {
		cmds, _ := analyzer.Parse("cat ./etc/hosts | grep test")
		if len(cmds) == 0 {
			t.Error("Expected command with pipe")
		}
		if len(cmds[0].Pipes) == 0 {
			t.Error("Expected pipe in command")
		}
	})

	// Test 3: Redirection
	t.Run("redirection", func(t *testing.T) {
		cmds, _ := analyzer.Parse("echo test > ./tmp/output.txt")
		if len(cmds) == 0 {
			t.Error("Expected command with redirection")
		}
		if len(cmds[0].Redirections) == 0 {
			t.Error("Expected redirection")
		}
	})

	// Test 4: Command chaining with &&
	t.Run("command chaining &&", func(t *testing.T) {
		cmds, _ := analyzer.Parse("echo test && echo more && echo done")
		if len(cmds) < 3 {
			t.Errorf("Expected 3 commands, got %d", len(cmds))
		}
	})

	// Test 5: Command chaining with ||
	t.Run("command chaining ||", func(t *testing.T) {
		cmds, _ := analyzer.Parse("echo test || echo fallback")
		if len(cmds) < 2 {
			t.Errorf("Expected 2 commands, got %d", len(cmds))
		}
	})

	// Test 6: Export statement
	t.Run("export statement", func(t *testing.T) {
		cmds, _ := analyzer.Parse("export PATH=/usr/bin && export USER=test")
		if len(cmds) == 0 {
			t.Error("Expected export commands")
		}
		if cmds[0].Command != "export" {
			t.Errorf("Expected 'export', got '%s'", cmds[0].Command)
		}
	})

	// Test 7: For loop
	t.Run("for loop", func(t *testing.T) {
		cmds, _ := analyzer.Parse("for f in *.txt; do cat $f; done")
		if len(cmds) == 0 {
			t.Error("Expected for loop command")
		}
		if cmds[0].Command != "for" {
			t.Errorf("Expected 'for', got '%s'", cmds[0].Command)
		}
	})

	// Test 8: While loop
	t.Run("while loop", func(t *testing.T) {
		cmds, _ := analyzer.Parse("while true; do echo test; done")
		if len(cmds) == 0 {
			t.Error("Expected while loop command")
		}
		if cmds[0].Command != "while" {
			t.Errorf("Expected 'while', got '%s'", cmds[0].Command)
		}
	})

	// Test 9: If statement
	t.Run("if statement", func(t *testing.T) {
		cmds, _ := analyzer.Parse("if test -f ./file.txt; then cat ./file.txt; fi")
		if len(cmds) == 0 {
			t.Error("Expected if statement command")
		}
		if cmds[0].Command != "if" {
			t.Errorf("Expected 'if', got '%s'", cmds[0].Command)
		}
	})

	// Test 10: Safety check
	t.Run("safety check", func(t *testing.T) {
		safe, report := analyzer.IsSafe("cat ./etc/hosts | grep test > ./tmp/output.txt")
		fmt.Printf("Shell safe: %v, Risk: %d, Dangerous patterns: %d\n", safe, report.RiskScore, len(report.DangerousPatterns))
	})

	// Test 11: Dangerous patterns
	t.Run("dangerous patterns", func(t *testing.T) {
		patterns := analyzer.ExtractDangerousPatterns("rm -rf ./tmp/test")
		if len(patterns) == 0 {
			t.Error("Expected dangerous patterns")
		}
		fmt.Printf("Found %d dangerous patterns\n", len(patterns))
	})

	// Test 12: sed -i detection
	t.Run("sed -i detection", func(t *testing.T) {
		patterns := analyzer.ExtractDangerousPatterns("sed -i 's/foo/bar/' ./file.txt")
		fmt.Printf("sed -i patterns: %d\n", len(patterns))
	})

	// Test 13: find -exec detection
	t.Run("find -exec detection", func(t *testing.T) {
		patterns := analyzer.ExtractDangerousPatterns("find . -name '*.txt' -exec grep test {} \\;")
		fmt.Printf("find -exec patterns: %d\n", len(patterns))
	})

	// Test 14: Semantic operations
	t.Run("semantic operations", func(t *testing.T) {
		ops, err := analyzer.GetSemanticOperations("cat ./etc/hosts | grep test")
		if err != nil {
			t.Fatalf("GetSemanticOperations failed: %v", err)
		}
		fmt.Printf("Semantic operations: %d\n", len(ops))
	})
}

func TestPythonAnalyzer(t *testing.T) {
	analyzer := NewPythonCodeAnalyzer()

	// Test 1: Simple with statement
	t.Run("simple with statement", func(t *testing.T) {
		structure, err := analyzer.Parse(`with open("test.txt", "r") as f:
    data = f.read()
    print(data)`)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		fmt.Printf("Python: imports=%d, functions=%d, statements=%d, dangerous=%d\n",
			len(structure.Imports), len(structure.Functions), len(structure.Statements), len(structure.DangerousCalls))
	})

	// Test 2: Safety check
	t.Run("safety check", func(t *testing.T) {
		safe, report := analyzer.IsSafe(`with open("test.txt", "r") as f:
    data = f.read()
    print(data)`)
		fmt.Printf("Python safe: %v, Risk: %d, Dangerous patterns: %d\n", safe, report.RiskScore, len(report.DangerousPatterns))
	})

	// Test 3: Dangerous patterns
	t.Run("dangerous patterns", func(t *testing.T) {
		patterns := analyzer.ExtractDangerousPatterns("os.system('rm -rf /')")
		if len(patterns) == 0 {
			t.Error("Expected dangerous patterns for os.system")
		}
		fmt.Printf("Found %d dangerous patterns\n", len(patterns))
	})

	// Test 4: Semantic operations
	t.Run("semantic operations", func(t *testing.T) {
		ops, err := analyzer.GetSemanticOperations(`with open("test.txt", "r") as f:
    data = f.read()`)
		if err != nil {
			t.Fatalf("GetSemanticOperations failed: %v", err)
		}
		fmt.Printf("Semantic operations: %d\n", len(ops))
	})
}

func TestComplexScripts(t *testing.T) {
	shell := NewShellCodeAnalyzer()
	python := NewPythonCodeAnalyzer()

	// Test the example from examples.txt
	t.Run("example from file - shell", func(t *testing.T) {
		script := `cd /home/panz/osrc/mistral-vibe && export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 && . venv/bin/activate`
		cmds, _ := shell.Parse(script)
		fmt.Printf("Parsed %d commands from script\n", len(cmds))
		for i, cmd := range cmds {
			fmt.Printf("  %d: %s\n", i+1, cmd.Command)
		}
	})

	t.Run("example from file - python", func(t *testing.T) {
		script := `with open('src/checks/checkstl.rs', 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines[75:78], 76):
    spaces = len(line) - len(line.lstrip())
    print(f'Line {i}: {spaces} spaces')`
		structure, _ := python.Parse(script)
		fmt.Printf("Python: imports=%d, functions=%d, statements=%d, dangerous=%d, with_statements=%d\n",
			len(structure.Imports), len(structure.Functions), len(structure.Statements), len(structure.DangerousCalls), len(structure.WithStatements))
	})

	// Test terminal workflow patterns
	t.Run("shell - cd and export", func(t *testing.T) {
		script := `cd /home/panz/osrc/project && export VAR=value && echo done`
		cmds, _ := shell.Parse(script)
		if len(cmds) < 3 {
			t.Errorf("Expected at least 3 commands, got %d", len(cmds))
		}
	})

	t.Run("shell - source command", func(t *testing.T) {
		script := `. venv/bin/activate`
		cmds, _ := shell.Parse(script)
		if len(cmds) != 1 {
			t.Errorf("Expected 1 command, got %d", len(cmds))
		}
		if cmds[0].Command != "source" {
			t.Errorf("Expected 'source' command, got '%s'", cmds[0].Command)
		}
	})

	t.Run("shell - find with exec", func(t *testing.T) {
		patterns := shell.ExtractDangerousPatterns(`find . -name "*.txt" -exec grep test {} \;`)
		if len(patterns) == 0 {
			t.Error("Expected dangerous pattern for find -exec")
		}
	})

	t.Run("shell - sed -i", func(t *testing.T) {
		patterns := shell.ExtractDangerousPatterns(`sed -i 's/foo/bar/' file.txt`)
		if len(patterns) == 0 {
			t.Error("Expected dangerous pattern for sed -i")
		}
	})

	t.Run("shell - command substitution", func(t *testing.T) {
		script := `echo $(ls -la)`
		cmds, _ := shell.Parse(script)
		fmt.Printf("Command substitution parsed: %d commands\n", len(cmds))
	})

	t.Run("python - with open read", func(t *testing.T) {
		script := `with open('file.txt', 'r') as f:
    data = f.read()`
		structure, _ := python.Parse(script)
		if len(structure.WithStatements) != 1 {
			t.Errorf("Expected 1 with statement, got %d", len(structure.WithStatements))
		}
		if structure.WithStatements[0].OpensForWrite {
			t.Error("Expected read mode, got write mode")
		}
	})

	t.Run("python - with open write", func(t *testing.T) {
		script := `with open('file.txt', 'w') as f:
    f.write('data')`
		structure, _ := python.Parse(script)
		if len(structure.WithStatements) != 1 {
			t.Errorf("Expected 1 with statement, got %d", len(structure.WithStatements))
		}
		if !structure.WithStatements[0].OpensForWrite {
			t.Error("Expected write mode")
		}
	})

	t.Run("python - enumerate with slice", func(t *testing.T) {
		script := `for i, line in enumerate(lines[10:20], 11):
    print(i, line)`
		structure, _ := python.Parse(script)
		fmt.Printf("Python enumerate: functions=%d\n", len(structure.Functions))
	})

	t.Run("python - list comprehension", func(t *testing.T) {
		script := `data = [x.strip() for x in lines if x]`
		structure, _ := python.Parse(script)
		fmt.Printf("Python list comprehension: statements=%d\n", len(structure.Statements))
	})

	t.Run("python - f-string", func(t *testing.T) {
		script := `result = f"Line {i}: {value}"`
		structure, _ := python.Parse(script)
		fmt.Printf("Python f-string: statements=%d\n", len(structure.Statements))
	})

	// Safety tests
	t.Run("safety - safe shell script", func(t *testing.T) {
		script := `cat ./etc/hosts | grep test`
		safe, report := shell.IsSafe(script)
		fmt.Printf("Safe shell: %v, Risk: %d\n", safe, report.RiskScore)
	})

	t.Run("safety - dangerous shell script", func(t *testing.T) {
		script := `rm -rf ./tmp`
		safe, report := shell.IsSafe(script)
		if safe {
			t.Error("Expected unsafe script to be flagged")
		}
		fmt.Printf("Dangerous shell: safe=%v, Risk: %d, patterns=%d\n", safe, report.RiskScore, len(report.DangerousPatterns))
	})

	t.Run("safety - safe python script", func(t *testing.T) {
		script := `with open('file.txt', 'r') as f:
    data = f.read()`
		safe, report := python.IsSafe(script)
		fmt.Printf("Safe python: %v, Risk: %d\n", safe, report.RiskScore)
	})

	t.Run("safety - dangerous python script", func(t *testing.T) {
		script := `os.system('rm -rf /')`
		safe, report := python.IsSafe(script)
		if safe {
			t.Error("Expected unsafe script to be flagged")
		}
		fmt.Printf("Dangerous python: safe=%v, Risk: %d, patterns=%d\n", safe, report.RiskScore, len(report.DangerousPatterns))
	})
}
