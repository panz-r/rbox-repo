package semantic

import (
	"fmt"
	"testing"
)

func TestMultiLineShellParser(t *testing.T) {
	parser := NewMultiLineShellParser()

	t.Run("simple multi-line script", func(t *testing.T) {
		script := `#!/bin/bash
echo "Hello"
cat file.txt
grep pattern file.txt`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if len(result.Commands) != 3 {
			t.Errorf("Expected 3 commands, got %d", len(result.Commands))
		}
		fmt.Printf("Simple script: %d commands\n", len(result.Commands))
	})

	t.Run("if statement multi-line", func(t *testing.T) {
		script := `if test -f /tmp/file.txt; then
    echo "File exists"
    cat /tmp/file.txt
else
    echo "File not found"
fi`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if len(result.Commands) != 1 {
			t.Errorf("Expected 1 command (if statement), got %d", len(result.Commands))
		}
		if result.Commands[0].Type != StmtIf {
			t.Errorf("Expected if statement, got %v", result.Commands[0].Type)
		}
		if len(result.Commands[0].ThenBody) != 2 {
			t.Errorf("Expected 2 commands in then body, got %d", len(result.Commands[0].ThenBody))
		}
		if len(result.Commands[0].ElseBody) != 1 {
			t.Errorf("Expected 1 command in else body, got %d", len(result.Commands[0].ElseBody))
		}
		fmt.Printf("If statement: then=%d, else=%d\n", len(result.Commands[0].ThenBody), len(result.Commands[0].ElseBody))
	})

	t.Run("nested if statements", func(t *testing.T) {
		script := `if [ -f file.txt ]; then
    if [ -s file.txt ]; then
        echo "File exists and is not empty"
    else
        echo "File exists but is empty"
    fi
fi`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		fmt.Printf("Nested if: commands=%d, then body=%d\n", len(result.Commands), len(result.Commands[0].ThenBody))
	})

	t.Run("for loop", func(t *testing.T) {
		script := `for f in *.txt; do
    echo "Processing $f"
    cat "$f" | grep pattern
done`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if len(result.Commands) != 1 {
			t.Errorf("Expected 1 command (for loop), got %d", len(result.Commands))
		}
		if result.Commands[0].Type != StmtFor {
			t.Errorf("Expected for statement, got %v", result.Commands[0].Type)
		}
		if result.Commands[0].IterVariable != "f" {
			t.Errorf("Expected iter variable 'f', got '%s'", result.Commands[0].IterVariable)
		}
		if len(result.Commands[0].DoBody) != 2 {
			t.Errorf("Expected 2 commands in do body, got %d", len(result.Commands[0].DoBody))
		}
		fmt.Printf("For loop: iter=%s, body=%d\n", result.Commands[0].IterVariable, len(result.Commands[0].DoBody))
	})

	t.Run("while loop", func(t *testing.T) {
		script := `count=0
while [ $count -lt 10 ]; do
    echo "Count: $count"
    count=$((count + 1))
done`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if len(result.Commands) != 2 {
			t.Errorf("Expected 2 commands, got %d", len(result.Commands))
		}
		if result.Commands[1].Type != StmtWhile {
			t.Errorf("Expected while statement, got %v", result.Commands[1].Type)
		}
		fmt.Printf("While loop: commands=%d\n", len(result.Commands))
	})

	t.Run("until loop", func(t *testing.T) {
		script := `until ping -c 1 server; do
    echo "Server is down, waiting..."
    sleep 5
done`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if result.Commands[0].Type != StmtUntil {
			t.Errorf("Expected until statement, got %v", result.Commands[0].Type)
		}
		fmt.Printf("Until loop parsed OK\n")
	})

	t.Run("case statement", func(t *testing.T) {
		script := `case "$extension" in
    txt)
        echo "Text file"
        ;;
    jpg|png)
        echo "Image file"
        ;;
    *)
        echo "Unknown file type"
        ;;
esac`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if result.Commands[0].Type != StmtCase {
			t.Errorf("Expected case statement, got %v", result.Commands[0].Type)
		}
		if len(result.Commands[0].CaseBody) != 3 {
			t.Errorf("Expected 3 case clauses, got %d", len(result.Commands[0].CaseBody))
		}
		fmt.Printf("Case statement: %d clauses\n", len(result.Commands[0].CaseBody))
	})

	t.Run("here document", func(t *testing.T) {
		script := `cat <<EOF
Hello, World!
This is a here document.
EOF`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if len(result.HereDocs) != 1 {
			t.Errorf("Expected 1 here doc, got %d", len(result.HereDocs))
		}
		if result.HereDocs[0].Delimiter != "EOF" {
			t.Errorf("Expected delimiter 'EOF', got '%s'", result.HereDocs[0].Delimiter)
		}
		fmt.Printf("Here doc: delimiter=%s, content lines=%d\n", result.HereDocs[0].Delimiter, len(result.HereDocs))
	})

	t.Run("source command", func(t *testing.T) {
		script := `. venv/bin/activate
source config.sh`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if len(result.Commands) != 2 {
			t.Errorf("Expected 2 commands, got %d", len(result.Commands))
		}
		if result.Commands[0].Type != StmtSource {
			t.Errorf("Expected source statement, got %v", result.Commands[0].Type)
		}
		fmt.Printf("Source commands: %d\n", len(result.Commands))
	})

	t.Run("export command", func(t *testing.T) {
		script := `export PATH=/usr/bin:$PATH
export VAR1=value1 VAR2=value2
export PYTHONPATH=/home/panz/osrc/project`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if len(result.Commands) != 3 {
			t.Errorf("Expected 3 commands, got %d", len(result.Commands))
		}
		fmt.Printf("Export commands: %d\n", len(result.Commands))
	})

	t.Run("complex script with cd", func(t *testing.T) {
		script := `cd /home/panz/osrc/mistral-vibe
export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1
. venv/bin/activate`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if len(result.Commands) != 3 {
			t.Errorf("Expected 3 commands, got %d", len(result.Commands))
		}
		if result.Commands[0].Type != StmtCd {
			t.Errorf("Expected cd statement, got %v", result.Commands[0].Type)
		}
		if result.Commands[1].Type != StmtExport {
			t.Errorf("Expected export statement, got %v", result.Commands[1].Type)
		}
		if result.Commands[2].Type != StmtSource {
			t.Errorf("Expected source statement, got %v", result.Commands[2].Type)
		}
		fmt.Printf("Complex script: %d commands parsed\n", len(result.Commands))
	})

	t.Run("elif branches", func(t *testing.T) {
		script := `if [ $x -eq 1 ]; then
    echo "One"
elif [ $x -eq 2 ]; then
    echo "Two"
elif [ $x -eq 3 ]; then
    echo "Three"
else
    echo "Other"
fi`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if len(result.Commands[0].ElifBodies) != 2 {
			t.Errorf("Expected 2 elif branches, got %d", len(result.Commands[0].ElifBodies))
		}
		fmt.Printf("Elif branches: %d\n", len(result.Commands[0].ElifBodies))
	})
}

func TestMultiLineShellSafety(t *testing.T) {
	parser := NewMultiLineShellParser()

	t.Run("safe script", func(t *testing.T) {
		script := `cat /etc/hosts | grep localhost
head -20 file.txt
wc -l *.txt`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		safe, report := parser.IsSafe(result)
		fmt.Printf("Safe script: safe=%v, risk=%d\n", safe, report.RiskScore)
	})

	t.Run("dangerous script with rm", func(t *testing.T) {
		script := `echo "Starting cleanup"
rm -rf /tmp/old/*
echo "Done"`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		safe, report := parser.IsSafe(result)
		if safe {
			t.Error("Expected script with rm to be unsafe")
		}
		fmt.Printf("Dangerous script (rm): safe=%v, risk=%d, patterns=%d\n", safe, report.RiskScore, len(report.DangerousPatterns))
	})

	t.Run("dangerous script with sed -i", func(t *testing.T) {
		script := `sed -i 's/old/new/g' file.txt
echo "Modified"`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		safe, report := parser.IsSafe(result)
		if safe {
			t.Error("Expected script with sed -i to be unsafe")
		}
		fmt.Printf("Dangerous script (sed -i): safe=%v, risk=%d\n", safe, report.RiskScore)
	})

	t.Run("dangerous source with relative path", func(t *testing.T) {
		script := `./setup-script.sh`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		safe, report := parser.IsSafe(result)
		if safe {
			t.Error("Expected source with relative path to be flagged")
		}
		fmt.Printf("Relative source: safe=%v, risk=%d\n", safe, report.RiskScore)
	})

	t.Run("here doc is safe", func(t *testing.T) {
		script := `cat <<EOF
This is safe content
EOF
echo "Done"`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		safe, report := parser.IsSafe(result)
		fmt.Printf("Here doc script: safe=%v, risk=%d\n", safe, report.RiskScore)
	})

	t.Run("script with pipes and redirection", func(t *testing.T) {
		script := `cat log.txt | grep ERROR | sort | uniq > errors.txt`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		safe, report := parser.IsSafe(result)
		fmt.Printf("Pipe/redir script: safe=%v, risk=%d\n", safe, report.RiskScore)
	})

	t.Run("function definition", func(t *testing.T) {
		script := `function cleanup() {
    rm -rf /tmp/*
}

cleanup`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		if len(result.Commands) != 2 {
			t.Errorf("Expected 2 commands, got %d", len(result.Commands))
		}
		if result.Commands[0].Type != StmtFunction {
			t.Errorf("Expected function definition, got %v", result.Commands[0].Type)
		}
		fmt.Printf("Function definition parsed\n")
	})
}

func TestMultiLineShellComplexScripts(t *testing.T) {
	parser := NewMultiLineShellParser()

	t.Run("real-world deployment script", func(t *testing.T) {
		script := `#!/bin/bash
set -e

cd /home/panz/osrc/project

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

. venv/bin/activate

export PYTHONPATH=/home/panz/osrc/project

pip install -r requirements.txt

python -c "
import sys
print(f'Python version: {sys.version}')
"

echo "Deployment complete!"`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		fmt.Printf("Deployment script: %d commands, %d here docs\n", len(result.Commands), len(result.HereDocs))
		for i, cmd := range result.Commands {
			fmt.Printf("  %d: type=%v", i+1, cmd.Type)
			if cmd.Type == StmtIf {
				fmt.Printf(", then=%d, else=%d", len(cmd.ThenBody), len(cmd.ElseBody))
			}
			if cmd.Type == StmtSource {
				fmt.Printf(", args=%v", cmd.Args)
			}
			if cmd.Type == StmtExport {
				fmt.Printf(", vars=%v", cmd.Args)
			}
			fmt.Printf("\n")
		}
	})

	t.Run("python here doc", func(t *testing.T) {
		script := `python3 - <<'PYTHON'
import sys
import json

with open('data.json', 'r') as f:
    data = json.load(f)

for item in data['items']:
    print(item['name'])
PYTHON`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		fmt.Printf("Python here doc: %d commands, %d here docs\n", len(result.Commands), len(result.HereDocs))
		if len(result.HereDocs) > 0 {
			fmt.Printf("  Here doc delimiter: %s\n", result.HereDocs[0].Delimiter)
		}
	})

	t.Run("python here doc with file write detected", func(t *testing.T) {
		script := `python3 << 'EOF'
with open('src/analysis/expression.rs', 'r') as f:
   content = f.read()

if old_code in content:
   content = content.replace(old_code, new_code, 1)
   with open('src/analysis/expression.rs', 'w') as f:
       f.write(content)
   print("Successfully patched BinaryOp construction")
EOF`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		fmt.Printf("Python file mod here doc: %d commands\n", len(result.Commands))

		if len(result.Commands) != 1 {
			t.Errorf("Expected 1 command, got %d", len(result.Commands))
		}
		if result.Commands[0].HereDoc == nil {
			t.Error("Expected HereDoc to be parsed")
		}
		if result.Commands[0].PythonOps == nil {
			t.Error("Expected PythonOps to be populated")
		}
		fmt.Printf("Python operations: %d\n", len(result.Commands[0].PythonOps))
		for _, op := range result.Commands[0].PythonOps {
			fmt.Printf("  - %v: %s\n", op.OperationType, op.Context)
		}

		isUnsafe := false
		for _, op := range result.Commands[0].PythonOps {
			if risk, ok := op.Parameters["risk_score"].(int); ok && risk > 0 {
				isUnsafe = true
			}
			if safe, ok := op.Parameters["python_code_safe"].(bool); ok && !safe {
				isUnsafe = true
			}
		}

		if !isUnsafe {
			t.Error("Expected script with file write to be flagged as unsafe")
		}
		if len(result.Commands[0].PythonOps) == 0 {
			t.Error("Expected at least one operation for file write")
		}
	})

	t.Run("python -c with file write", func(t *testing.T) {
		script := `python3 -c "with open('test.txt', 'w') as f: f.write('hello')"`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		fmt.Printf("Python -c inline: %d commands\n", len(result.Commands))

		if len(result.Commands) != 1 {
			t.Errorf("Expected 1 command, got %d", len(result.Commands))
		}
		if result.Commands[0].PythonOps == nil {
			t.Error("Expected PythonOps to be populated")
		}
		fmt.Printf("Python -c operations: %d\n", len(result.Commands[0].PythonOps))

		isUnsafe := false
		for _, op := range result.Commands[0].PythonOps {
			if risk, ok := op.Parameters["risk_score"].(int); ok && risk > 0 {
				isUnsafe = true
			}
			if safe, ok := op.Parameters["python_code_safe"].(bool); ok && !safe {
				isUnsafe = true
			}
		}

		if !isUnsafe {
			t.Error("Expected script with file write to be flagged as unsafe")
		}
	})

	t.Run("python -c safe code", func(t *testing.T) {
		script := `python3 -c "print('hello world'); import sys; print(sys.version)"`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		fmt.Printf("Python -c safe: %d commands, ops=%v\n", len(result.Commands), result.Commands[0].PythonOps != nil)
	})

	t.Run("bash -c with dangerous command", func(t *testing.T) {
		script := `bash -c "rm -rf /tmp/test"`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		fmt.Printf("Bash -c dangerous: %d commands\n", len(result.Commands))
		if len(result.Commands) != 1 {
			t.Errorf("Expected 1 command, got %d", len(result.Commands))
		}
		if result.Commands[0].BashOps == nil {
			t.Error("Expected BashOps to be populated")
		}
		fmt.Printf("Bash operations: %d\n", len(result.Commands[0].BashOps))
		for _, op := range result.Commands[0].BashOps {
			fmt.Printf("  - %v: %s\n", op.OperationType, op.Context)
		}

		isUnsafe := false
		for _, op := range result.Commands[0].BashOps {
			if risk, ok := op.Parameters["risk_score"].(int); ok && risk > 0 {
				isUnsafe = true
			}
			if safe, ok := op.Parameters["bash_safe"].(bool); ok && !safe {
				isUnsafe = true
			}
		}

		if !isUnsafe {
			t.Error("Expected script with rm to be flagged as unsafe")
		}
	})

	t.Run("bash -c safe command", func(t *testing.T) {
		script := `bash -c "echo 'hello'; ls -la"`
		result, err := parser.ParseScript(script)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		fmt.Printf("Bash -c safe: %d commands, ops=%v\n", len(result.Commands), result.Commands[0].BashOps != nil)
	})
}
