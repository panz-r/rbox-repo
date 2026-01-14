package semantic

import (
	"fmt"
	"testing"
)

func TestDebugPython(t *testing.T) {
	parser := NewBashParser()

	script := "python -c \"print('hello')\""

	cmd, err := parser.ParseArguments([]string{"-c", script})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	bashCmd, ok := cmd.(*BashCommand)
	if !ok {
		t.Fatal("Not a bash command")
	}

	hasPython := parser.HasPythonCommands(script)
	fmt.Printf("Has Python: %v\n", hasPython)

	ops, err := parser.GetSemanticOperations(bashCmd)
	if err != nil {
		t.Fatalf("Semantic operations error: %v", err)
	}

	fmt.Printf("Number of operations: %d\n", len(ops))

	for i, op := range ops {
		fmt.Printf("Operation %d: Type=%v, Target=%s\n", i, op.OperationType, op.TargetPath)
		if op.Parameters != nil {
			for k, v := range op.Parameters {
				fmt.Printf("  %s: %v\n", k, v)
			}
		}
	}
}