package semantic

import (
	"strings"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTextUtilsParser_Seq(t *testing.T) {
	parser := &TextUtilsParser{commandType: "seq"}

	// Test seq with last argument only
	cmd, err := parser.ParseArguments([]string{"5"})
	require.NoError(t, err)
	seqCmd, ok := cmd.(*SeqCommand)
	require.True(t, ok)
	assert.Equal(t, "1", seqCmd.First)
	assert.Equal(t, "1", seqCmd.Increment)
	assert.Equal(t, "5", seqCmd.Last)

	// Test seq with first and last
	cmd, err = parser.ParseArguments([]string{"2", "10"})
	require.NoError(t, err)
	seqCmd, ok = cmd.(*SeqCommand)
	require.True(t, ok)
	assert.Equal(t, "2", seqCmd.First)
	assert.Equal(t, "1", seqCmd.Increment)
	assert.Equal(t, "10", seqCmd.Last)

	// Test seq with first, increment, and last
	cmd, err = parser.ParseArguments([]string{"1", "2", "20"})
	require.NoError(t, err)
	seqCmd, ok = cmd.(*SeqCommand)
	require.True(t, ok)
	assert.Equal(t, "1", seqCmd.First)
	assert.Equal(t, "2", seqCmd.Increment)
	assert.Equal(t, "20", seqCmd.Last)

	// Test seq with format option
	cmd, err = parser.ParseArguments([]string{"-f", "%03g", "1", "10"})
	require.NoError(t, err)
	seqCmd, ok = cmd.(*SeqCommand)
	require.True(t, ok)
	assert.Equal(t, "%03g", seqCmd.Format)

	// Test semantic operations for seq
	ops, err := parser.GetSemanticOperations(seqCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have number generation operation
	hasGen := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "null") {
			hasGen = true
			assert.Equal(t, "number_generation", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "seq", val)
			}
			break
		}
	}
	assert.True(t, hasGen, "Should have number generation operation")
}

func TestTextUtilsParser_Nl(t *testing.T) {
	parser := &TextUtilsParser{commandType: "nl"}

	// Test nl with file
	cmd, err := parser.ParseArguments([]string{"file.txt"})
	require.NoError(t, err)
	nlCmd, ok := cmd.(*NlCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file.txt"}, nlCmd.InputFiles)

	// Test nl with number width
	cmd, err = parser.ParseArguments([]string{"-w", "3", "file.txt"})
	require.NoError(t, err)
	nlCmd, ok = cmd.(*NlCommand)
	require.True(t, ok)
	assert.Equal(t, 3, nlCmd.NumberWidth)

	// Test semantic operations for nl
	ops, err := parser.GetSemanticOperations(nlCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for text data
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "file.txt") {
			hasRead = true
			assert.Equal(t, "text_data", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "nl", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for text data")
}

func TestTextUtilsParser_Tac(t *testing.T) {
	parser := &TextUtilsParser{commandType: "tac"}

	// Test tac with file
	cmd, err := parser.ParseArguments([]string{"file.txt"})
	require.NoError(t, err)
	tacCmd, ok := cmd.(*TacCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file.txt"}, tacCmd.InputFiles)

	// Test tac with separator
	cmd, err = parser.ParseArguments([]string{"-s", ":", "file.txt"})
	require.NoError(t, err)
	tacCmd, ok = cmd.(*TacCommand)
	require.True(t, ok)
	assert.Equal(t, ":", tacCmd.Separator)

	// Test semantic operations for tac
	ops, err := parser.GetSemanticOperations(tacCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for text data
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "file.txt") {
			hasRead = true
			assert.Equal(t, "text_data", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "tac", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for text data")
}

func TestTextUtilsParser_Rev(t *testing.T) {
	parser := &TextUtilsParser{commandType: "rev"}

	// Test rev with file
	cmd, err := parser.ParseArguments([]string{"file.txt"})
	require.NoError(t, err)
	revCmd, ok := cmd.(*RevCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file.txt"}, revCmd.InputFiles)

	// Test semantic operations for rev
	ops, err := parser.GetSemanticOperations(revCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for text data
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "file.txt") {
			hasRead = true
			assert.Equal(t, "text_data", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "rev", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for text data")
}

func TestTextUtilsParser_Expand(t *testing.T) {
	parser := &TextUtilsParser{commandType: "expand"}

	// Test expand with file
	cmd, err := parser.ParseArguments([]string{"file.txt"})
	require.NoError(t, err)
	expandCmd, ok := cmd.(*ExpandCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file.txt"}, expandCmd.InputFiles)

	// Test expand with tabs option
	cmd, err = parser.ParseArguments([]string{"-t", "4", "file.txt"})
	require.NoError(t, err)
	expandCmd, ok = cmd.(*ExpandCommand)
	require.True(t, ok)
	assert.Equal(t, 4, expandCmd.Tabs)

	// Test semantic operations for expand
	ops, err := parser.GetSemanticOperations(expandCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for text data
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "file.txt") {
			hasRead = true
			assert.Equal(t, "text_data", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "expand", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for text data")
}

func TestTextUtilsParser_Unexpand(t *testing.T) {
	parser := &TextUtilsParser{commandType: "unexpand"}

	// Test unexpand with file
	cmd, err := parser.ParseArguments([]string{"file.txt"})
	require.NoError(t, err)
	unexpandCmd, ok := cmd.(*UnexpandCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file.txt"}, unexpandCmd.InputFiles)

	// Test unexpand with all option
	cmd, err = parser.ParseArguments([]string{"-a", "file.txt"})
	require.NoError(t, err)
	unexpandCmd, ok = cmd.(*UnexpandCommand)
	require.True(t, ok)
	assert.True(t, unexpandCmd.All)

	// Test semantic operations for unexpand
	ops, err := parser.GetSemanticOperations(unexpandCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for text data
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "file.txt") {
			hasRead = true
			assert.Equal(t, "text_data", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "unexpand", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for text data")
}

func TestTextUtilsParser_EdgeCases(t *testing.T) {
	// Test seq parser with unknown option
	seqParser := &TextUtilsParser{commandType: "seq"}
	_, err := seqParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test nl parser with unknown option
	nlParser := &TextUtilsParser{commandType: "nl"}
	_, err = nlParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test tac parser with unknown option
	tacParser := &TextUtilsParser{commandType: "tac"}
	_, err = tacParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test rev parser with unknown option
	revParser := &TextUtilsParser{commandType: "rev"}
	_, err = revParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test expand parser with unknown option
	expandParser := &TextUtilsParser{commandType: "expand"}
	_, err = expandParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test unexpand parser with unknown option
	unexpandParser := &TextUtilsParser{commandType: "unexpand"}
	_, err = unexpandParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)
}

func TestTextUtilsParser_Soundness(t *testing.T) {
	parser := &TextUtilsParser{commandType: "seq"}

	// Test that number generation is properly captured
	cmd, err := parser.ParseArguments([]string{"1", "5"})
	require.NoError(t, err)

	ops, err := parser.GetSemanticOperations(cmd)
	require.NoError(t, err)

	// Should have over-approximated number generation operation
	assert.NotEmpty(t, ops)
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "null") {
			assert.Equal(t, "number_generation", op.Context)
			if params, exists := op.Parameters["over_approximated"]; exists && params.(bool) {
				return // Found over-approximated operation
			}
		}
	}
	assert.Fail(t, "Should have over-approximated number generation operation")
}