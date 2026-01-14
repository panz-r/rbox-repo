package semantic

import (
	"strings"
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOdStringsParser_Od(t *testing.T) {
	parser := &OdStringsParser{commandType: "od"}

	// Test od with file
	cmd, err := parser.ParseArguments([]string{"file.bin"})
	require.NoError(t, err)
	odCmd, ok := cmd.(*OdCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file.bin"}, odCmd.InputFiles)
	assert.Equal(t, "o", odCmd.OutputType)

	// Test od with format option
	cmd, err = parser.ParseArguments([]string{"-t", "x1", "file.bin"})
	require.NoError(t, err)
	odCmd, ok = cmd.(*OdCommand)
	require.True(t, ok)
	assert.Equal(t, "x1", odCmd.OutputType)

	// Test od with address radix
	cmd, err = parser.ParseArguments([]string{"-A", "x", "file.bin"})
	require.NoError(t, err)
	odCmd, ok = cmd.(*OdCommand)
	require.True(t, ok)
	assert.Equal(t, "x", odCmd.AddressRadix)

	// Test semantic operations for od
	ops, err := parser.GetSemanticOperations(odCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for binary data
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "file.bin") {
			hasRead = true
			assert.Equal(t, "binary_data", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "od", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for binary data")
}

func TestOdStringsParser_Strings(t *testing.T) {
	parser := &OdStringsParser{commandType: "strings"}

	// Test strings with file
	cmd, err := parser.ParseArguments([]string{"file.txt"})
	require.NoError(t, err)
	stringsCmd, ok := cmd.(*StringsCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"file.txt"}, stringsCmd.InputFiles)

	// Test strings with min length
	cmd, err = parser.ParseArguments([]string{"-n", "8", "file.txt"})
	require.NoError(t, err)
	stringsCmd, ok = cmd.(*StringsCommand)
	require.True(t, ok)
	assert.Equal(t, 8, stringsCmd.MinLength)

	// Test semantic operations for strings
	ops, err := parser.GetSemanticOperations(stringsCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read operations for text data
	hasRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "file.txt") {
			hasRead = true
			assert.Equal(t, "text_data", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "strings", val)
			}
			break
		}
	}
	assert.True(t, hasRead, "Should have read operations for text data")
}

func TestOdStringsParser_Factor(t *testing.T) {
	parser := &OdStringsParser{commandType: "factor"}

	// Test factor with number
	cmd, err := parser.ParseArguments([]string{"42"})
	require.NoError(t, err)
	factorCmd, ok := cmd.(*FactorCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"42"}, factorCmd.Numbers)

	// Test factor with bignum option
	cmd, err = parser.ParseArguments([]string{"-b", "12345678901234567890"})
	require.NoError(t, err)
	factorCmd, ok = cmd.(*FactorCommand)
	require.True(t, ok)
	assert.True(t, factorCmd.Bignum)

	// Test semantic operations for factor
	ops, err := parser.GetSemanticOperations(factorCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have computation operation
	hasComputation := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "null") {
			hasComputation = true
			assert.Equal(t, "computation", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "factor", val)
			}
			break
		}
	}
	assert.True(t, hasComputation, "Should have computation operation")
}

func TestOdStringsParser_Yes(t *testing.T) {
	parser := &OdStringsParser{commandType: "yes"}

	// Test yes with default message
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)
	yesCmd, ok := cmd.(*YesCommand)
	require.True(t, ok)
	assert.Equal(t, "y", yesCmd.Message)

	// Test yes with custom message
	cmd, err = parser.ParseArguments([]string{"hello", "world"})
	require.NoError(t, err)
	yesCmd, ok = cmd.(*YesCommand)
	require.True(t, ok)
	assert.Equal(t, "hello world", yesCmd.Message)

	// Test semantic operations for yes
	ops, err := parser.GetSemanticOperations(yesCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have output generation operation
	hasOutputGen := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "null") {
			hasOutputGen = true
			assert.Equal(t, "output_generation", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "yes", val)
			}
			break
		}
	}
	assert.True(t, hasOutputGen, "Should have output generation operation")
}

func TestOdStringsParser_Sleep(t *testing.T) {
	parser := &OdStringsParser{commandType: "sleep"}

	// Test sleep with duration
	cmd, err := parser.ParseArguments([]string{"5"})
	require.NoError(t, err)
	sleepCmd, ok := cmd.(*SleepCommand)
	require.True(t, ok)
	assert.Equal(t, "5", sleepCmd.Duration)

	// Test semantic operations for sleep
	ops, err := parser.GetSemanticOperations(sleepCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have time operation
	hasTimeOp := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "null") {
			hasTimeOp = true
			assert.Equal(t, "time_operation", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "sleep", val)
			}
			break
		}
	}
	assert.True(t, hasTimeOp, "Should have time operation")
}

func TestOdStringsParser_Cal(t *testing.T) {
	parser := &OdStringsParser{commandType: "cal"}

	// Test cal with no arguments (current month)
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)
	calCmd, ok := cmd.(*CalCommand)
	require.True(t, ok)
	assert.Equal(t, -1, calCmd.Month)
	assert.Equal(t, -1, calCmd.Year)

	// Test cal with month and year
	cmd, err = parser.ParseArguments([]string{"12", "2023"})
	require.NoError(t, err)
	calCmd, ok = cmd.(*CalCommand)
	require.True(t, ok)
	assert.Equal(t, 12, calCmd.Month)
	assert.Equal(t, 2023, calCmd.Year)

	// Test cal with year option
	cmd, err = parser.ParseArguments([]string{"-y", "2023"})
	require.NoError(t, err)
	calCmd, ok = cmd.(*CalCommand)
	require.True(t, ok)
	assert.True(t, calCmd.ShowYear)

	// Test semantic operations for cal
	ops, err := parser.GetSemanticOperations(calCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have calendar generation operation
	hasCalGen := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "null") {
			hasCalGen = true
			assert.Equal(t, "calendar_generation", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "cal", val)
			}
			break
		}
	}
	assert.True(t, hasCalGen, "Should have calendar generation operation")
}

func TestOdStringsParser_Printenv(t *testing.T) {
	parser := &OdStringsParser{commandType: "printenv"}

	// Test printenv with no arguments (all variables)
	cmd, err := parser.ParseArguments([]string{})
	require.NoError(t, err)
	printenvCmd, ok := cmd.(*PrintenvCommand)
	require.True(t, ok)
	assert.True(t, printenvCmd.All)
	assert.Empty(t, printenvCmd.Variables)

	// Test printenv with specific variables
	cmd, err = parser.ParseArguments([]string{"PATH", "HOME"})
	require.NoError(t, err)
	printenvCmd, ok = cmd.(*PrintenvCommand)
	require.True(t, ok)
	assert.Equal(t, []string{"PATH", "HOME"}, printenvCmd.Variables)
	assert.False(t, printenvCmd.All)

	// Test printenv with null option
	cmd, err = parser.ParseArguments([]string{"-0", "PATH"})
	require.NoError(t, err)
	printenvCmd, ok = cmd.(*PrintenvCommand)
	require.True(t, ok)
	assert.True(t, printenvCmd.Null)

	// Test semantic operations for printenv
	ops, err := parser.GetSemanticOperations(printenvCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have environment variables read operation
	hasEnvRead := false
	for _, op := range ops {
		if op.OperationType == OpRead && strings.Contains(op.TargetPath, "environ") {
			hasEnvRead = true
			assert.Equal(t, "environment_variables", op.Context)
			if val, exists := op.Parameters["command"]; exists {
				assert.Equal(t, "printenv", val)
			}
			break
		}
	}
	assert.True(t, hasEnvRead, "Should have environment variables read operation")
}

func TestOdStringsParser_EdgeCases(t *testing.T) {
	// Test od parser with unknown option
	odParser := &OdStringsParser{commandType: "od"}
	_, err := odParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test strings parser with unknown option
	stringsParser := &OdStringsParser{commandType: "strings"}
	_, err = stringsParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test factor parser with unknown option
	factorParser := &OdStringsParser{commandType: "factor"}
	_, err = factorParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test yes parser with unknown option
	yesParser := &OdStringsParser{commandType: "yes"}
	_, err = yesParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test sleep parser with unknown option
	sleepParser := &OdStringsParser{commandType: "sleep"}
	_, err = sleepParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test cal parser with unknown option
	calParser := &OdStringsParser{commandType: "cal"}
	_, err = calParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)

	// Test printenv parser with unknown option
	printenvParser := &OdStringsParser{commandType: "printenv"}
	_, err = printenvParser.ParseArguments([]string{"--unknown"})
	assert.Error(t, err)
}

func TestOdStringsParser_Soundness(t *testing.T) {
	parser := &OdStringsParser{commandType: "od"}

	// Test that file reading is properly captured
	cmd, err := parser.ParseArguments([]string{"file.bin"})
	require.NoError(t, err)

	ops, err := parser.GetSemanticOperations(cmd)
	require.NoError(t, err)

	// Should have precise read operations for the file
	assert.NotEmpty(t, ops)
	for _, op := range ops {
		if op.OperationType == OpRead && op.TargetPath == "file.bin" {
			assert.Equal(t, "binary_data", op.Context)
			if params, exists := op.Parameters["precise"]; exists && params.(bool) {
				return // Found precise operation
			}
		}
	}
	assert.Fail(t, "Should have precise read operation for file.bin")
}