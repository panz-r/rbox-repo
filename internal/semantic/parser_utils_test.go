package semantic

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShellParsingUtils(t *testing.T) {
	shellUtils := ParserUtilsInstance.ShellParsingUtils()

	// Test ParseShellCommand
	cmd, args, err := shellUtils.ParseShellCommand("echo hello world")
	require.NoError(t, err)
	assert.Equal(t, "echo", cmd)
	assert.Equal(t, []string{"hello", "world"}, args)

	// Test IsShellCommandSafe - safe command
	assert.True(t, shellUtils.IsShellCommandSafe("ls -la"))
	assert.True(t, shellUtils.IsShellCommandSafe("cat file.txt"))

	// Test IsShellCommandSafe - unsafe commands
	assert.False(t, shellUtils.IsShellCommandSafe("rm -rf /"))
	assert.False(t, shellUtils.IsShellCommandSafe("echo test | cat"))
	assert.False(t, shellUtils.IsShellCommandSafe("ls && rm file"))

	// Test ExtractShellCommandsFromHereDoc
	hereDocContent := `#!/bin/bash
# This is a comment
echo "Hello World"
ls -la
rm -rf / # dangerous`

	commands := shellUtils.ExtractShellCommandsFromHereDoc(hereDocContent)
	assert.Contains(t, commands, "echo \"Hello World\"")
	assert.Contains(t, commands, "ls -la")
	assert.Contains(t, commands, "rm -rf / # dangerous")
}

func TestPythonParsingUtils(t *testing.T) {
	pythonUtils := ParserUtilsInstance.PythonParsingUtils()

	// Test ParsePythonCode
	pythonCode := `import os
import sys
from datetime import datetime

x = 5
y = 10

def hello():
    print("Hello")

class MyClass:
    pass

if x > 0:
    print("Positive")

for i in range(10):
    print(i)

while True:
    break`

	imports, statements, err := pythonUtils.ParsePythonCode(pythonCode)
	require.NoError(t, err)
	assert.Contains(t, imports, "import os")
	assert.Contains(t, imports, "import sys")
	assert.Contains(t, imports, "from datetime import datetime")
	assert.Contains(t, statements, "x = 5")
	assert.Contains(t, statements, "def hello():")
	assert.Contains(t, statements, "class MyClass:")
	assert.Contains(t, statements, "if x > 0:")

	// Test IsPythonCodeSafe - safe code
	assert.True(t, pythonUtils.IsPythonCodeSafe("x = 5\ny = 10\nprint(x + y)"))

	// Test IsPythonCodeSafe - unsafe code
	assert.False(t, pythonUtils.IsPythonCodeSafe("__import__('os').system('rm -rf /')"))
	assert.False(t, pythonUtils.IsPythonCodeSafe("exec('dangerous code')"))
	assert.False(t, pythonUtils.IsPythonCodeSafe("os.system('ls')"))

	// Test ExtractPythonCodeFromHereDoc
	hereDocContent := `python3 -c '
import sys
print("Hello from Python")
x = 5 + 10
print(x)
'`

	pythonLines := pythonUtils.ExtractPythonCodeFromHereDoc(hereDocContent)
	assert.Contains(t, pythonLines, "import sys")
	assert.Contains(t, pythonLines, "print(\"Hello from Python\")")
	assert.Contains(t, pythonLines, "x = 5 + 10")
}

func TestHereDocUtils(t *testing.T) {
	hereDocUtils := ParserUtilsInstance.HereDocUtils()

	// Test ExtractHereDocContent
	command := `cat << EOF
This is line 1
This is line 2
This is line 3
EOF`

	header, content, found := hereDocUtils.ExtractHereDocContent(command)
	assert.True(t, found)
	assert.Equal(t, "cat << EOF", header)
	assert.Equal(t, "This is line 1\nThis is line 2\nThis is line 3", content)

	// Test IsHereDocSafe - safe content
	assert.True(t, hereDocUtils.IsHereDocSafe("echo 'Hello'\nls -la"))

	// Test IsHereDocSafe - unsafe content
	assert.False(t, hereDocUtils.IsHereDocSafe("rm -rf /\necho test"))
	assert.False(t, hereDocUtils.IsHereDocSafe("cat file.txt | grep pattern"))
}

func TestParseInt(t *testing.T) {
	// Test ParseInt utility function
	assert.Equal(t, 0, ParserUtilsInstance.ParseInt(""))
	assert.Equal(t, 1, ParserUtilsInstance.ParseInt("1"))
	assert.Equal(t, 42, ParserUtilsInstance.ParseInt("42"))
	assert.Equal(t, 123, ParserUtilsInstance.ParseInt("123"))
	assert.Equal(t, 1, ParserUtilsInstance.ParseInt("abc")) // Non-numeric returns default
	assert.Equal(t, 1, ParserUtilsInstance.ParseInt("123abc")) // Partial numeric
}