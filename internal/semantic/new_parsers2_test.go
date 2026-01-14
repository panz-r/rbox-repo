package semantic

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTarParser(t *testing.T) {
	parser := NewTarParser()

	// Test tar create command
	cmd, err := parser.ParseArguments([]string{"-czvf", "archive.tar.gz", "file1.txt", "file2.txt"})
	require.NoError(t, err)
	tarCmd, ok := cmd.(*TarCommand)
	require.True(t, ok)
	assert.Equal(t, "create", tarCmd.Operation)
	assert.Equal(t, "archive.tar.gz", tarCmd.ArchiveFile)
	assert.Equal(t, []string{"file1.txt", "file2.txt"}, tarCmd.Files)
	assert.True(t, tarCmd.Gzip)
	assert.True(t, tarCmd.Verbose)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(tarCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read and write operations
	hasRead := false
	hasWrite := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
		}
		if op.OperationType == OpWrite {
			hasWrite = true
		}
	}
	assert.True(t, hasRead, "Should have read operations")
	assert.True(t, hasWrite, "Should have write operations")

	// Test tar extract command
	cmd, err = parser.ParseArguments([]string{"-xzvf", "archive.tar.gz", "-C", "/tmp"})
	require.NoError(t, err)
	tarCmd, ok = cmd.(*TarCommand)
	require.True(t, ok)
	assert.Equal(t, "extract", tarCmd.Operation)
	assert.Equal(t, "archive.tar.gz", tarCmd.ArchiveFile)
	assert.Equal(t, "/tmp", tarCmd.Directory)
	assert.True(t, tarCmd.Gzip)
	assert.True(t, tarCmd.Verbose)

	// Test semantic operations for extract
	ops, err = parser.GetSemanticOperations(tarCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)
}

func TestGzipParser(t *testing.T) {
	parser := NewGzipParser()

	// Test gzip compress command
	cmd, err := parser.ParseArguments([]string{"-v", "-9", "file.txt"})
	require.NoError(t, err)
	gzipCmd, ok := cmd.(*GzipCommand)
	require.True(t, ok)
	assert.Equal(t, "compress", gzipCmd.Operation)
	assert.Equal(t, []string{"file.txt"}, gzipCmd.Files)
	assert.True(t, gzipCmd.Verbose)
	assert.True(t, gzipCmd.Best)
	assert.Equal(t, 9, gzipCmd.Level)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(gzipCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have read and write operations
	hasRead := false
	hasWrite := false
	for _, op := range ops {
		if op.OperationType == OpRead {
			hasRead = true
		}
		if op.OperationType == OpWrite {
			hasWrite = true
		}
	}
	assert.True(t, hasRead, "Should have read operations")
	assert.True(t, hasWrite, "Should have write operations")

	// Test gzip decompress command
	cmd, err = parser.ParseArguments([]string{"-d", "-v", "file.txt.gz"})
	require.NoError(t, err)
	gzipCmd, ok = cmd.(*GzipCommand)
	require.True(t, ok)
	assert.Equal(t, "decompress", gzipCmd.Operation)
	assert.Equal(t, []string{"file.txt.gz"}, gzipCmd.Files)
	assert.True(t, gzipCmd.Verbose)

	// Test semantic operations for decompress
	ops, err = parser.GetSemanticOperations(gzipCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)
}

func TestSshParser(t *testing.T) {
	parser := NewSshParser()

	// Test ssh command
	cmd, err := parser.ParseArguments([]string{"-v", "-p", "2222", "user@host", "ls -la"})
	require.NoError(t, err)
	sshCmd, ok := cmd.(*SshCommand)
	require.True(t, ok)
	assert.Equal(t, "user", sshCmd.User)
	assert.Equal(t, "host", sshCmd.Host)
	assert.Equal(t, "2222", sshCmd.Port)
	assert.Equal(t, "ls -la", sshCmd.Command)
	assert.True(t, sshCmd.Verbose)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(sshCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have dangerous operations (network operations)
	hasDangerous := false
	for _, op := range ops {
		if op.Parameters != nil {
			if dangerous, ok := op.Parameters["dangerous"].(bool); ok && dangerous {
				hasDangerous = true
				break
			}
		}
	}
	assert.True(t, hasDangerous, "SSH operations should be marked as dangerous")

	// Test ssh with identity file
	cmd, err = parser.ParseArguments([]string{"-i", "~/.ssh/custom_key", "-A", "user@host"})
	require.NoError(t, err)
	sshCmd, ok = cmd.(*SshCommand)
	require.True(t, ok)
	assert.Equal(t, "~/.ssh/custom_key", sshCmd.IdentityFile)
	assert.True(t, sshCmd.ForwardAgent)

	// Test semantic operations with identity file
	ops, err = parser.GetSemanticOperations(sshCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)
}

func TestScpParser(t *testing.T) {
	parser := NewScpParser()

	// Test scp to remote
	cmd, err := parser.ParseArguments([]string{"-v", "-P", "2222", "file.txt", "user@host:/tmp/"})
	require.NoError(t, err)
	scpCmd, ok := cmd.(*ScpCommand)
	require.True(t, ok)
	assert.Equal(t, "copy_to_remote", scpCmd.Operation)
	assert.Equal(t, []string{"file.txt"}, scpCmd.Sources)
	assert.Equal(t, "user@host:/tmp/", scpCmd.Destination)
	assert.Equal(t, "2222", scpCmd.Port)
	assert.True(t, scpCmd.Verbose)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(scpCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have dangerous operations (network operations)
	hasDangerous := false
	for _, op := range ops {
		if op.Parameters != nil {
			if dangerous, ok := op.Parameters["dangerous"].(bool); ok && dangerous {
				hasDangerous = true
				break
			}
		}
	}
	assert.True(t, hasDangerous, "SCP operations should be marked as dangerous")

	// Test scp from remote
	cmd, err = parser.ParseArguments([]string{"-r", "user@host:/tmp/*.txt", "./downloads/"})
	require.NoError(t, err)
	scpCmd, ok = cmd.(*ScpCommand)
	require.True(t, ok)
	assert.Equal(t, "copy_from_remote", scpCmd.Operation)
	assert.Equal(t, []string{"user@host:/tmp/*.txt"}, scpCmd.Sources)
	assert.Equal(t, "./downloads/", scpCmd.Destination)
	assert.True(t, scpCmd.Recursive)

	// Test semantic operations for recursive copy
	ops, err = parser.GetSemanticOperations(scpCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)
}

func TestWgetCurlParser(t *testing.T) {
	parser := NewWgetCurlParser()

	// Test wget command
	cmd, err := parser.ParseArguments([]string{"wget", "-q", "-O", "output.html", "https://example.com"})
	require.NoError(t, err)
	wgetCmd, ok := cmd.(*WgetCurlCommand)
	require.True(t, ok)
	assert.Equal(t, "wget", wgetCmd.CommandType)
	assert.Equal(t, []string{"https://example.com"}, wgetCmd.Urls)
	assert.Equal(t, "output.html", wgetCmd.OutputFile)
	assert.True(t, wgetCmd.Quiet)

	// Test semantic operations
	ops, err := parser.GetSemanticOperations(wgetCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have dangerous operations (network operations)
	hasDangerous := false
	for _, op := range ops {
		if op.Parameters != nil {
			if dangerous, ok := op.Parameters["dangerous"].(bool); ok && dangerous {
				hasDangerous = true
				break
			}
		}
	}
	assert.True(t, hasDangerous, "Wget operations should be marked as dangerous")

	// Test curl command with POST
	cmd, err = parser.ParseArguments([]string{"curl", "-X", "POST", "-d", "data=test", "-v", "https://api.example.com/endpoint"})
	require.NoError(t, err)
	curlCmd, ok := cmd.(*WgetCurlCommand)
	require.True(t, ok)
	assert.Equal(t, "curl", curlCmd.CommandType)
	assert.Equal(t, []string{"https://api.example.com/endpoint"}, curlCmd.Urls)
	assert.Equal(t, "data=test", curlCmd.PostData)
	assert.True(t, curlCmd.Verbose)

	// Test semantic operations for POST
	ops, err = parser.GetSemanticOperations(curlCmd)
	require.NoError(t, err)
	assert.NotEmpty(t, ops)

	// Should have high risk operations (POST requests)
	hasHighRisk := false
	for _, op := range ops {
		if op.Parameters != nil {
			if highRisk, ok := op.Parameters["high_risk"].(bool); ok && highRisk {
				hasHighRisk = true
				break
			}
		}
	}
	assert.True(t, hasHighRisk, "Curl POST operations should be marked as high risk")
}