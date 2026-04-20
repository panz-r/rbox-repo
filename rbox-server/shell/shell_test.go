//go:build cgo
// +build cgo

package shell

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewGate(t *testing.T) {
	g, err := NewGate()
	assert.NoError(t, err)
	assert.NotNil(t, g)
	g.Close()
}

func TestEvalSimple(t *testing.T) {
	g, err := NewGate()
	assert.NoError(t, err)
	defer g.Close()

	err = g.AddRule("echo *")
	assert.NoError(t, err)

	result, err := g.Eval("echo hello")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, VerdictAllow, result.Verdict)
	assert.Len(t, result.Subcmds, 1)
	assert.Equal(t, "echo hello", result.Subcmds[0].Command)
}

func TestEvalUndetermined(t *testing.T) {
	g, err := NewGate()
	assert.NoError(t, err)
	defer g.Close()

	err = g.AddRule("ls")
	assert.NoError(t, err)

	result, err := g.Eval("rm -rf /")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, VerdictUndetermined, result.Verdict)
}

func TestEvalEmpty(t *testing.T) {
	g, err := NewGate()
	assert.NoError(t, err)
	defer g.Close()

	result, err := g.Eval("")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestEvalPipe(t *testing.T) {
	g, err := NewGate()
	assert.NoError(t, err)
	defer g.Close()

	err = g.AddRule("echo *")
	assert.NoError(t, err)
	err = g.AddRule("grep")
	assert.NoError(t, err)

	result, err := g.Eval("echo hello | grep pattern")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Subcmds, 2)
}

func TestAddRemoveRule(t *testing.T) {
	g, err := NewGate()
	assert.NoError(t, err)
	defer g.Close()

	err = g.AddRule("ls")
	assert.NoError(t, err)
	assert.Equal(t, uint32(1), g.RuleCount())

	err = g.RemoveRule("ls")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), g.RuleCount())
}

func TestSaveLoadPolicy(t *testing.T) {
	g, err := NewGate()
	assert.NoError(t, err)
	defer g.Close()

	g.AddRule("echo *")
	g.AddRule("ls")

	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "test.policy")

	err = g.SavePolicy(policyPath)
	assert.NoError(t, err)
	_, statErr := os.Stat(policyPath)
	assert.NoError(t, statErr)

	g2, err := NewGate()
	assert.NoError(t, err)
	defer g2.Close()

	err = g2.LoadPolicy(policyPath)
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), g2.RuleCount())

	result, err := g2.Eval("echo test")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, VerdictAllow, result.Verdict)
}

func TestViolationScan(t *testing.T) {
	g, err := NewGate()
	assert.NoError(t, err)
	defer g.Close()

	g.AddRule("cat #path")
	g.AddRule("sudo *")
	g.AddRule("curl *")
	g.AddRule("sh")
	g.AddRule("base64")
	g.AddRule("bash")
	g.AddRule("git *")

	result, err := g.Eval("sudo bash")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	if result.HasViolation {
		assert.True(t, len(result.Violations) > 0)
		found := false
		for _, v := range result.Violations {
			if v.Severity >= 80 {
				found = true
			}
		}
		assert.True(t, found, "expected high-severity violation for sudo bash")
	}
}

func TestVerdictName(t *testing.T) {
	assert.Equal(t, "ALLOW", VerdictName(VerdictAllow))
	assert.Equal(t, "DENY", VerdictName(VerdictDeny))
	assert.Equal(t, "REJECT", VerdictName(VerdictReject))
	assert.Equal(t, "UNDETERMINED", VerdictName(VerdictUndetermined))
}

func TestViolationTypeName(t *testing.T) {
	assert.Equal(t, "write-sensitive", ViolationTypeName(1<<16|1<<0))
	assert.Equal(t, "remove-system", ViolationTypeName(1<<16|1<<1))
	assert.Equal(t, "perm-system", ViolationTypeName(1<<16|1<<2))
	assert.Equal(t, "git-destructive", ViolationTypeName(1<<16|1<<3))
	assert.Equal(t, "env-privileged", ViolationTypeName(1<<17|1<<0))
	assert.Equal(t, "shell-escalation", ViolationTypeName(1<<17|1<<1))
	assert.Equal(t, "sudo-redirect", ViolationTypeName(1<<17|1<<2))
	assert.Equal(t, "persistence", ViolationTypeName(1<<17|1<<3))
	assert.Equal(t, "write-then-read", ViolationTypeName(1<<18|1<<0))
	assert.Equal(t, "subst-sensitive", ViolationTypeName(1<<18|1<<1))
	assert.Equal(t, "redirect-fanout", ViolationTypeName(1<<18|1<<2))
	assert.Equal(t, "read-secrets", ViolationTypeName(1<<18|1<<3))
	assert.Equal(t, "shell-obfuscation", ViolationTypeName(1<<18|1<<4))
	assert.Equal(t, "net-download-exec", ViolationTypeName(1<<19|1<<0))
	assert.Equal(t, "net-upload", ViolationTypeName(1<<19|1<<1))
	assert.Equal(t, "net-listener", ViolationTypeName(1<<19|1<<2))
	assert.Equal(t, "unknown", ViolationTypeName(0))
}
