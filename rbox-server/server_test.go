//go:build cgo
// +build cgo

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSocketPath(t *testing.T) {
	tests := []struct {
		name        string
		cmdSocket   string
		forceSystem bool
		forceUser   bool
		envSocket   string
		xdgRuntime  string
		expected    string
	}{
		{
			name:        "Explicit socket path",
			cmdSocket:   "/tmp/custom.sock",
			forceSystem: false,
			forceUser:   false,
			envSocket:   "",
			xdgRuntime:  "",
			expected:    "/tmp/custom.sock",
		},
		{
			name:        "System socket",
			cmdSocket:   "",
			forceSystem: true,
			forceUser:   false,
			envSocket:   "",
			xdgRuntime:  "",
			expected:    SystemSocketPath,
		},
		{
			name:        "User socket with XDG_RUNTIME_DIR",
			cmdSocket:   "",
			forceSystem: false,
			forceUser:   true,
			envSocket:   "",
			xdgRuntime:  "/run/user/1000",
			expected:    "/run/user/1000/readonlybox.sock",
		},
		{
			name:        "Env socket takes priority over XDG_RUNTIME_DIR",
			cmdSocket:   "",
			forceSystem: false,
			forceUser:   false,
			envSocket:   "/var/run/my.sock",
			xdgRuntime:  "/run/user/1000",
			expected:    "/var/run/my.sock",
		},
		{
			name:        "User socket falls back to system when XDG_RUNTIME_DIR not set",
			cmdSocket:   "",
			forceSystem: false,
			forceUser:   true,
			envSocket:   "",
			xdgRuntime:  "",
			expected:    SystemSocketPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.xdgRuntime != "" {
				t.Setenv("XDG_RUNTIME_DIR", tt.xdgRuntime)
			} else {
				t.Setenv("XDG_RUNTIME_DIR", "")
			}
			if tt.envSocket != "" {
				t.Setenv(EnvSocket, tt.envSocket)
			} else {
				t.Setenv(EnvSocket, "")
			}

			result := getSocketPath(tt.cmdSocket, tt.forceSystem, tt.forceUser)
			assert.Equal(t, tt.expected, result)
		})
	}
}
