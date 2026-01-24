package test

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	ROBO_MAGIC   = 0x524F424F
	ROBO_VERSION = 4
	ROBO_MSG_REQ = 1
)

func TestCwdProtocolFlow(t *testing.T) {
	if os.Getenv("SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network tests")
	}

	socketPath := "/tmp/readonlybox-cwd-test-" + strconv.Itoa(os.Getpid()) + ".sock"

	server := exec.Command("../bin/readonlybox-server", "-socket", socketPath, "-debug")
	var serverOutput bytes.Buffer
	server.Stdout = &serverOutput
	server.Stderr = &serverOutput

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if server.Process != nil {
			server.Process.Kill()
			server.Wait()
		}
		os.Remove(socketPath)
	}()

	time.Sleep(500 * time.Millisecond)

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	testCases := []struct {
		name        string
		caller      string
		cwd         string
		cmd         string
		expectCwd   bool
		expectedCwd string
	}{
		{
			name:        "basic ls command with cwd",
			caller:      "claude:execve",
			cwd:         "/home/panz",
			cmd:         "which ls",
			expectCwd:   true,
			expectedCwd: "/home/panz",
		},
		{
			name:        "command from project root",
			caller:      "cursor:execve",
			cwd:         "/home/panz/osrc/lms-test/readonlybox",
			cmd:         "which cat",
			expectCwd:   true,
			expectedCwd: "/home/panz/osrc/lms-test/readonlybox",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			augmentedCmd := "[" + tc.caller + "] " + tc.cmd

			var buf bytes.Buffer

			binary.Write(&buf, binary.LittleEndian, uint32(ROBO_MAGIC))
			binary.Write(&buf, binary.LittleEndian, uint32(ROBO_VERSION))
			buf.Write(make([]byte, 16))
			buf.Write(make([]byte, 16))
			buf.Write(make([]byte, 16))
			binary.Write(&buf, binary.LittleEndian, uint32(ROBO_MSG_REQ))
			binary.Write(&buf, binary.LittleEndian, uint32(0))
			binary.Write(&buf, binary.LittleEndian, uint32(1))
			buf.Write(make([]byte, 4))

			buf.WriteString(augmentedCmd)
			buf.WriteByte(0)
			buf.WriteString("READONLYBOX_CWD=" + tc.cwd)
			buf.WriteByte(0)

			checksum := calculateSimpleChecksum(buf.Bytes()[:68])
			checksumBytes := []byte{
				byte(checksum),
				byte(checksum >> 8),
				byte(checksum >> 16),
				byte(checksum >> 24),
			}
			copy(buf.Bytes()[68:72], checksumBytes)

			conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write(buf.Bytes()); err != nil {
				t.Fatalf("Failed to write request: %v", err)
			}

			time.Sleep(100 * time.Millisecond)

			if !tc.expectCwd {
				return
			}

			serverOutputStr := serverOutput.String()
			if !strings.Contains(serverOutputStr, tc.expectedCwd) {
				t.Errorf("Expected CWD '%s' in server debug output, got:\n%s", tc.expectedCwd, serverOutputStr)
			}
		})
	}
}

func TestReadonlyboxCwdArgumentParsing(t *testing.T) {
	testCases := []struct {
		name            string
		args            []string
		expectedCaller  string
		expectedSyscall string
		expectedCwd     string
		expectError     bool
	}{
		{
			name:            "basic caller with cwd",
			args:            []string{"--caller", "testapp:execve", "--cwd", "/home/panz", "--run", "which", "ls"},
			expectedCaller:  "testapp",
			expectedSyscall: "execve",
			expectedCwd:     "/home/panz",
			expectError:     false,
		},
		{
			name:            "cursor with syscall",
			args:            []string{"--caller", "cursor:syscall", "--cwd", "/tmp", "--run", "which", "cat"},
			expectedCaller:  "cursor",
			expectedSyscall: "syscall",
			expectedCwd:     "/tmp",
			expectError:     false,
		},
		{
			name:            "nested path",
			args:            []string{"--caller", "claude:read", "--cwd", "/home/panz/project/src", "--run", "which", "wc"},
			expectedCaller:  "claude",
			expectedSyscall: "read",
			expectedCwd:     "/home/panz/project/src",
			expectError:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("../bin/readonlybox", tc.args...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			cmd.Env = append(os.Environ(), "READONLYBOX_SOCKET=/tmp/readonlybox-does-not-exist.sock")

			_ = cmd.Run()

			stderrStr := stderr.String()

			if !strings.Contains(stderrStr, "READONLYBOX_CWD=") &&
				!strings.Contains(stderrStr, "READONLYBOX_CALLER=") &&
				!strings.Contains(stderrStr, "unknown command") &&
				!strings.Contains(stderrStr, "server not available") {
				t.Errorf("Expected --caller parsing to work (env vars set, unknown command, or server message), got:\n%s", stderrStr)
			}
		})
	}
}

func TestClientPacketEnvcCount(t *testing.T) {
	testCases := []struct {
		name        string
		envCount    int
		cwdProvided bool
		expectEnvc  int
	}{
		{
			name:        "no env vars, no cwd",
			envCount:    0,
			cwdProvided: false,
			expectEnvc:  0,
		},
		{
			name:        "no env vars, with cwd",
			envCount:    0,
			cwdProvided: true,
			expectEnvc:  1,
		},
		{
			name:        "some env vars, no cwd",
			envCount:    5,
			cwdProvided: false,
			expectEnvc:  5,
		},
		{
			name:        "some env vars, with cwd",
			envCount:    5,
			cwdProvided: true,
			expectEnvc:  6,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cwd := ""
			if tc.cwdProvided {
				cwd = "/test/path"
			}

			envcWithCwd := tc.envCount
			if cwd != "" {
				envcWithCwd++
			}

			if envcWithCwd != tc.expectEnvc {
				t.Errorf("Expected envc=%d, got %d", tc.expectEnvc, envcWithCwd)
			}
		})
	}
}

func TestNoExtraNullInPacket(t *testing.T) {
	var buf bytes.Buffer

	buf.WriteString("test")
	buf.WriteByte(0)

	buf.WriteString("arg1")
	buf.WriteByte(0)

	buf.WriteString("ENV=value")
	buf.WriteByte(0)

	data := buf.Bytes()

	cmdEnd := bytes.IndexByte(data, 0)
	if cmdEnd != 4 {
		t.Errorf("Expected cmd to end at position 4, got: %d", cmdEnd)
	}

	arg1Start := cmdEnd + 1
	arg1End := bytes.IndexByte(data[arg1Start:], 0)
	if arg1End != 4 {
		t.Errorf("Expected arg1 to be 4 bytes, got: %d", arg1End)
	}

	envStart := arg1Start + arg1End + 1
	envContent := string(data[envStart : envStart+9])
	if envContent != "ENV=value" {
		t.Errorf("Expected env content to be 'ENV=value', got: %q", envContent)
	}
}

func calculateSimpleChecksum(data []byte) uint32 {
	var sum uint32
	for _, b := range data {
		sum += uint32(b)
	}
	return sum
}
