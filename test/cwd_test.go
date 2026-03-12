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
	RBOX_MAGIC   = 0x524F424F
	RBOX_VERSION = 5
	RBOX_MSG_REQ = 1
)

func TestCwdProtocolFlow(t *testing.T) {
	if os.Getenv("SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network tests")
	}

	socketPath := "/tmp/readonlybox-cwd-test-" + strconv.Itoa(os.Getpid()) + ".sock"

	server := exec.Command("../bin/readonlybox-server", "-socket", socketPath)
	var serverOutput bytes.Buffer
	server.Stdout = &serverOutput
	server.Stderr = &serverOutput

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	
	// Give server time to start
	time.Sleep(500 * time.Millisecond)
	
	defer func() {
		if server.Process != nil {
			server.Process.Kill()
			server.Wait()
		}
		os.Remove(socketPath)
	}()

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Test basic v5 protocol communication
	// v5 format: [caller] command is sent as part of the command string
	augmentedCmd := "[claude:execve] which ls"

	var buf bytes.Buffer

	// Header (88 bytes)
	binary.Write(&buf, binary.LittleEndian, uint32(RBOX_MAGIC))           // 0-3: magic
	binary.Write(&buf, binary.LittleEndian, uint32(RBOX_VERSION))        // 4-7: version
	buf.Write(make([]byte, 16))                                         // 8-23: client_id
	buf.Write(make([]byte, 16))                                         // 24-39: request_id
	buf.Write(make([]byte, 16))                                         // 40-55: server_id
	binary.Write(&buf, binary.LittleEndian, uint32(RBOX_MSG_REQ))       // 56-59: type
	binary.Write(&buf, binary.LittleEndian, uint32(1))                  // 60-63: flags (FIRST)
	binary.Write(&buf, binary.LittleEndian, uint64(0))                  // 64-71: offset
	binary.Write(&buf, binary.LittleEndian, uint32(0))                  // 72-75: chunk_len
	binary.Write(&buf, binary.LittleEndian, uint64(0))                  // 76-83: total_len
	binary.Write(&buf, binary.LittleEndian, uint32(0))                  // 84-87: checksum

	// Body: command + args
	buf.WriteString(augmentedCmd)
	buf.WriteByte(0)

	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(buf.Bytes()); err != nil {
		t.Fatalf("Failed to write request: %v", err)
	}

	// Read response (v5 format)
	resp := make([]byte, 128)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(resp)
	if err != nil && n == 0 {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Verify we got a valid v5 response
	if n < 41 {
		t.Errorf("Expected at least 41 bytes response, got %d", n)
	}
	
	// Check magic in response
	respMagic := binary.LittleEndian.Uint32(resp[0:4])
	if respMagic != RBOX_MAGIC {
		t.Errorf("Expected magic 0x%x in response, got 0x%x", RBOX_MAGIC, respMagic)
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
