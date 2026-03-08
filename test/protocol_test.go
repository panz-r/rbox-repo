package test

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/panz/openroutertest/internal/protocol"
)

type testServer struct {
	listener *net.UnixListener
	mu       sync.RWMutex
	requests []testRequest
	quit     chan struct{}
}

type testRequest struct {
	Cmd      string
	Args     []string
	Env      []string
	Cwd      string
	Decision uint8
	Reason   string
}

func newTestServer(socketPath string) (*testServer, error) {
	os.Remove(socketPath)

	listener, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: socketPath,
		Net:  "unix",
	})
	if err != nil {
		return nil, err
	}
	os.Chmod(socketPath, 0666)

	server := &testServer{
		listener: listener,
		requests: make([]testRequest, 0),
		quit:     make(chan struct{}),
	}

	go server.acceptLoop()
	return server, nil
}

func (s *testServer) acceptLoop() {
	for {
		select {
		case <-s.quit:
			return
		default:
		}

		s.listener.SetDeadline(time.Now().Add(100 * time.Millisecond))
		conn, err := s.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}
		go s.handleConnection(conn)
	}
}

func (s *testServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	err := protocol.HandleConnection(conn, s.handleRequest)
	if err != nil {
	}
}

func (s *testServer) handleRequest(req *protocol.Request) *protocol.Response {
	decision, reason := makeTestDecision(req.Cmd, req.Args)

	s.mu.Lock()
	s.requests = append(s.requests, testRequest{
		Cmd:      req.Cmd,
		Args:     req.Args,
		Env:      req.Env,
		Cwd:      req.Cwd,
		Decision: decision,
		Reason:   reason,
	})
	s.mu.Unlock()

	return &protocol.Response{
		Decision: decision,
		Reason:   reason,
	}
}

func makeTestDecision(cmd string, args []string) (uint8, string) {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return protocol.ROBO_DECISION_DENY, "empty command"
	}

	cmdLower := strings.ToLower(fields[0])

	readOnlyCmds := map[string]bool{
		"ls": true, "cat": true, "head": true, "tail": true, "wc": true,
		"uniq": true, "sort": true, "grep": true, "echo": true, "date": true,
		"pwd": true, "hostname": true, "uname": true, "whoami": true, "id": true,
		"who": true, "last": true, "printenv": true, "sleep": true, "expr": true,
		"timeout": true, "true": true, "false": true,
		"basename": true, "dirname": true, "readlink": true, "uptime": true,
		"which": true, "test": true, "[": true, "stat": true, "file": true,
		"find": true, "xargs": true, "tr": true, "cut": true, "join": true,
		"paste": true, "comm": true, "diff": true, "nl": true, "od": true,
		"base64": true, "strings": true,
	}

	if readOnlyCmds[cmdLower] {
		if strings.Contains(cmd, " >") || strings.Contains(cmd, " >>") || strings.Contains(cmd, " 2>") || strings.Contains(cmd, " &>") {
			return protocol.ROBO_DECISION_DENY, "write operation detected"
		}
		return protocol.ROBO_DECISION_ALLOW, "read-only command"
	}

	dangerousCmds := map[string]bool{
		"rm": true, "mv": true, "cp": true, "mkdir": true, "rmdir": true,
		"ln": true, "chmod": true, "chown": true, "touch": true, "dd": true,
	}

	if dangerousCmds[cmdLower] {
		return protocol.ROBO_DECISION_DENY, "dangerous command"
	}

	for _, arg := range args {
		if arg == ">" || arg == ">>" || arg == "2>" || arg == "&>" {
			return protocol.ROBO_DECISION_DENY, "write operation detected"
		}
	}

	if strings.Contains(cmd, " >") || strings.Contains(cmd, " >>") || strings.Contains(cmd, " 2>") || strings.Contains(cmd, " &>") {
		return protocol.ROBO_DECISION_DENY, "write operation detected"
	}

	return protocol.ROBO_DECISION_ALLOW, "unknown command"
}

func (s *testServer) stop() {
	close(s.quit)
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *testServer) getRequests() []testRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.requests
}

func TestProtocolValidRequest(t *testing.T) {
	if os.Getenv("SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network tests")
	}

	socketPath := "/tmp/readonlybox-proto-test-" + strconv.Itoa(os.Getpid()) + ".sock"

	server, err := newTestServer(socketPath)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.stop()
	defer os.Remove(socketPath)

	time.Sleep(100 * time.Millisecond)

	client, err := protocol.Dial(socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer client.Close()

	resp, err := client.SendRequest("ls -la", nil, "/home/test")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.Decision != protocol.ROBO_DECISION_ALLOW {
		t.Errorf("Expected ALLOW decision, got %d", resp.Decision)
	}

	if !strings.Contains(resp.Reason, "read-only") {
		t.Errorf("Expected reason to contain 'read-only', got: %s", resp.Reason)
	}

	requests := server.getRequests()
	if len(requests) != 1 {
		t.Errorf("Expected 1 request, got %d", len(requests))
	}

	if requests[0].Cmd != "ls -la" {
		t.Errorf("Expected cmd 'ls -la', got: %s", requests[0].Cmd)
	}

	if requests[0].Cwd != "/home/test" {
		t.Errorf("Expected cwd '/home/test', got: %s", requests[0].Cwd)
	}
}

func TestProtocolDangerousCommand(t *testing.T) {
	if os.Getenv("SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network tests")
	}

	socketPath := "/tmp/readonlybox-proto-test-" + strconv.Itoa(os.Getpid()) + ".sock"

	server, err := newTestServer(socketPath)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.stop()
	defer os.Remove(socketPath)

	time.Sleep(100 * time.Millisecond)

	client, err := protocol.Dial(socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer client.Close()

	resp, err := client.SendRequest("rm -rf /", nil, "/tmp")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.Decision != protocol.ROBO_DECISION_DENY {
		t.Errorf("Expected DENY decision, got %d", resp.Decision)
	}

	if !strings.Contains(resp.Reason, "dangerous") {
		t.Errorf("Expected reason to contain 'dangerous', got: %s", resp.Reason)
	}
}

func TestProtocolVersionMismatch(t *testing.T) {
	if os.Getenv("SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network tests")
	}

	socketPath := "/tmp/readonlybox-proto-test-" + strconv.Itoa(os.Getpid()) + ".sock"

	server, err := newTestServer(socketPath)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.stop()
	defer os.Remove(socketPath)

	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(protocol.ROBO_MAGIC))
	binary.Write(&buf, binary.LittleEndian, uint32(999))
	buf.Write(make([]byte, 64))

	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.Write(buf.Bytes())

	time.Sleep(200 * time.Millisecond)

	oneByte := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Read(oneByte)

	if err == nil {
		t.Error("Expected server to close connection on version mismatch")
	}
}

func TestProtocolInvalidMagic(t *testing.T) {
	if os.Getenv("SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network tests")
	}

	socketPath := "/tmp/readonlybox-proto-test-" + strconv.Itoa(os.Getpid()) + ".sock"

	server, err := newTestServer(socketPath)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.stop()
	defer os.Remove(socketPath)

	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(0xDEADBEEF))
	binary.Write(&buf, binary.LittleEndian, uint32(protocol.ROBO_VERSION))
	buf.Write(make([]byte, 64))

	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.Write(buf.Bytes())

	time.Sleep(200 * time.Millisecond)

	oneByte := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Read(oneByte)

	if err == nil {
		t.Error("Expected server to close connection on invalid magic")
	}
}

func TestProtocolMultipleRequests(t *testing.T) {
	if os.Getenv("SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network tests")
	}

	socketPath := "/tmp/readonlybox-proto-test-" + strconv.Itoa(os.Getpid()) + ".sock"

	server, err := newTestServer(socketPath)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.stop()
	defer os.Remove(socketPath)

	time.Sleep(100 * time.Millisecond)

	client, err := protocol.Dial(socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer client.Close()

	requests := []struct {
		cmd      string
		args     []string
		decision uint8
	}{
		{"ls", nil, protocol.ROBO_DECISION_ALLOW},
		{"cat /etc/passwd", nil, protocol.ROBO_DECISION_ALLOW},
		{"find . -name test", nil, protocol.ROBO_DECISION_ALLOW},
		{"rm file", nil, protocol.ROBO_DECISION_DENY},
	}

	for _, req := range requests {
		resp, err := client.SendRequest(req.cmd, req.args, "/tmp")
		if err != nil {
			t.Fatalf("Request failed for %s: %v", req.cmd, err)
		}
		if resp.Decision != req.decision {
			t.Errorf("Expected decision %d for %s, got %d (%s)", req.decision, req.cmd, resp.Decision, resp.Reason)
		}
	}

	serverRequests := server.getRequests()
	if len(serverRequests) != len(requests) {
		t.Errorf("Expected %d requests, got %d", len(requests), len(serverRequests))
	}
}

func TestProtocolWriteOperationDetection(t *testing.T) {
	if os.Getenv("SKIP_NETWORK_TESTS") == "1" {
		t.Skip("Skipping network tests")
	}

	socketPath := "/tmp/readonlybox-proto-test-" + strconv.Itoa(os.Getpid()) + ".sock"

	server, err := newTestServer(socketPath)
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.stop()
	defer os.Remove(socketPath)

	time.Sleep(100 * time.Millisecond)

	client, err := protocol.Dial(socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer client.Close()

	resp, err := client.SendRequest("echo test > output.txt", nil, "/tmp")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	if resp.Decision != protocol.ROBO_DECISION_DENY {
		t.Errorf("Expected DENY for write operation, got %d", resp.Decision)
	}

	if !strings.Contains(resp.Reason, "write") {
		t.Errorf("Expected reason to contain 'write', got: %s", resp.Reason)
	}
}
