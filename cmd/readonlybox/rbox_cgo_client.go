//go:build cgo
// +build cgo

package main

/*
#cgo LDFLAGS: /w/rbox-repo/rbox-protocol/librbox_protocol.a /w/rbox-repo/shellsplit/src/shell_tokenizer.o /w/rbox-repo/internal/client/readonlybox_dfa_data.o /w/rbox-repo/internal/client/dfa.o /w/rbox-repo/internal/client/dfa_eval.o -lpthread -lm
#cgo CFLAGS: -I/w/rbox-repo/rbox-protocol/include -I/w/rbox-repo/shellsplit/include -I/w/rbox-repo/internal/client -I/w/rbox-repo/c-dfa/include

#include <rbox_protocol.h>
#include <stdlib.h>
#include <string.h>
#include <dfa.h>

// Check DFA locally - returns 1 if allowed, 0 if not
extern int dfa_should_allow_len(const char* cmd, int cmd_len);

static int check_dfa_allow(const char* cmd, int cmd_len) {
    return dfa_should_allow_len(cmd, cmd_len);
}
*/
import "C"

import (
	"fmt"
	"os"
	"strings"
	"unsafe"
)

// Decision constants (from C library)
const (
	DecisionAllow = uint8(C.RBOX_DECISION_ALLOW)
	DecisionDeny  = uint8(C.RBOX_DECISION_DENY)
	DecisionError = uint8(C.RBOX_DECISION_ERROR)
)

// DefaultSocketPath is the default server socket
const DefaultSocketPath = "/tmp/readonlybox.sock"

// RBoxClient wraps the C library client
type RBoxClient struct {
	cClient *C.rbox_client_t
}

// NewRBoxClient connects to the ReadOnlyBox server
func NewRBoxClient(socketPath string) (*RBoxClient, error) {
	cPath := C.CString(socketPath)
	defer C.free(unsafe.Pointer(cPath))

	client := C.rbox_client_connect(cPath)
	if client == nil {
		return nil, fmt.Errorf("failed to connect to %s", socketPath)
	}

	return &RBoxClient{cClient: client}, nil
}

// NewRBoxClientWithRetry connects with exponential backoff retry
func NewRBoxClientWithRetry(socketPath string, baseDelayMs uint32, maxRetries uint32) (*RBoxClient, error) {
	cPath := C.CString(socketPath)
	defer C.free(unsafe.Pointer(cPath))

	client := C.rbox_client_connect_retry(cPath, C.uint32_t(baseDelayMs), C.uint32_t(maxRetries))
	if client == nil {
		return nil, fmt.Errorf("failed to connect to %s after retries", socketPath)
	}

	return &RBoxClient{cClient: client}, nil
}

// SendRequest sends a command to the server and gets the decision
// command: the command to execute
// args: command arguments
// Returns: decision (DecisionAllow/DecisionDeny), reason string, error
func (c *RBoxClient) SendRequest(command string, args []string) (uint8, string, error) {
	if c.cClient == nil {
		return DecisionError, "", fmt.Errorf("client not connected")
	}

	// Build argv for C
	argv := make([]*C.char, len(args))
	for i, arg := range args {
		argv[i] = C.CString(arg)
		defer C.free(unsafe.Pointer(argv[i]))
	}

	// Convert command
	cCommand := C.CString(command)
	defer C.free(unsafe.Pointer(cCommand))

	// Prepare response struct
	var response C.rbox_response_t

	// Send request
	cArgc := C.int(len(args))
	var cArgv **C.char
	if len(args) > 0 {
		cArgv = &argv[0]
	}

	err := C.rbox_client_send_request(c.cClient, cCommand, cArgc, cArgv, &response)
	if err != C.RBOX_OK {
		errStr := C.GoString(C.rbox_strerror(err))
		return DecisionError, "", fmt.Errorf("request failed: %s", errStr)
	}

	reason := C.GoString(&response.reason[0])
	return uint8(response.decision), reason, nil
}

// Close closes the client connection
func (c *RBoxClient) Close() {
	if c.cClient != nil {
		C.rbox_client_close(c.cClient)
		c.cClient = nil
	}
}

// BlockingRequest is a convenience function that connects, sends, and gets response
// It handles connection retry internally
func BlockingRequest(socketPath, command string, args []string, baseDelayMs uint32, maxRetries uint32) (uint8, string, error) {
	client, err := NewRBoxClientWithRetry(socketPath, baseDelayMs, maxRetries)
	if err != nil {
		return DecisionError, "", err
	}
	defer client.Close()

	return client.SendRequest(command, args)
}

// SimpleRequest is a convenience for simple use cases
// Uses default retry settings (100ms base, 10 retries)
func SimpleRequest(socketPath, command string, args ...string) (uint8, string, error) {
	return BlockingRequest(socketPath, command, args, 100, 10)
}

// CheckDFALocal checks if command is allowed by local DFA without contacting server
// Returns: isAllowed (bool), reason (string)
func CheckDFALocal(command string, args []string) (bool, string) {
	// Build full command string
	fullCmd := command
	if len(args) > 0 {
		fullCmd = command + " " + strings.Join(args, " ")
	}

	cCmd := C.CString(fullCmd)
	defer C.free(unsafe.Pointer(cCmd))

	result := C.check_dfa_allow(cCmd, C.int(len(fullCmd)))
	if result == 1 {
		return true, "DFA fast-path"
	}
	return false, "unknown"
}

// augmentCommandWithContext adds [caller:syscall] or [caller] prefix if env vars set
func augmentCommandWithContext(cmd string, args []string) string {
	caller := os.Getenv("READONLYBOX_CALLER")
	syscall := os.Getenv("READONLYBOX_SYSCALL")

	fullCommand := cmd
	if len(args) > 0 {
		fullCommand = cmd + " " + strings.Join(args, " ")
	}

	if caller != "" && syscall != "" {
		fullCommand = fmt.Sprintf("[%s:%s] %s", caller, syscall, fullCommand)
	} else if caller != "" {
		fullCommand = fmt.Sprintf("[%s] %s", caller, fullCommand)
	}

	return fullCommand
}
