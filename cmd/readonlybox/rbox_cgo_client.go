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

// BlockingRequest sends a command to the server and waits for response
// Handles connection retries and request resends automatically
// baseDelayMs: minimum 10ms, maxRetries: 0 means unlimited
// caller: identifies the calling application (e.g., "ptrace", "--judge")
// syscall: optional syscall context (e.g., "execve")
func BlockingRequest(socketPath, command, caller, syscall string, args []string, baseDelayMs uint32, maxRetries uint32) (uint8, string, error) {
	// Ensure minimum base delay
	if baseDelayMs < 10 {
		baseDelayMs = 10
	}

	// Build argv for C
	var cArgv **C.char = nil
	if len(args) > 0 {
		argv := make([]*C.char, len(args))
		for i, arg := range args {
			argv[i] = C.CString(arg)
			defer C.free(unsafe.Pointer(argv[i]))
		}
		cArgv = &argv[0]
	} else {
	}

	// Convert command
	cCommand := C.CString(command)
	defer C.free(unsafe.Pointer(cCommand))

	// Convert caller info
	cCaller := C.CString(caller)
	defer C.free(unsafe.Pointer(cCaller))
	
	cSyscall := C.CString(syscall)
	defer C.free(unsafe.Pointer(cSyscall))

	// Prepare response struct
	var response C.rbox_response_t

	// Use blocking request which handles retries automatically
	// Parameters: socket_path, command, argc, argv, caller, syscall, response, base_delay, max_retries
	err := C.rbox_blocking_request(
		C.CString(socketPath),
		cCommand,
		C.int(len(args)),
		cArgv,
		cCaller,
		cSyscall,
		&response,
		C.uint32_t(baseDelayMs),
		C.uint32_t(maxRetries),
	)
	
	if err != C.RBOX_OK {
		errStr := C.GoString(C.rbox_strerror(err))
		return DecisionError, "", fmt.Errorf("request failed: %s", errStr)
	}

	reason := C.GoString(&response.reason[0])
	return uint8(response.decision), reason, nil
}

// SimpleRequest is a convenience for simple use cases
// Uses default retry settings (10ms base, unlimited retries)
func SimpleRequest(socketPath, command, caller, syscall string, args ...string) (uint8, string, error) {
	return BlockingRequest(socketPath, command, caller, syscall, args, 10, 0)
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
