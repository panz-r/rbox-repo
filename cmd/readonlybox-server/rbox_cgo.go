//go:build cgo
// +build cgo

/*
 * rbox_cgo.go - Go wrapper for rbox-protocol C library
 * 
 * This provides the bridge between the Go TUI server and the C library
 * for protocol handling.
 */

package main

/*
#cgo LDFLAGS: /w/rbox-repo/rbox-protocol/librbox_protocol.a /w/rbox-repo/shellsplit/src/shell_tokenizer.o -lpthread -lm
#cgo CFLAGS: -I/w/rbox-repo/rbox-protocol/include -I/w/rbox-repo/shellsplit/include

#include <rbox_protocol.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

// RBoxServer wraps the C rbox-protocol server
type RBoxServer struct {
	cServer *C.rbox_server_handle_t
	socketPath string
}

// NewRBoxServer creates a new server using the C library
func NewRBoxServer(socketPath string) (*RBoxServer, error) {
	cPath := C.CString(socketPath)
	defer C.free(unsafe.Pointer(cPath))

	cServer := C.rbox_server_handle_new(cPath)
	if cServer == nil {
		return nil, fmt.Errorf("failed to create C server")
	}

	// Listen
	if err := C.rbox_server_handle_listen(cServer); err != C.RBOX_OK {
		C.rbox_server_handle_free(cServer)
		return nil, fmt.Errorf("failed to listen: %s", C.GoString(C.rbox_strerror(err)))
	}

	// Start background thread with epoll
	if err := C.rbox_server_start(cServer); err != C.RBOX_OK {
		C.rbox_server_handle_free(cServer)
		return nil, fmt.Errorf("failed to start: %s", C.GoString(C.rbox_strerror(err)))
	}

	return &RBoxServer{
		cServer: cServer,
		socketPath: socketPath,
	}, nil
}

// GetRequest blocks until a request is ready
// Returns nil if server is stopped
func (s *RBoxServer) GetRequest() *RBoxRequest {
	if s.cServer == nil {
		return nil
	}
	
	cReq := C.rbox_server_get_request(s.cServer)
	if cReq == nil {
		return nil
	}
	
	return &RBoxRequest{cRequest: cReq}
}

// Stop signals the server to shutdown
func (s *RBoxServer) Stop() {
	if s.cServer != nil {
		C.rbox_server_stop(s.cServer)
	}
}

// Free releases all resources
func (s *RBoxServer) Free() {
	if s.cServer != nil {
		C.rbox_server_handle_free(s.cServer)
		s.cServer = nil
	}
}

// RBoxRequest wraps a C request handle
type RBoxRequest struct {
	cRequest *C.rbox_server_request_t
}

// GetCommand returns the command string
func (r *RBoxRequest) GetCommand() string {
	if r.cRequest == nil {
		return ""
	}
	cmd := C.rbox_server_request_command(r.cRequest)
	if cmd == nil {
		return ""
	}
	return C.GoString(cmd)
}

// GetArg returns the argument at the given index
func (r *RBoxRequest) GetArg(index int) string {
	if r.cRequest == nil {
		return ""
	}
	arg := C.rbox_server_request_arg(r.cRequest, C.int(index))
	if arg == nil {
		return ""
	}
	return C.GoString(arg)
}

// GetArgc returns the number of arguments
func (r *RBoxRequest) GetArgc() int {
	if r.cRequest == nil {
		return 0
	}
	return int(C.rbox_server_request_argc(r.cRequest))
}

// Decide sends the decision to the client
func (r *RBoxRequest) Decide(decision uint8, reason string, duration uint32) error {
	if r.cRequest == nil {
		return fmt.Errorf("nil request")
	}

	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))

	err := C.rbox_server_decide(r.cRequest, C.uint8_t(decision), cReason, C.uint32_t(duration))
	if err != C.RBOX_OK {
		return fmt.Errorf("decide failed: %s", C.GoString(C.rbox_strerror(err)))
	}

	// Note: C library frees the request after decide
	r.cRequest = nil

	return nil
}

// IsNil checks if the request is nil
func (r *RBoxRequest) IsNil() bool {
	return r.cRequest == nil
}

// Decision constants (match C values)
const (
	DecisionUnknown = uint8(C.RBOX_DECISION_UNKNOWN)
	DecisionAllow  = uint8(C.RBOX_DECISION_ALLOW)
	DecisionDeny   = uint8(C.RBOX_DECISION_DENY)
	DecisionError  = uint8(C.RBOX_DECISION_ERROR)
)

// Ensure socket has correct permissions
func init() {
	os.Chmod("/tmp/readonlybox.sock", 0666)
}
