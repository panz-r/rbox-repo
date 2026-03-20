/*
 * rbox_go.go - Go bindings for rbox-protocol library
 * 
 * This package provides Go wrappers for the C rbox-protocol library.
 * Use via cgo to integrate with the Go TUI server.
 */

package rbox

/*
#cgo CFLAGS: -I../include -I../../shellsplit/include
#cgo LDFLAGS: -L. -lrbox_protocol -lpthread -lm
#cgo LDFLAGS: -Wl,-rpath,/usr/local/lib

#include <rbox_protocol.h>
#include <stdlib.h>
#include <string.h>

// Need forward declarations for Go
extern rbox_server_handle_t* rbox_server_handle_new(const char* socket_path);
extern rbox_error_t rbox_server_handle_listen(rbox_server_handle_t* server);
extern rbox_error_t rbox_server_start(rbox_server_handle_t* server);
extern void rbox_server_stop(rbox_server_handle_t* server);
extern void rbox_server_handle_free(rbox_server_handle_t* server);

extern rbox_server_request_t* rbox_server_get_request(rbox_server_handle_t* server);
extern const char* rbox_server_request_command(const rbox_server_request_t* req);
extern const char* rbox_server_request_arg(const rbox_server_request_t* req, int index);
extern int rbox_server_request_argc(const rbox_server_request_t* req);
extern const rbox_parse_result_t* rbox_server_request_parse(const rbox_server_request_t* req);

extern rbox_error_t rbox_server_decide(rbox_server_request_t* req, uint8_t decision, const char* reason, uint32_t duration,
    int env_decision_count, const char** env_decision_names, const uint8_t* env_decisions);

extern const char* rbox_strerror(rbox_error_t err);
*/
import "C"
import (
	"errors"
	"unsafe"
)

// Server handle wrapper
type ServerHandle struct {
	cHandle *C.rbox_server_handle_t
}

// Request handle wrapper
type RequestHandle struct {
	cRequest *C.rbox_server_request_t
}

// Error codes
const (
	DecisionAllow = uint8(C.RBOX_DECISION_ALLOW)
	DecisionDeny  = uint8(C.RBOX_DECISION_DENY)
)

// Create a new server handle
func NewServer(socketPath string) (*ServerHandle, error) {
	cPath := C.CString(socketPath)
	defer C.free(unsafe.Pointer(cPath))

	cHandle := C.rbox_server_handle_new(cPath)
	if cHandle == nil {
		return nil, errors.New("failed to create server")
	}

	return &ServerHandle{cHandle: cHandle}, nil
}

// Start listening on the socket
func (s *ServerHandle) Listen() error {
	err := C.rbox_server_handle_listen(s.cHandle)
	if err != C.RBOX_OK {
		return errors.New(C.GoString(C.rbox_strerror(err)))
	}
	return nil
}

// Start the server (spawns background thread with epoll)
func (s *ServerHandle) Start() error {
	err := C.rbox_server_start(s.cHandle)
	if err != C.RBOX_OK {
		return errors.New(C.GoString(C.rbox_strerror(err)))
	}
	return nil
}

// Stop the server (signals shutdown, waits for thread)
func (s *ServerHandle) Stop() {
	C.rbox_server_stop(s.cHandle)
}

// Free the server handle
func (s *ServerHandle) Free() {
	C.rbox_server_handle_free(s.cHandle)
	s.cHandle = nil
}

// GetRequest blocks until a request is ready
// Returns nil if server is stopped
func (s *ServerHandle) GetRequest() *RequestHandle {
	cReq := C.rbox_server_get_request(s.cHandle)
	if cReq == nil {
		return nil
	}
	return &RequestHandle{cRequest: cReq}
}

// GetCommand returns the command string (zero-copy)
func (r *RequestHandle) GetCommand() string {
	if r.cRequest == nil {
		return ""
	}
	return C.GoString(C.rbox_server_request_command(r.cRequest))
}

// GetArg returns the argument at the given index
func (r *RequestHandle) GetArg(index int) string {
	if r.cRequest == nil {
		return ""
	}
	return C.GoString(C.rbox_server_request_arg(r.cRequest, C.int(index)))
}

// GetArgc returns the number of arguments
func (r *RequestHandle) GetArgc() int {
	if r.cRequest == nil {
		return 0
	}
	return int(C.rbox_server_request_argc(r.cRequest))
}

// Decide sends the decision back to the client and frees the request
func (r *RequestHandle) Decide(decision uint8, reason string, duration uint32) error {
	if r.cRequest == nil {
		return errors.New("nil request")
	}

	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))

	err := C.rbox_server_decide(r.cRequest, C.uint8_t(decision), cReason, C.uint32_t(duration),
		0, nil, nil)
	if err != C.RBOX_OK {
		return errors.New(C.GoString(C.rbox_strerror(err)))
	}

	// Request is freed by C library after decide
	r.cRequest = nil

	return nil
}

// IsNil checks if the request handle is nil
func (r *RequestHandle) IsNil() bool {
	return r.cRequest == nil
}
