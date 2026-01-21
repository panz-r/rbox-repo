package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	socketPath  = flag.String("socket", SocketPath, "Unix socket path")
	verbose     = flag.Bool("v", false, "Verbose: show all commands")
	veryVerbose = flag.Bool("vv", false, "Very verbose: show all commands and logs")
	quiet       = flag.Bool("q", false, "Quiet: only show blocked commands (default)")
	logFile     = flag.String("log", "", "Log file path (empty=disabled)")
	logLevel    = flag.Int("log-level", 0, "Log level: 0=off, 1=errors, 2=info, 3=debug")
	port        = flag.Int("p", 0, "Also listen on TCP port (0=disabled)")
	tui         = flag.Bool("tui", false, "Run in TUI mode")
	debugTUI    = flag.Bool("debug-tui", false, "Debug mode: simulate TUI decisions (auto-allow after 500ms)")
	autoDeny    = flag.Bool("auto-deny", false, "Auto-deny unknown commands (for testing)")
	debugMode   = flag.Bool("debug", false, "Debug mode: print protocol traces to stderr")
)

const SocketPath = "/tmp/readonlybox.sock"
const ServerVersion = "1.0.0"
const ProtocolVersion uint32 = 4 /* Protocol version - matches client */

// UUID for identifying this server instance
var ServerUUID [16]byte

// RequestCache stores responses for duplicate request detection
// Key: clientUUID + requestUUID (32 bytes), Value: response data
type RequestCache struct {
	mu        sync.RWMutex
	responses map[string]CachedResponse
}

type CachedResponse struct {
	Decision uint8
	Reason   string
	ServerID [16]byte
	Expiry   time.Time
}

func init() {
	// Generate server UUID from random bytes and timestamp
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	// Mix in timestamp for uniqueness
	ts := time.Now().UnixNano()
	for i := 0; i < 8 && i < len(b); i++ {
		b[i] ^= byte((ts >> (i * 8)) & 0xFF)
	}
	copy(ServerUUID[:], b)
	gLogger.Log(2, "Server UUID: %x", ServerUUID)
}

func NewRequestCache() *RequestCache {
	return &RequestCache{
		responses: make(map[string]CachedResponse),
	}
}

func (c *RequestCache) Get(clientID, requestID [16]byte, serverID [16]byte) (uint8, string, bool) {
	key := string(clientID[:]) + string(requestID[:])

	c.mu.RLock()
	resp, ok := c.responses[key]
	c.mu.RUnlock()

	if !ok {
		return 0, "", false
	}

	// Check if server restarted (server ID mismatch)
	if resp.ServerID != serverID {
		c.mu.Lock()
		delete(c.responses, key)
		c.mu.Unlock()
		return 0, "", false
	}

	// Check expiry (1 hour)
	if time.Now().After(resp.Expiry) {
		c.mu.Lock()
		delete(c.responses, key)
		c.mu.Unlock()
		return 0, "", false
	}

	return resp.Decision, resp.Reason, true
}

func (c *RequestCache) Set(clientID, requestID, serverID [16]byte, decision uint8, reason string) {
	key := string(clientID[:]) + string(requestID[:])

	c.mu.Lock()
	c.responses[key] = CachedResponse{
		Decision: decision,
		Reason:   reason,
		ServerID: serverID,
		Expiry:   time.Now().Add(1 * time.Hour),
	}
	c.mu.Unlock()
}

const (
	ROBO_MAGIC            = 0x524F424F
	ROBO_MSG_LOG          = 0 /* Log message from client */
	ROBO_MSG_REQ          = 1 /* Command request from client */
	ROBO_DECISION_UNKNOWN = 0
	ROBO_DECISION_ALLOW   = 2
	ROBO_DECISION_DENY    = 3
	ROBO_DECISION_ERROR   = 4
)

// CRC32 lookup table for validating packet integrity
var crc32Table [256]uint32

func init() {
	// Generate CRC32 table (polynomial 0xEDB88320)
	for i := 0; i < 256; i++ {
		crc := uint32(i)
		for j := 0; j < 8; j++ {
			if crc&1 == 1 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
		crc32Table[i] = crc
	}
}

// Calculate CRC32 checksum
func calculateCRC32(data []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc = (crc >> 8) ^ crc32Table[(crc^uint32(b))&0xFF]
	}
	return crc ^ 0xFFFFFFFF
}

// Validate packet checksum - returns true if valid
func validatePacketChecksum(packet []byte, expectedChecksum uint32) bool {
	// Calculate checksum over entire packet (excluding checksum field at offset 68)
	// Temporarily zero out checksum field for calculation
	original := make([]byte, 4)
	copy(original, packet[68:72])
	for i := 68; i < 72; i++ {
		packet[i] = 0
	}
	calcChecksum := calculateCRC32(packet)
	// Restore checksum field
	copy(packet[68:72], original)

	return calcChecksum == expectedChecksum
}

type Logger struct {
	file     *os.File
	mu       sync.Mutex
	logLevel int
}

func NewLogger(filename string, level int) *Logger {
	if filename == "" || level == 0 {
		return nil
	}
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil
	}
	return &Logger{file: f, logLevel: level}
}

func (l *Logger) Log(level int, format string, args ...interface{}) {
	if l == nil || l.file == nil || level > l.logLevel {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, args...))
	l.file.WriteString(msg)
	l.file.Sync()
}

func (l *Logger) Close() {
	if l != nil && l.file != nil {
		l.file.Close()
	}
}

var gLogger *Logger

type Request struct {
	ID   uint32
	Cmd  string
	Args []string
	Env  []string
}

type Response struct {
	ID       uint32
	Decision uint8
	Reason   string
}

type Server struct {
	listener     net.Listener
	connections  map[string]*Connection
	mu           sync.RWMutex
	shutdown     chan struct{}
	onConnect    func()
	onDisconnect func()
	onCommand    func(requestID int, decision string, cmd string, args []string, reason string)
	onLog        func(log string)
	onRequest    func(requestID int, clientID string, cmd string, args []string)
	onDecision   func(requestID int, allowed bool, reason string)
}

type Connection struct {
	conn     net.Conn
	lastSeen time.Time
}

type RequestStatus int

const (
	RequestPending RequestStatus = iota
	RequestAllowed
	RequestDenied
)

type PendingRequest struct {
	ID           int
	ClientID     string
	Command      string
	Args         []string
	Env          []string
	Timestamp    time.Time
	Status       RequestStatus
	Reason       string
	DecisionCond *sync.Cond // Changed from polling to proper sync
}

const MaxLogEntries = 100
const MaxRequestsPerClient = 50

type LogBuffer struct {
	entries []string
	mu      sync.Mutex
}

func NewLogBuffer() *LogBuffer {
	return &LogBuffer{
		entries: make([]string, 0, MaxLogEntries),
	}
}

func (b *LogBuffer) Add(log string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, log)
	if len(b.entries) > MaxLogEntries {
		b.entries = b.entries[len(b.entries)-MaxLogEntries:]
	}
}

func (b *LogBuffer) GetAll() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := make([]string, len(b.entries))
	copy(result, b.entries)
	return result
}

type RequestQueue struct {
	requests     map[string][]*PendingRequest
	nextID       int
	mu           sync.Mutex
	pendingCount int
}

func NewRequestQueue() *RequestQueue {
	return &RequestQueue{
		requests: make(map[string][]*PendingRequest),
		nextID:   1,
	}
}

func (q *RequestQueue) Add(clientID, cmd string, args, env []string) *PendingRequest {
	q.mu.Lock()
	defer q.mu.Unlock()

	req := &PendingRequest{
		ID:           q.nextID,
		ClientID:     clientID,
		Command:      cmd,
		Args:         args,
		Env:          env,
		Timestamp:    time.Now(),
		Status:       RequestPending,
		DecisionCond: sync.NewCond(&q.mu),
	}
	q.nextID++

	q.requests[clientID] = append(q.requests[clientID], req)
	q.pendingCount++

	// Limit per client
	if len(q.requests[clientID]) > MaxRequestsPerClient {
		q.requests[clientID] = q.requests[clientID][len(q.requests[clientID])-MaxRequestsPerClient:]
	}

	return req
}

func (q *RequestQueue) GetAll() []*PendingRequest {
	q.mu.Lock()
	defer q.mu.Unlock()

	var all []*PendingRequest
	for _, clientReqs := range q.requests {
		for _, req := range clientReqs {
			all = append(all, req)
		}
	}
	return all
}

func (q *RequestQueue) GetByClient(clientID string) []*PendingRequest {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.requests[clientID]
}

func (q *RequestQueue) GetRequest(id int) *PendingRequest {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, clientReqs := range q.requests {
		for _, req := range clientReqs {
			if req.ID == id {
				return req
			}
		}
	}
	return nil
}

func (q *RequestQueue) GetClients() []string {
	q.mu.Lock()
	defer q.mu.Unlock()

	clients := make([]string, 0, len(q.requests))
	for clientID := range q.requests {
		clients = append(clients, clientID)
	}
	return clients
}

func (q *RequestQueue) SetDecision(id int, status RequestStatus, reason string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	gLogger.Log(3, "SETDECISION: id=%d status=%d reason=%s", id, status, reason)

	for _, clientReqs := range q.requests {
		for _, req := range clientReqs {
			if req.ID == id {
				if req.Status == RequestPending {
					req.Status = status
					req.Reason = reason
					q.pendingCount--
					// Wake up any goroutines waiting on this request
					gLogger.Log(3, "SETDECISION: broadcasting for request #%d", id)
					req.DecisionCond.Broadcast()
				} else {
					gLogger.Log(3, "SETDECISION: request #%d was not pending (status=%d), skipping", id, req.Status)
				}
				return
			}
		}
	}
	gLogger.Log(3, "SETDECISION: request #%d not found", id)
}

func SetRequestDecision(requestID int, allowed bool, reason string) {
	var status RequestStatus
	if allowed {
		status = RequestAllowed
	} else {
		status = RequestDenied
	}
	GlobalRequestQueue.SetDecision(requestID, status, reason)
}

func (q *RequestQueue) PendingCount() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pendingCount
}

func NewServer() *Server {
	return &Server{
		connections: make(map[string]*Connection),
		shutdown:    make(chan struct{}),
	}
}

var GlobalLogBuffer = NewLogBuffer()
var GlobalRequestQueue = NewRequestQueue()
var GlobalRequestCache = NewRequestCache()

func (s *Server) Start() error {
	// Clean up old socket
	os.Remove(*socketPath)

	// Create Unix socket
	listener, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: *socketPath,
		Net:  "unix",
	})
	if err != nil {
		return fmt.Errorf("failed to create socket: %v", err)
	}
	listener.SetUnlinkOnClose(true)
	os.Chmod(*socketPath, 0666)

	s.listener = listener

	// Accept Unix socket connections in a goroutine
	go s.acceptUnix(listener)

	// Also listen on TCP if requested
	if *port > 0 {
		tcpListener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			listener.Close()
			return fmt.Errorf("failed to create TCP listener: %v", err)
		}
		go s.acceptTCP(tcpListener)
	}

	fmt.Printf("readonlybox-server v1.0 - listening on %s\n", *socketPath)

	mode := "blocking"
	if *quiet || (!*verbose && !*veryVerbose) {
		mode = "quiet (blocked only)"
	} else if *veryVerbose {
		mode = "very verbose (all commands and logs)"
	} else if *verbose {
		mode = "verbose (all commands)"
	}
	fmt.Printf("Mode: %s\n\n", mode)

	return nil
}

func (s *Server) acceptTCP(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) acceptUnix(l *net.UnixListener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	close(s.shutdown)
}

func (s *Server) HandleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	s.mu.Lock()
	s.connections[remoteAddr] = &Connection{conn: conn, lastSeen: time.Now()}
	s.mu.Unlock()

	if s.onConnect != nil {
		s.onConnect()
	}

	reader := bufio.NewReader(conn)

	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// Read raw bytes first for debugging (Protocol v4 = 72 byte header with checksum)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		rawHeader := make([]byte, 72)
		n, err := io.ReadFull(reader, rawHeader)
		if err != nil {
			if *debugMode {
				fmt.Fprintf(os.Stderr, "DEBUG: ReadFull failed: n=%d, err=%v\n", n, err)
				fmt.Fprintf(os.Stderr, "DEBUG: Raw bytes (%d): ", n)
				for i := 0; i < n && i < 16; i++ {
					fmt.Fprintf(os.Stderr, "%02x ", rawHeader[i])
				}
				fmt.Fprintf(os.Stderr, "\n")
			}
			s.mu.Lock()
			delete(s.connections, remoteAddr)
			s.mu.Unlock()
			return
		}

		if *debugMode {
			fmt.Fprintf(os.Stderr, "DEBUG: ReadFull success, got 72 bytes: %02x%02x%02x%02x%02x%02x%02x%02x\n",
				rawHeader[0], rawHeader[1], rawHeader[2], rawHeader[3],
				rawHeader[4], rawHeader[5], rawHeader[6], rawHeader[7])
		}

		// Parse header from raw bytes (Protocol v4 with checksum)
		var hdr struct {
			Magic     uint32
			Version   uint32
			ClientID  [16]byte
			RequestID [16]byte
			ServerID  [16]byte
			ID        uint32
			Argc      uint32
			Envc      uint32
			Checksum  uint32
		}
		hdr.Magic = uint32(rawHeader[0]) | uint32(rawHeader[1])<<8 | uint32(rawHeader[2])<<16 | uint32(rawHeader[3])<<24
		hdr.Version = uint32(rawHeader[4]) | uint32(rawHeader[5])<<8 | uint32(rawHeader[6])<<16 | uint32(rawHeader[7])<<24
		copy(hdr.ClientID[:], rawHeader[8:24])
		copy(hdr.RequestID[:], rawHeader[24:40])
		copy(hdr.ServerID[:], rawHeader[40:56])
		hdr.ID = uint32(rawHeader[56]) | uint32(rawHeader[57])<<8 | uint32(rawHeader[58])<<16 | uint32(rawHeader[59])<<24
		hdr.Argc = uint32(rawHeader[60]) | uint32(rawHeader[61])<<8 | uint32(rawHeader[62])<<16 | uint32(rawHeader[63])<<24
		hdr.Envc = uint32(rawHeader[64]) | uint32(rawHeader[65])<<8 | uint32(rawHeader[66])<<16 | uint32(rawHeader[67])<<24
		hdr.Checksum = uint32(rawHeader[68]) | uint32(rawHeader[69])<<8 | uint32(rawHeader[70])<<16 | uint32(rawHeader[71])<<24

		if *debugMode {
			fmt.Fprintf(os.Stderr, "DEBUG HDR: magic=0x%08x version=%d id=%d argc=%d checksum=%08x\n",
				hdr.Magic, hdr.Version, hdr.ID, hdr.Argc, hdr.Checksum)
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.mu.Lock()
				delete(s.connections, remoteAddr)
				s.mu.Unlock()
				return
			}
			// Connection closed or error
			s.mu.Lock()
			delete(s.connections, remoteAddr)
			s.mu.Unlock()
			return
		}

		if hdr.Magic == 0 {
			// Connection was closed (EOF received as zeros)
			s.mu.Lock()
			delete(s.connections, remoteAddr)
			s.mu.Unlock()
			return
		}

		if hdr.Magic != ROBO_MAGIC {
			// Invalid magic - possible old client
			s.mu.Lock()
			delete(s.connections, remoteAddr)
			s.mu.Unlock()
			return
		}

		// Check protocol version
		if hdr.Version != ProtocolVersion {
			fmt.Fprintf(os.Stderr, "ERROR: Client protocol version %d != server protocol version %d\n", hdr.Version, ProtocolVersion)
			fmt.Fprintf(os.Stderr, "Please rebuild readonlybox-client to match server version %s\n", ServerVersion)
			s.mu.Lock()
			delete(s.connections, remoteAddr)
			s.mu.Unlock()
			return
		}

		s.mu.Lock()
		if c, ok := s.connections[remoteAddr]; ok {
			c.lastSeen = time.Now()
		}
		s.mu.Unlock()

		/* Handle LOG message (ID=0) vs REQUEST message (ID>=1) */
		if hdr.ID == ROBO_MSG_LOG {
			/* LOG message: read cmd, skip args section (ends with null), read log from first env */
			_, err := reader.ReadString(0) /* skip cmd */
			if err != nil {
				return
			}
			/* skip arguments */
			for i := uint32(0); i < hdr.Argc; i++ {
				_, err := reader.ReadString(0)
				if err != nil {
					return
				}
			}
			/* skip args section null terminator */
			_, err = reader.ReadString(0)
			if err != nil {
				return
			}
			/* read log message from first env var */
			var logMsg string
			if hdr.Envc > 0 {
				logMsg, err = reader.ReadString(0)
				if err != nil {
					return
				}
				logMsg = strings.TrimSuffix(logMsg, "\x00")
			}
			/* store log message in buffer, notify TUI, and print if very verbose */
			GlobalLogBuffer.Add(logMsg)
			if *veryVerbose {
				fmt.Printf("LOG: %s\n", logMsg)
			}
			if s.onLog != nil {
				s.onLog(logMsg)
			}
			/* skip remaining env vars */
			for i := uint32(1); i < hdr.Envc; i++ {
				_, err := reader.ReadString(0)
				if err != nil {
					return
				}
			}
			/* Don't send response - client is fire-and-forget for logs */
			continue
		}

		/* REQUEST message: read cmd, args, env and process normally */

		// Read command name
		cmd, err := reader.ReadString(0)
		if err != nil {
			if *debugMode {
				fmt.Fprintf(os.Stderr, "[DEBUG] Error reading cmd: %v\n", err)
			}
			return
		}
		cmd = strings.TrimSuffix(cmd, "\x00")
		if *debugMode {
			fmt.Fprintf(os.Stderr, "[DEBUG] Read cmd: %s\n", cmd)
		}

		// Read arguments
		var args []string
		for i := uint32(0); i < hdr.Argc; i++ {
			arg, err := reader.ReadString(0)
			if err != nil {
				if *debugMode {
					fmt.Fprintf(os.Stderr, "[DEBUG] Error reading arg %d: %v\n", i, err)
				}
				return
			}
			args = append(args, strings.TrimSuffix(arg, "\x00"))
		}
		if *debugMode {
			fmt.Fprintf(os.Stderr, "[DEBUG] Read %d args\n", len(args))
		}

		// Read environment
		var env []string
		for i := uint32(0); i < hdr.Envc; i++ {
			envVar, err := reader.ReadString(0)
			if err != nil {
				if *debugMode {
					fmt.Fprintf(os.Stderr, "[DEBUG] Error reading env %d: %v\n", i, err)
				}
				return
			}
			env = append(env, strings.TrimSuffix(envVar, "\x00"))
		}
		if *debugMode {
			fmt.Fprintf(os.Stderr, "[DEBUG] Read %d env vars\n", len(env))
		}

		// Check request cache first (for retries after server restart)
		cachedDecision, cachedReason, found := GlobalRequestCache.Get(hdr.ClientID, hdr.RequestID, hdr.ServerID)
		if found {
			gLogger.Log(3, "CACHE HIT: client=%s request=%x decision=%d reason=%s",
				remoteAddr, hdr.RequestID[:4], cachedDecision, cachedReason)

			// Send cached response
			response := struct {
				Magic     uint32
				ServerID  [16]byte
				ID        uint32
				Decision  uint8
				ReasonLen uint32
			}{
				Magic:     ROBO_MAGIC,
				ServerID:  ServerUUID,
				ID:        hdr.ID,
				Decision:  cachedDecision,
				ReasonLen: uint32(len(cachedReason) + 1),
			}

			var buf bytes.Buffer
			binary.Write(&buf, binary.LittleEndian, &response)
			buf.WriteString(cachedReason)
			buf.WriteByte(0)

			if _, err := conn.Write(buf.Bytes()); err != nil {
				s.mu.Lock()
				delete(s.connections, remoteAddr)
				s.mu.Unlock()
				return
			}
			continue
		}

		// Add to request queue and notify TUI
		pendingReq := GlobalRequestQueue.Add(remoteAddr, cmd, args, env)
		if s.onRequest != nil {
			if *debugMode {
				fmt.Fprintf(os.Stderr, "[DEBUG] Sending onCommand callback for request #%d\n", pendingReq.ID)
			}
			s.onRequest(pendingReq.ID, remoteAddr, cmd, args)
			if *debugMode {
				fmt.Fprintf(os.Stderr, "[DEBUG] onCommand callback done for request #%d\n", pendingReq.ID)
			}
		}
		gLogger.Log(3, "REQUEST #%d: client=%s cmd=%s args=%v", pendingReq.ID, remoteAddr, cmd, args)

		// Make decision
		decision, reason := makeDecision(cmd, args)
		gLogger.Log(3, "DECISION #%d: initial decision=%d reason=%s", pendingReq.ID, decision, reason)

		// Auto-deny for testing
		if *autoDeny && decision == ROBO_DECISION_ALLOW && reason == "unknown command" {
			decision = ROBO_DECISION_DENY
			reason = "auto-deny for testing"
			pendingReq.Status = RequestDenied
			pendingReq.Reason = reason
			gLogger.Log(3, "DECISION #%d: auto-deny applied", pendingReq.ID)
		}

		// In TUI mode or debug mode, unknown commands wait for user decision
		if (*tui || *debugTUI) && decision == ROBO_DECISION_ALLOW && reason == "unknown command" {
			if *debugMode {
				fmt.Fprintf(os.Stderr, "[DEBUG] Unknown command '%s', waiting for TUI decision (request #%d)...\n", cmd, pendingReq.ID)
			}

			if *debugTUI {
				// In debug mode, wait with timeout using proper sync
				type waitResult struct {
					status RequestStatus
					reason string
				}
				resultCh := make(chan waitResult, 1)
				go func() {
					pendingReq.DecisionCond.L.Lock()
					for pendingReq.Status == RequestPending {
						pendingReq.DecisionCond.Wait()
					}
					pendingReq.DecisionCond.L.Unlock()
					resultCh <- waitResult{status: pendingReq.Status, reason: pendingReq.Reason}
				}()
				select {
				case result := <-resultCh:
					if result.status == RequestAllowed {
						if *debugMode {
							fmt.Fprintf(os.Stderr, "[DEBUG] TUI allowed request #%d\n", pendingReq.ID)
						}
						decision = ROBO_DECISION_ALLOW
						reason = result.reason
					} else if result.status == RequestDenied {
						if *debugMode {
							fmt.Fprintf(os.Stderr, "[DEBUG] TUI denied request #%d\n", pendingReq.ID)
						}
						decision = ROBO_DECISION_DENY
						reason = result.reason
					}
				case <-time.After(30 * time.Second):
					if *debugMode {
						fmt.Fprintf(os.Stderr, "[DEBUG] Debug mode: auto-allowing request #%d\n", pendingReq.ID)
					}
					decision = ROBO_DECISION_ALLOW
					reason = "debug auto-allow"
				}
			} else {
				// In real TUI mode, wait indefinitely for user decision using proper sync
				pendingReq.DecisionCond.L.Lock()
				for pendingReq.Status == RequestPending {
					gLogger.Log(3, "WAIT #%d: waiting for TUI decision...", pendingReq.ID)
					pendingReq.DecisionCond.Wait()
				}
				pendingReq.DecisionCond.L.Unlock()
				gLogger.Log(3, "WAIT #%d: TUI responded with status=%d", pendingReq.ID, pendingReq.Status)
				if pendingReq.Status == RequestAllowed {
					decision = ROBO_DECISION_ALLOW
					reason = pendingReq.Reason
				} else if pendingReq.Status == RequestDenied {
					decision = ROBO_DECISION_DENY
					reason = pendingReq.Reason
				}
				gLogger.Log(3, "DECISION #%d: TUI final decision=%d reason=%s", pendingReq.ID, decision, reason)
			}
		}

		// Cache the response for potential retries
		GlobalRequestCache.Set(hdr.ClientID, hdr.RequestID, ServerUUID, decision, reason)
		gLogger.Log(3, "CACHE SET: client=%s request=%x server=%x decision=%d",
			remoteAddr, hdr.RequestID[:4], ServerUUID[:4], decision)

		// Notify TUI if callback is set
		if s.onCommand != nil {
			var decisionStr string
			switch decision {
			case ROBO_DECISION_ALLOW:
				decisionStr = "ALLOW"
			case ROBO_DECISION_DENY:
				decisionStr = "DENY"
			default:
				decisionStr = "UNKNOWN"
			}
			if *debugMode {
				fmt.Fprintf(os.Stderr, "[DEBUG] Sending onCommand callback for request #%d\n", pendingReq.ID)
			}
			s.onCommand(pendingReq.ID, decisionStr, cmd, args, reason)
			if *debugMode {
				fmt.Fprintf(os.Stderr, "[DEBUG] onCommand callback done for request #%d\n", pendingReq.ID)
			}
		}

		// Log based on mode
		if *veryVerbose || *verbose || decision == ROBO_DECISION_DENY {
			if decision == ROBO_DECISION_DENY {
				fmt.Printf("DENY: %s %v - %s\n", cmd, args, reason)
			} else if *veryVerbose || *verbose {
				fmt.Printf("ALLOW: %s %v - %s\n", cmd, args, reason)
			}
		}

		// Send response with ServerUUID for client caching
		response := struct {
			Magic     uint32
			ServerID  [16]byte
			ID        uint32
			Decision  uint8
			ReasonLen uint32
		}{
			Magic:     ROBO_MAGIC,
			ServerID:  ServerUUID,
			ID:        hdr.ID,
			Decision:  decision,
			ReasonLen: uint32(len(reason) + 1),
		}

		var buf bytes.Buffer
		binary.Write(&buf, binary.LittleEndian, &response)
		buf.WriteString(reason)
		buf.WriteByte(0)

		if _, err := conn.Write(buf.Bytes()); err != nil {
			s.mu.Lock()
			delete(s.connections, remoteAddr)
			s.mu.Unlock()
			return
		}
		gLogger.Log(3, "RESPONSE #%d: sent decision=%d reason=%s to %s", pendingReq.ID, decision, reason, remoteAddr)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	// Wrapper to match interface
	s.HandleConnection(conn)
}

func makeDecision(cmd string, args []string) (uint8, string) {
	// Strip syscall prefix if present (e.g., "execve:rm" -> "rm")
	actualCmd := cmd
	if idx := strings.LastIndex(cmd, ":"); idx >= 0 && idx < len(cmd)-1 {
		actualCmd = cmd[idx+1:]
	}

	cmdLower := strings.ToLower(actualCmd)

	// Read-only commands - always safe
	readOnlyCmds := map[string]bool{
		"ls": true, "cat": true, "head": true, "tail": true, "wc": true,
		"uniq": true, "sort": true, "grep": true, "echo": true, "date": true,
		"pwd": true, "hostname": true, "uname": true, "whoami": true, "id": true,
		"who": true, "last": true, "printenv": true, "sleep": true, "expr": true,
		"timeout": true, "true": true, "false": true, "null": true,
		"basename": true, "dirname": true, "readlink": true, "uptime": true,
		"which": true, "test": true, "[": true, "stat": true, "file": true,
		"find": true, "xargs": true, "tr": true, "cut": true, "join": true,
		"paste": true, "comm": true, "diff": true, "nl": true, "od": true,
		"base64": true, "strings": true,
	}

	if readOnlyCmds[cmdLower] {
		return ROBO_DECISION_ALLOW, "read-only command"
	}

	// Block dangerous commands - CRITICAL risk
	dangerousCmds := map[string]bool{
		"rm": true, "mv": true, "cp": true, "mkdir": true, "rmdir": true,
		"ln": true, "chmod": true, "chown": true, "touch": true, "dd": true,
	}

	if dangerousCmds[cmdLower] {
		return ROBO_DECISION_DENY, "dangerous command"
	}

	// Check for write operations - HIGH risk
	for _, arg := range args {
		if arg == ">" || arg == ">>" || arg == "2>" || arg == "&>" {
			return ROBO_DECISION_DENY, "write operation detected"
		}
	}

	// Unknown command - MEDIUM risk (requires user decision in TUI mode)
	return ROBO_DECISION_ALLOW, "unknown command"
}

// Risk level constants
type RiskLevel int

const (
	RiskLow RiskLevel = iota
	RiskMedium
	RiskHigh
	RiskCritical
)

func (r RiskLevel) String() string {
	switch r {
	case RiskLow:
		return "LOW"
	case RiskMedium:
		return "MEDIUM"
	case RiskHigh:
		return "HIGH"
	case RiskCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (r RiskLevel) Color() string {
	switch r {
	case RiskLow:
		return "#50FA7B" // Green
	case RiskMedium:
		return "#FFB86C" // Orange
	case RiskHigh:
		return "#FF5555" // Red
	case RiskCritical:
		return "#FF0000" // Bright red
	default:
		return "#6272A4" // Gray
	}
}

// Assess risk level of a command
func assessRisk(cmd string, args []string) RiskLevel {
	cmdLower := strings.ToLower(cmd)

	// Critical risk: destructive commands
	dangerousCmds := map[string]bool{
		"rm": true, "mv": true, "cp": true, "mkdir": true, "rmdir": true,
		"ln": true, "chmod": true, "chown": true, "touch": true, "dd": true,
	}
	if dangerousCmds[cmdLower] {
		return RiskCritical
	}

	// High risk: write operations
	for _, arg := range args {
		if arg == ">" || arg == ">>" || arg == "2>" || arg == "&>" {
			return RiskHigh
		}
	}

	// Medium risk: unknown commands (could be anything)
	readOnlyCmds := map[string]bool{
		"ls": true, "cat": true, "head": true, "tail": true, "wc": true,
		"uniq": true, "sort": true, "grep": true, "echo": true, "date": true,
		"pwd": true, "hostname": true, "uname": true, "whoami": true, "id": true,
		"who": true, "last": true, "printenv": true, "sleep": true, "expr": true,
		"timeout": true, "true": true, "false": true, "null": true,
		"basename": true, "dirname": true, "readlink": true, "uptime": true,
		"which": true, "test": true, "[": true, "stat": true, "file": true,
		"find": true, "xargs": true, "tr": true, "cut": true, "join": true,
		"paste": true, "comm": true, "diff": true, "nl": true, "od": true,
		"base64": true, "strings": true,
	}
	if !readOnlyCmds[cmdLower] {
		return RiskMedium
	}

	// Low risk: known read-only commands
	return RiskLow
}

func main() {
	flag.Parse()

	// Initialize verbose logger
	gLogger = NewLogger(*logFile, *logLevel)
	if gLogger != nil {
		defer gLogger.Close()
		gLogger.Log(2, "Server starting v%s, protocol v%d", ServerVersion, ProtocolVersion)
	}

	if *tui {
		RunTUIMode()
		return
	}

	server := NewServer()
	if err := server.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case <-sigChan:
	case <-server.shutdown:
	}

	fmt.Println("\nShutting down...")
	server.Stop()
	gLogger.Log(2, "Server stopped")
}
