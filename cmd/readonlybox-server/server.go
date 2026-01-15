package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
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
	port        = flag.Int("p", 0, "Also listen on TCP port (0=disabled)")
	tui         = flag.Bool("tui", false, "Run in TUI mode")
)

const SocketPath = "/tmp/readonlybox.sock"

const (
	ROBO_MAGIC            = 0x524F424F
	ROBO_VERSION          = 1
	ROBO_MSG_LOG          = 0 /* Log message from client */
	ROBO_MSG_REQ          = 1 /* Command request from client */
	ROBO_DECISION_UNKNOWN = 0
	ROBO_DECISION_ALLOW   = 2
	ROBO_DECISION_DENY    = 3
	ROBO_DECISION_ERROR   = 4
)

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
	onCommand    func(decision string, cmd string, args []string, reason string)
	onLog        func(log string)
}

type Connection struct {
	conn     net.Conn
	lastSeen time.Time
}

const MaxLogEntries = 100

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

func NewServer() *Server {
	return &Server{
		connections: make(map[string]*Connection),
		shutdown:    make(chan struct{}),
	}
}

var GlobalLogBuffer = NewLogBuffer()

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

		// Read magic and header
		var hdr struct {
			Magic uint32
			ID    uint32
			Argc  uint32
			Envc  uint32
		}
		err := binary.Read(reader, binary.LittleEndian, &hdr)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.mu.Lock()
				delete(s.connections, remoteAddr)
				s.mu.Unlock()
				return
			}
			s.mu.Lock()
			delete(s.connections, remoteAddr)
			s.mu.Unlock()
			return
		}

		if hdr.Magic != ROBO_MAGIC {
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
			/* send simple ALLOW response for log message */
			response := struct {
				Magic     uint32
				ID        uint32
				Decision  uint8
				ReasonLen uint32
			}{
				Magic:     ROBO_MAGIC,
				ID:        hdr.ID,
				Decision:  ROBO_DECISION_ALLOW,
				ReasonLen: 0,
			}
			var buf bytes.Buffer
			binary.Write(&buf, binary.LittleEndian, &response)
			if _, err := conn.Write(buf.Bytes()); err != nil {
				s.mu.Lock()
				delete(s.connections, remoteAddr)
				s.mu.Unlock()
				return
			}
			continue
		}

		/* REQUEST message: read cmd, args, env and process normally */

		// Read command name
		cmd, err := reader.ReadString(0)
		if err != nil {
			return
		}
		cmd = strings.TrimSuffix(cmd, "\x00")

		// Read arguments
		var args []string
		for i := uint32(0); i < hdr.Argc; i++ {
			arg, err := reader.ReadString(0)
			if err != nil {
				return
			}
			args = append(args, strings.TrimSuffix(arg, "\x00"))
		}

		// Read environment
		var env []string
		for i := uint32(0); i < hdr.Envc; i++ {
			envVar, err := reader.ReadString(0)
			if err != nil {
				return
			}
			env = append(env, strings.TrimSuffix(envVar, "\x00"))
		}

		// Make decision
		decision, reason := makeDecision(cmd, args)

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
			s.onCommand(decisionStr, cmd, args, reason)
		}

		// Log based on mode
		if *veryVerbose || *verbose || decision == ROBO_DECISION_DENY {
			if decision == ROBO_DECISION_DENY {
				fmt.Printf("DENY: %s %v - %s\n", cmd, args, reason)
			} else if *veryVerbose || *verbose {
				fmt.Printf("ALLOW: %s %v - %s\n", cmd, args, reason)
			}
		}

		// Send response
		response := struct {
			Magic     uint32
			ID        uint32
			Decision  uint8
			ReasonLen uint32
		}{
			Magic:     ROBO_MAGIC,
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
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	// Wrapper to match interface
	s.HandleConnection(conn)
}

func makeDecision(cmd string, args []string) (uint8, string) {
	cmdLower := strings.ToLower(cmd)

	// Read-only commands
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

	// Block dangerous commands
	dangerousCmds := map[string]bool{
		"rm": true, "mv": true, "cp": true, "mkdir": true, "rmdir": true,
		"ln": true, "chmod": true, "chown": true, "touch": true, "dd": true,
	}

	if dangerousCmds[cmdLower] {
		return ROBO_DECISION_DENY, "dangerous command"
	}

	// Check for write operations
	for _, arg := range args {
		if arg == ">" || arg == ">>" || arg == "2>" || arg == "&>" {
			return ROBO_DECISION_DENY, "write operation detected"
		}
	}

	// Unknown command - allow by default
	return ROBO_DECISION_ALLOW, "unknown command"
}

func main() {
	flag.Parse()

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
}
