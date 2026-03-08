package protocol

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type Client struct {
	conn net.Conn
}

func Dial(socketPath string, timeout time.Duration) (*Client, error) {
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn}, nil
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) SendRequest(cmd string, args []string, cwd string) (*Response, error) {
	var buf bytes.Buffer

	clientUUID := GenerateClientUUID()
	requestUUID := GenerateRequestUUID()

	binary.Write(&buf, binary.LittleEndian, uint32(ROBO_MAGIC))
	binary.Write(&buf, binary.LittleEndian, uint32(ROBO_VERSION))
	buf.Write(clientUUID)
	buf.Write(requestUUID)
	buf.Write(make([]byte, 16))
	binary.Write(&buf, binary.LittleEndian, uint32(ROBO_MSG_REQ))
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	envc := 0
	if cwd != "" {
		envc = 1
	}
	binary.Write(&buf, binary.LittleEndian, uint32(envc))
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	fullCommand := cmd
	if len(args) > 0 {
		fullCommand = cmd + " " + JoinArgs(args)
	}
	buf.WriteString(fullCommand)
	buf.WriteByte(0)

	if cwd != "" {
		buf.WriteString("READONLYBOX_CWD=" + cwd)
		buf.WriteByte(0)
	}

	packetBytes := buf.Bytes()
	headerChecksum := CalculateChecksum(packetBytes[:68])
	binary.LittleEndian.PutUint32(packetBytes[68:], headerChecksum)

	c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := c.conn.Write(packetBytes)
	if err != nil {
		return nil, err
	}

	return c.readResponse()
}

func (c *Client) readResponse() (*Response, error) {
	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	headerBytes := make([]byte, ResponseHeaderSize)
	n, err := io.ReadFull(c.conn, headerBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read response header: %v", err)
	}
	if n < 4 {
		return nil, fmt.Errorf("short read on magic: got %d bytes", n)
	}

	h := ParseResponseHeader(headerBytes)
	if h == nil {
		return nil, fmt.Errorf("failed to parse response header")
	}

	if h.Magic != ROBO_MAGIC {
		return nil, fmt.Errorf("invalid response magic: 0x%08x", h.Magic)
	}

	reason := make([]byte, h.ReasonLen)
	reasonRead, err := c.conn.Read(reason)
	if err != nil {
		return nil, err
	}
	if reasonRead > 0 && reason[reasonRead-1] == 0 {
		reason = reason[:reasonRead-1]
	}

	return &Response{
		Decision: h.Decision,
		Reason:   string(reason),
		ServerID: h.ServerID,
		ID:       h.ID,
	}, nil
}

func JoinArgs(args []string) string {
	result := ""
	for i, arg := range args {
		if i > 0 {
			result += " "
		}
		result += arg
	}
	return result
}

type ServerHandler func(*Request) *Response

func Serve(socketPath string, handler ServerHandler) error {
	net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	return nil
}

func HandleConnection(conn net.Conn, handler ServerHandler) error {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		rawHeader := make([]byte, HeaderSize)
		n, err := io.ReadFull(reader, rawHeader)
		if err != nil {
			return err
		}
		if n < HeaderSize {
			return fmt.Errorf("short header read: %d bytes", n)
		}

		h := ParseRequestHeader(rawHeader)
		if h == nil {
			return fmt.Errorf("failed to parse header")
		}

		if h.Magic != ROBO_MAGIC || h.Version != ROBO_VERSION {
			return fmt.Errorf("invalid magic or version")
		}

		cmd, err := reader.ReadString(0)
		if err != nil {
			return err
		}
		cmd = cmd[:len(cmd)-1]

		var reqArgs []string
		for i := uint32(0); i < h.Argc; i++ {
			arg, err := reader.ReadString(0)
			if err != nil {
				return err
			}
			reqArgs = append(reqArgs, arg[:len(arg)-1])
		}

		var envVars []string
		for i := uint32(0); i < h.Envc; i++ {
			envVar, err := reader.ReadString(0)
			if err != nil {
				return err
			}
			envVars = append(envVars, envVar[:len(envVar)-1])
		}

		cwd := ""
		for _, e := range envVars {
			if strings.HasPrefix(e, "READONLYBOX_CWD=") {
				cwd = strings.TrimPrefix(e, "READONLYBOX_CWD=")
				break
			}
		}

		req := &Request{
			Cmd:  cmd,
			Args: reqArgs,
			Env:  envVars,
			Cwd:  cwd,
		}

		resp := handler(req)

		var respBuf bytes.Buffer
		var serverID [16]byte
		copy(serverID[:], GenerateServerUUID())
		respHeader := ResponseHeader{
			Magic:     ROBO_MAGIC,
			ServerID:  serverID,
			ID:        h.ID,
			Decision:  resp.Decision,
			ReasonLen: uint32(len(resp.Reason) + 1),
		}
		binary.Write(&respBuf, binary.LittleEndian, &respHeader)
		respBuf.WriteString(resp.Reason)
		respBuf.WriteByte(0)

		conn.Write(respBuf.Bytes())
	}
}
