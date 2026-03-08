package protocol

import (
	"encoding/binary"
	"time"
)

const (
	ROBO_MAGIC            = 0x524F424F
	ROBO_VERSION          = 4
	ROBO_MSG_LOG          = 0
	ROBO_MSG_REQ          = 1
	ROBO_DECISION_UNKNOWN = 0
	ROBO_DECISION_ALLOW   = 2
	ROBO_DECISION_DENY    = 3
	ROBO_DECISION_ERROR   = 4

	DefaultSocketPath  = "/tmp/readonlybox.sock"
	HeaderSize         = 72
	ResponseHeaderSize = 29
)

type PacketHeader struct {
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

type ResponseHeader struct {
	Magic     uint32
	ServerID  [16]byte
	ID        uint32
	Decision  uint8
	ReasonLen uint32
}

func ParseRequestHeader(data []byte) *PacketHeader {
	if len(data) < HeaderSize {
		return nil
	}
	h := &PacketHeader{}
	h.Magic = binary.LittleEndian.Uint32(data[0:4])
	h.Version = binary.LittleEndian.Uint32(data[4:8])
	copy(h.ClientID[:], data[8:24])
	copy(h.RequestID[:], data[24:40])
	copy(h.ServerID[:], data[40:56])
	h.ID = binary.LittleEndian.Uint32(data[56:60])
	h.Argc = binary.LittleEndian.Uint32(data[60:64])
	h.Envc = binary.LittleEndian.Uint32(data[64:68])
	h.Checksum = binary.LittleEndian.Uint32(data[68:72])
	return h
}

func ParseResponseHeader(data []byte) *ResponseHeader {
	if len(data) < ResponseHeaderSize {
		return nil
	}
	h := &ResponseHeader{}
	h.Magic = binary.LittleEndian.Uint32(data[0:4])
	copy(h.ServerID[:], data[4:20])
	h.ID = binary.LittleEndian.Uint32(data[20:24])
	h.Decision = data[24]
	h.ReasonLen = binary.LittleEndian.Uint32(data[25:29])
	return h
}

func CalculateChecksum(data []byte) uint32 {
	var sum uint32
	for _, b := range data {
		sum += uint32(b)
	}
	return sum
}

var crc32Table [256]uint32

func init() {
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

func CalculateCRC32(data []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc = (crc >> 8) ^ crc32Table[(crc^uint32(b))&0xFF]
	}
	return crc ^ 0xFFFFFFFF
}

func ValidatePacketChecksum(packet []byte, expectedChecksum uint32) bool {
	if len(packet) < HeaderSize {
		return false
	}
	original := make([]byte, 4)
	copy(original, packet[68:72])
	for i := 68; i < 72; i++ {
		packet[i] = 0
	}
	calcChecksum := CalculateCRC32(packet)
	copy(packet[68:72], original)
	return calcChecksum == expectedChecksum
}

type Request struct {
	Cmd     string
	Args    []string
	Env     []string
	Cwd     string
	Caller  string
	Syscall string
}

type Response struct {
	Decision uint8
	Reason   string
	ServerID [16]byte
	ID       uint32
}

func GenerateClientUUID() []byte {
	return []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
}

func GenerateRequestUUID() []byte {
	now := time.Now().UnixNano()
	return []byte{
		byte(now), byte(now >> 8), byte(now >> 16), byte(now >> 24),
		byte(now >> 32), byte(now >> 40), byte(now >> 48), byte(now >> 56),
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	}
}

func GenerateServerUUID() []byte {
	now := time.Now().UnixNano()
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(now >> (i % 8))
	}
	return b
}
