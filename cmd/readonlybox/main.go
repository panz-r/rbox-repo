package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/panz/openroutertest/internal/access"
	"github.com/panz/openroutertest/internal/config"
	"github.com/panz/openroutertest/internal/readonlybox"
)

func main() {
	if len(os.Args) >= 2 {
		if os.Args[1] == "--configure-access" {
			handleConfigureAccess()
			return
		}
		if os.Args[1] == "--show-access" {
			handleShowAccess()
			return
		}
		if os.Args[1] == "shell" {
			handleShell()
			return
		}
		if os.Args[1] == "install-links" {
			handleInstallLinks()
			return
		}
		if os.Args[1] == "--run" {
			handleRun()
			return
		}
	}

	command := ""
	args := []string{}

	if len(os.Args) >= 2 {
		argv0 := filepath.Base(os.Args[0])
		if isSymlinkCommand(argv0) {
			// Strip "ro-" prefix from symlink name to get actual command
			command = strings.TrimPrefix(argv0, "ro-")
			args = os.Args[1:]
		} else {
			command = os.Args[1]
			args = os.Args[2:]
		}
	}

	if command == "" {
		fmt.Fprintf(os.Stderr, "readonlybox: No command provided\n")
		fmt.Fprintf(os.Stderr, "Usage: readonlybox <command> [args...]\n")
		fmt.Fprintf(os.Stderr, "\nAvailable commands:\n")
		readonlybox.ListCommands()
		fmt.Fprintf(os.Stderr, "\nSpecial commands:\n")
		fmt.Fprintf(os.Stderr, "  shell              Launch a shell with read-only commands\n")
		fmt.Fprintf(os.Stderr, "  install-links      Install symlinks for all commands\n")
		fmt.Fprintf(os.Stderr, "  --configure-access <config-file>  Configure access control\n")
		fmt.Fprintf(os.Stderr, "  --show-access                    Show current access configuration\n")
		fmt.Fprintf(os.Stderr, "  --run <path> <args...>           Run validated command (internal use)\n")
		os.Exit(1)
	}

	accessEngine, err := loadAccessControlEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: Failed to load access control: %v\n", err)
		fmt.Fprintf(os.Stderr, "Using default read-only mode\n")
	} else {
		readonlybox.SetAccessEngine(accessEngine)
	}

	if accessEngine != nil {
		allowedCommands := accessEngine.GetAllowedCommands()
		isAllowed := false
		for _, cmd := range allowedCommands {
			if cmd == command {
				isAllowed = true
				break
			}
		}

		if !isAllowed {
			fmt.Fprintf(os.Stderr, "readonlybox: Command '%s' is not allowed by access control policy\n", command)
			os.Exit(1)
		}
	}

	if err := readonlybox.ExecuteCommand(command, args); err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: %v\n", err)
		os.Exit(1)
	}
}

/* --run handler: validates and executes original command via server
 * Usage: readonlybox --run <original-path> <original-args...>
 */
func handleRun() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "readonlybox: --run requires at least the path argument\n")
		os.Exit(1)
	}

	originalPath := os.Args[2]
	originalArgs := os.Args[2:] /* Include path as argv[0] */

	/* Get just the command name for validation */
	command := filepath.Base(originalPath)

	/* Skip validation if server is not available - fallback to local check */
	client, err := newServerClient()
	if err != nil {
		/* Server not available - use local validation */
		fmt.Fprintf(os.Stderr, "readonlybox: server not available, using local validation\n")
		handleRunLocal(command, originalPath, originalArgs)
		return
	}
	defer client.close()

	/* Ask server for decision */
	/* Skip argv[0] when sending to server (the command name is in 'command') */
	argsForServer := originalArgs[1:]
	allowed, reason, err := client.requestDecision(command, argsForServer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: server error: %v, falling back to local validation\n", err)
		handleRunLocal(command, originalPath, originalArgs)
		return
	}

	if !allowed {
		fmt.Fprintf(os.Stderr, "readonlybox: %s\n", reason)
		os.Exit(1)
	}

	/* Server allowed - execute the command */
	executeCommand(originalPath, argsForServer)
}

/* handleRunLocal - fallback when server is unavailable */
func handleRunLocal(command, originalPath string, originalArgs []string) {
	/* Check if command is in readonlybox registry */
	cmd, exists := readonlybox.CommandRegistry[command]
	if !exists {
		fmt.Fprintf(os.Stderr, "readonlybox: Permission denied: '%s' is not a read-only command\n", command)
		os.Exit(1)
	}

	/* Validate arguments using the command's safety check */
	args := originalArgs[1:]

	/* Call the handler to validate and execute */
	if err := cmd.Handler(args); err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: %v\n", err)
		os.Exit(1)
	}

	/* Handler should have exec'd the command, if it returns, something went wrong */
	fmt.Fprintf(os.Stderr, "readonlybox: command handler returned unexpectedly\n")
	os.Exit(1)
}

/* executeCommand - execute the actual command using syscall.Exec */
func executeCommand(path string, args []string) {
	/* Find the real command in PATH */
	cmdPath, err := exec.LookPath(path)
	if err != nil {
		cmdPath = path /* Use as-is if not in PATH */
	}

	/* Build environment */
	env := os.Environ()

	/* Use syscall.Exec to replace current process */
	argv0 := filepath.Base(path)
	err = syscall.Exec(cmdPath, append([]string{argv0}, args...), env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: failed to execute %s: %v\n", path, err)
		os.Exit(1)
	}
}

func isSymlinkCommand(name string) bool {
	if name == "readonlybox" || name == "main" {
		return false
	}

	// Check for ro-* prefix (symlink names)
	if strings.HasPrefix(name, "ro-") {
		base := strings.TrimPrefix(name, "ro-")
		knownCommands := map[string]bool{
			"git": true, "find": true, "ls": true, "cat": true, "grep": true,
			"head": true, "tail": true, "echo": true, "date": true, "sort": true,
			"wc": true, "uniq": true, "tr": true, "cut": true, "paste": true,
			"join": true, "diff": true, "comm": true, "sed": true, "awk": true,
			"df": true, "du": true, "ps": true, "free": true,
			"stat": true, "file": true, "touch": true, "mkdir": true, "rm": true,
			"rmdir": true, "cp": true, "mv": true, "ln": true, "chmod": true,
			"chown": true, "pwd": true, "cd": true, "hostname": true, "uname": true,
			"whoami": true, "id": true, "who": true, "last": true, "printenv": true,
			"sleep": true, "expr": true, "test": true, "timeout": true, "man": true,
			"tar": true, "gzip": true, "gunzip": true, "bzip2": true, "xz": true,
			"dd": true, "od": true, "strings": true, "base64": true,
			"bash": true, "sh": true, "ulimit": true, "readlink": true,
			"basename": true, "dirname": true, "uptime": true, "which": true,
			"yes": true, "false": true, "true": true, "null": true,
		}
		return knownCommands[base]
	}

	// Also check for bare command names (installed directly)
	knownCommands := map[string]bool{
		"git": true, "find": true, "ls": true, "cat": true, "grep": true,
		"head": true, "tail": true, "echo": true, "date": true, "sort": true,
		"wc": true, "uniq": true, "tr": true, "cut": true, "paste": true,
		"join": true, "diff": true, "comm": true, "sed": true, "awk": true,
		"df": true, "du": true, "ps": true, "free": true,
		"stat": true, "file": true, "touch": true, "mkdir": true, "rm": true,
		"rmdir": true, "cp": true, "mv": true, "ln": true, "chmod": true,
		"chown": true, "pwd": true, "cd": true, "hostname": true, "uname": true,
		"whoami": true, "id": true, "who": true, "last": true, "printenv": true,
		"sleep": true, "expr": true, "test": true, "timeout": true, "man": true,
		"tar": true, "gzip": true, "gunzip": true, "bzip2": true, "xz": true,
		"dd": true, "od": true, "strings": true, "base64": true,
		"bash": true, "sh": true, "ulimit": true, "readlink": true,
		"basename": true, "dirname": true, "uptime": true, "which": true,
		"yes": true, "false": true, "true": true, "null": true,
	}

	return knownCommands[name]
}

func handleShell() {
	shellPath := "/bin/sh"

	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "--bash" {
			shellPath = "/bin/bash"
		}
	}

	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox shell: failed to get executable path: %v\n", err)
		os.Exit(1)
	}

	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox shell: failed to resolve executable: %v\n", err)
		os.Exit(1)
	}

	symlinkDir, err := createSymlinkDir(executable)
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox shell: failed to create symlinks: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(symlinkDir)

	currentPath := os.Getenv("PATH")
	newPath := symlinkDir
	if currentPath != "" {
		newPath = newPath + string(os.PathListSeparator) + currentPath
	}

	env := os.Environ()
	newEnv := make([]string, 0, len(env)+4)
	for _, e := range env {
		if !strings.HasPrefix(e, "PATH=") && !strings.HasPrefix(e, "READONLYBOX_") {
			newEnv = append(newEnv, e)
		}
	}
	newEnv = append(newEnv, "PATH="+newPath)
	newEnv = append(newEnv, "READONLYBOX_ACTIVE=1")
	newEnv = append(newEnv, "READONLYBOX_SYMLINK_DIR="+symlinkDir)

	fmt.Printf("readonlybox shell - Commands are intercepted via symlinks\n")
	fmt.Printf("Symlink directory: %s\n", symlinkDir)
	fmt.Printf("Shell: %s\n\n", shellPath)

	// Build a simple shell script that runs commands from stdin
	script := fmt.Sprintf(`#!/bin/sh
# readonlybox shell wrapper
# PATH is set to prioritize readonlybox symlinks
# WARNING: Commands using absolute paths (e.g., /bin/bash -c) bypass readonlybox!

export PATH="%s"
export READONLYBOX_ACTIVE=1
export READONLYBOX_SYMLINK_DIR="%s"

echo "readonlybox shell - Commands intercepted via symlinks"
echo "WARNING: Absolute paths like /bin/bash bypass readonlybox!"
echo "Type 'exit' to leave."
echo ""

exec %s
`, newPath, symlinkDir, shellPath)

	tmpScript, err := os.CreateTemp("", "readonlybox-shell-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox shell: failed to create temp script: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(tmpScript.Name())

	if _, err := tmpScript.WriteString(script); err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox shell: failed to write script: %v\n", err)
		os.Exit(1)
	}
	tmpScript.Close()
	os.Chmod(tmpScript.Name(), 0755)

	cmd := exec.Command("/bin/sh", tmpScript.Name())
	cmd.Env = newEnv
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox shell: shell exited: %v\n", err)
	}
}

func createSymlinkDir(executable string) (string, error) {
	symlinkDir, err := os.MkdirTemp("", "readonlybox-")
	if err != nil {
		return "", err
	}

	commands := getAllCommands()

	for _, cmd := range commands {
		symlinkPath := filepath.Join(symlinkDir, cmd)
		err := os.Symlink(executable, symlinkPath)
		if err != nil {
			os.RemoveAll(symlinkDir)
			return "", err
		}
	}

	return symlinkDir, nil
}

func getAllCommands() []string {
	return []string{
		"git", "find", "ls", "cat", "grep", "head", "tail", "echo", "date",
		"sort", "wc", "uniq", "tr", "cut", "paste", "join", "diff", "comm",
		"sed", "awk", "df", "du", "ps", "free", "stat", "file", "touch",
		"mkdir", "rm", "rmdir", "cp", "mv", "ln", "chmod", "chown", "pwd",
		"hostname", "uname", "whoami", "id", "who", "last", "printenv",
		"sleep", "expr", "timeout", "man", "tar", "gzip", "bzip2", "dd",
		"od", "strings", "bash", "sh", "ulimit", "readlink", "basename",
		"dirname", "uptime", "which", "yes", "true", "false", "null",
	}
}

func handleInstallLinks() {
	targetDir := "/usr/local/bin"
	if len(os.Args) >= 3 {
		targetDir = os.Args[2]
	}

	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: failed to get executable path: %v\n", err)
		os.Exit(1)
	}

	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: failed to resolve executable: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: failed to create directory %s: %v\n", targetDir, err)
		os.Exit(1)
	}

	commands := getAllCommands()
	installed := 0
	skipped := 0

	for _, cmd := range commands {
		symlinkPath := filepath.Join(targetDir, cmd)

		link, err := os.Readlink(symlinkPath)
		if err == nil && link == executable {
			fmt.Printf("  %s: already installed (points to readonlybox)\n", cmd)
			skipped++
			continue
		}

		os.Remove(symlinkPath)

		err = os.Symlink(executable, symlinkPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "readonlybox: failed to create symlink for %s: %v\n", cmd, err)
			continue
		}

		fmt.Printf("  %s -> readonlybox\n", cmd)
		installed++
	}

	fmt.Printf("\nInstalled %d symlinks to %s (%d skipped)\n", installed, targetDir, skipped)
}

func loadAccessControlEngine() (*access.AccessControlEngine, error) {
	configPath, err := config.FindConfigFile()
	if err != nil {
		return nil, nil
	}

	configAST, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	engine := access.NewAccessControlEngine(*configAST)

	return engine, nil
}

func handleConfigureAccess() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: readonlybox --configure-access <config-file>\n")
		os.Exit(1)
	}

	configPath := os.Args[2]

	configAST, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: Failed to load config: %v\n", err)
		os.Exit(1)
	}

	err = config.SaveConfig(configAST, ".readonlybox.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: Failed to save config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Access control configuration loaded from %s and saved to .readonlybox.yaml\n", configPath)
}

func handleShowAccess() {
	configPath, err := config.FindConfigFile()
	if err != nil {
		fmt.Printf("No access control configuration found. Using default read-only mode.\n")
		return
	}

	configAST, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: Failed to load current config: %v\n", err)
		return
	}

	fmt.Printf("Current Access Control Configuration:\n")
	fmt.Printf("  Version: %s\n", configAST.Version)
	fmt.Printf("  Base Directory: %s\n", configAST.BaseDir)
	fmt.Printf("  Commands: %d rules\n", len(configAST.Rules))

	if configAST.TempConfig != nil {
		fmt.Printf("  Temp Files:\n")
		fmt.Printf("    Pattern: %s\n", configAST.TempConfig.Pattern)
		fmt.Printf("    Max Size: %s\n", configAST.TempConfig.MaxSize)
		fmt.Printf("    Max Count: %d\n", configAST.TempConfig.MaxCount)
		fmt.Printf("    Auto Cleanup: %s\n", configAST.TempConfig.AutoCleanup)
	}
}

/* Server client for --run validation */

const (
	SocketPath          = "/tmp/readonlybox.sock"
	ROBO_MAGIC          = 0x524F424F
	ROBO_VERSION        = 4
	ROBO_MSG_REQ        = 1
	ROBO_DECISION_ALLOW = 2
	ROBO_DECISION_DENY  = 3
)

type serverClient struct {
	conn net.Conn
}

func newServerClient() (*serverClient, error) {
	conn, err := net.DialTimeout("unix", SocketPath, 2*time.Second)
	if err != nil {
		return nil, err
	}
	return &serverClient{conn: conn}, nil
}

func (c *serverClient) close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *serverClient) requestDecision(command string, args []string) (bool, string, error) {
	/* Build request packet */
	var buf bytes.Buffer

	/* Header: magic(4) + version(4) + clientUUID(16) + requestUUID(16) + serverUUID(16) + id(4) + argc(4) + envc(4) + checksum(4) = 72 bytes */
	/* Generate client UUID (static for this process) */
	clientUUID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	/* Generate request UUID (based on time) */
	now := time.Now().UnixNano()
	requestUUID := []byte{
		byte(now), byte(now >> 8), byte(now >> 16), byte(now >> 24),
		byte(now >> 32), byte(now >> 40), byte(now >> 48), byte(now >> 56),
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	}

	/* Write header (without checksum first) */
	binary.Write(&buf, binary.LittleEndian, uint32(ROBO_MAGIC))
	binary.Write(&buf, binary.LittleEndian, uint32(ROBO_VERSION))
	buf.Write(clientUUID)
	buf.Write(requestUUID)
	buf.Write(make([]byte, 16)) /* serverUUID (filled by server) */
	binary.Write(&buf, binary.LittleEndian, uint32(ROBO_MSG_REQ))
	binary.Write(&buf, binary.LittleEndian, uint32(len(args)))
	binary.Write(&buf, binary.LittleEndian, uint32(0)) /* envc */
	binary.Write(&buf, binary.LittleEndian, uint32(0)) /* checksum placeholder */

	/* Write command and args */
	buf.WriteString(command)
	buf.WriteByte(0)
	for _, arg := range args {
		buf.WriteString(arg)
		buf.WriteByte(0)
	}
	buf.WriteByte(0) /* end of args */

	/* Calculate checksum (CRC32 over entire packet excluding checksum field at offset 68) */
	packetBytes := buf.Bytes()
	checksum := calculateChecksum(packetBytes)

	/* Write checksum at offset 68 */
	binary.LittleEndian.PutUint32(packetBytes[68:], checksum)

	/* Send request */
	c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := c.conn.Write(packetBytes)
	if err != nil {
		return false, "", err
	}

	/* Read response */
	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	/* Read response header: magic(4) + serverID(16) + id(4) + decision(1) + reasonLen(4) */
	var magic uint32
	var serverID [16]byte
	var id uint32
	var decision uint8
	var reasonLen uint32

	/* Read first 4 bytes to check magic */
	headerBytes := make([]byte, 29)
	n, err := c.conn.Read(headerBytes)
	if err != nil {
		return false, "", fmt.Errorf("failed to read response header: %v", err)
	}
	if n < 4 {
		return false, "", fmt.Errorf("short read on magic: got %d bytes, first 4 bytes: %x", n, headerBytes[:min(n, 4)])
	}

	/* Parse header */
	magic = uint32(headerBytes[0]) | uint32(headerBytes[1])<<8 | uint32(headerBytes[2])<<16 | uint32(headerBytes[3])<<24
	if n > 4 {
		copy(serverID[:], headerBytes[4:20])
		id = uint32(headerBytes[20]) | uint32(headerBytes[21])<<8 | uint32(headerBytes[22])<<16 | uint32(headerBytes[23])<<24
		decision = headerBytes[24]
		reasonLen = uint32(headerBytes[25]) | uint32(headerBytes[26])<<8 | uint32(headerBytes[27])<<16 | uint32(headerBytes[28])<<24
	}

	if magic != ROBO_MAGIC {
		return false, "", fmt.Errorf("invalid response magic")
	}

	/* Read reason (includes null terminator) */
	reason := make([]byte, reasonLen)
	reasonRead, err := c.conn.Read(reason)
	if err != nil {
		return false, "", err
	}
	if reasonRead != int(reasonLen) {
		return false, "", fmt.Errorf("short read on reason: got %d, want %d", reasonRead, reasonLen)
	}

	/* Remove null terminator */
	if reasonRead > 0 && reason[reasonRead-1] == 0 {
		reason = reason[:reasonRead-1]
	}

	_ = id /* unused but kept for protocol compatibility */
	_ = serverID

	if decision == ROBO_DECISION_ALLOW {
		return true, string(reason), nil
	}
	return false, string(reason), nil
}

/* calculateChecksum - simple checksum over packet data */
func calculateChecksum(data []byte) uint32 {
	/* Simple sum of all bytes as a placeholder for CRC32 */
	var sum uint32
	for _, b := range data {
		sum += uint32(b)
	}
	return sum
}
