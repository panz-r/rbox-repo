package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/panz/openroutertest/internal/access"
	"github.com/panz/openroutertest/internal/config"
	"github.com/panz/openroutertest/internal/protocol"
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
		if os.Args[1] == "ptrace" {
			handlePtrace()
			return
		}
		if os.Args[1] == "--run" {
			handleRun()
			return
		}
		if os.Args[1] == "--judge" {
			handleJudge()
			return
		}
		/* Handle --caller with format "appname:syscall"
		 * Format: readonlybox --caller <appname:syscall> --cwd <path> --run <path> <args...>
		 * Args: [0]=readonlybox, [1]=--caller, [2]=<info>, [3]=--cwd, [4]=<cwd>, [5]=--run, [6]=<path>, [7...]=args
		 */
		if os.Args[1] == "--caller" && len(os.Args) > 6 && os.Args[3] == "--cwd" && os.Args[5] == "--run" {
			callerInfo := os.Args[2]
			/* Parse "appname:syscall" format */
			parts := strings.SplitN(callerInfo, ":", 2)
			if len(parts) >= 1 {
				os.Setenv("READONLYBOX_CALLER", parts[0])
			}
			if len(parts) >= 2 {
				os.Setenv("READONLYBOX_SYSCALL", parts[1])
			}
			/* Set Cwd from --cwd argument */
			os.Setenv("READONLYBOX_CWD", os.Args[4])
			/* Rewrite args to: readonlybox --run <path> <args...> */
			/* os.Args was: [readonlybox, --caller, <info>, --cwd, <cwd>, --run, <path>, arg1, arg2, ...] */
			/* We want:   [readonlybox, --run, <path>, arg1, arg2, ...] */
			newArgs := make([]string, 0, len(os.Args)-5)
			newArgs = append(newArgs, os.Args[0]) /* executable name */
			newArgs = append(newArgs, "--run")
			newArgs = append(newArgs, os.Args[6])     /* path */
			newArgs = append(newArgs, os.Args[7:]...) /* remaining args */
			os.Args = newArgs
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
		fmt.Fprintf(os.Stderr, "  ptrace <cmd>       Run command with ptrace-based interception\n")
		fmt.Fprintf(os.Stderr, "  install-links      Install symlinks for all commands\n")
		fmt.Fprintf(os.Stderr, "  --configure-access <config-file>  Configure access control\n")
		fmt.Fprintf(os.Stderr, "  --show-access                    Show current access configuration\n")
		fmt.Fprintf(os.Stderr, "  --run <path> <args...>           Run validated command (internal use)\n")
		fmt.Fprintf(os.Stderr, "  --judge <command> <args...>      Ask server for decision without executing\n")
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
		/* Strip duration suffixes from reason for consistent error message */
		switch reason {
		case "once", "15m", "1h", "4h", "session", "always", "pattern":
			reason = "unsafe command"
		}
		fmt.Fprintf(os.Stderr, "readonlybox: Permission denied, possibly unsafe command.\n")
		os.Exit(1)
	}

	/* Server allowed - execute the command */
	executeCommand(originalPath, argsForServer)
}

/* --judge handler: asks server for decision without executing the command
 * Usage: readonlybox --judge <command> [args...]
 * Output: ALLOW <reason> or DENY <reason> to stderr
 * Exit code: 0 for ALLOW, 9 for DENY, 1 for error
 */
func handleJudge() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "readonlybox: --judge requires at least the command argument\n")
		os.Exit(1)
	}

	command := os.Args[2]
	argsForServer := os.Args[3:]

	/* Ask server for decision */
	client, err := newServerClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: server not available\n")
		os.Exit(1)
	}
	defer client.close()

	allowed, reason, err := client.requestDecision(command, argsForServer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: server error: %v\n", err)
		os.Exit(1)
	}

	if allowed {
		fmt.Fprintf(os.Stderr, "ALLOW %s\n", reason)
		os.Exit(0)  // Success
	} else {
		fmt.Fprintf(os.Stderr, "DENY %s\n", reason)
		os.Exit(9)  // Denied
	}
}

/* handleRunLocal - fallback when server is unavailable */
func handleRunLocal(command, originalPath string, originalArgs []string) {
	/* Check if command is in readonlybox registry */
	cmd, exists := readonlybox.CommandRegistry[command]
	if !exists {
		fmt.Fprintf(os.Stderr, "readonlybox: Permission denied, possibly unsafe command.\n")
		os.Exit(1)
	}

	/* Validate arguments using the command's safety check */
	args := originalArgs[1:]

	/* Call the handler to validate and execute */
	if err := cmd.Handler(args); err != nil {
		fmt.Fprintf(os.Stderr, "readonlybox: Permission denied, possibly unsafe command.\n")
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

/* handlePtrace - run command with ptrace-based interception
 * Usage: readonlybox ptrace <command> [args...]
 */
func handlePtrace() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: readonlybox ptrace <command> [args...]\n")
		fmt.Fprintf(os.Stderr, "\nRun a command with ptrace-based command interception.\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  readonlybox ptrace bash\n")
		fmt.Fprintf(os.Stderr, "  readonlybox ptrace /bin/ls -la\n")
		os.Exit(1)
	}

	/* Find readonlybox-ptrace binary */
	ptracePath := "/usr/local/bin/readonlybox-ptrace"
	if _, err := os.Stat(ptracePath); os.IsNotExist(err) {
		/* Try to find in PATH */
		ptracePath = "readonlybox-ptrace"
	}

	/* Build arguments for readonlybox-ptrace */
	/* Skip "readonlybox ptrace" and pass the rest */
	ptraceArgs := os.Args[2:]

	/* Execute readonlybox-ptrace */
	cmd := exec.Command(ptracePath, ptraceArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "readonlybox ptrace: %v\n", err)
		os.Exit(1)
	}
}

/* Server client for --run validation */

type serverClient struct {
	conn *protocol.Client
}

func newServerClient() (*serverClient, error) {
	// Check for socket path in environment variable first
	socketPath := os.Getenv("READONLYBOX_SOCKET")
	if socketPath == "" {
		socketPath = protocol.DefaultSocketPath
	}
	conn, err := protocol.Dial(socketPath, 0)
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
	caller := os.Getenv("READONLYBOX_CALLER")
	syscall := os.Getenv("READONLYBOX_SYSCALL")
	cwd := os.Getenv("READONLYBOX_CWD")

	fullCommand := command
	if len(args) > 0 {
		fullCommand = command + " " + strings.Join(args, " ")
	}

	augmentedCmd := fullCommand
	if caller != "" && syscall != "" {
		augmentedCmd = fmt.Sprintf("[%s:%s] %s", caller, syscall, fullCommand)
	} else if caller != "" {
		augmentedCmd = fmt.Sprintf("[%s] %s", caller, fullCommand)
	}

	resp, err := c.conn.SendRequest(augmentedCmd, nil, cwd)
	if err != nil {
		return false, "", err
	}

	if resp.Decision == protocol.ROBO_DECISION_ALLOW {
		return true, resp.Reason, nil
	}
	return false, resp.Reason, nil
}
