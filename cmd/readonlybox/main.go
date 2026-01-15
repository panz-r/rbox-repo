package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
	}

	command := ""
	args := []string{}

	if len(os.Args) >= 2 {
		argv0 := filepath.Base(os.Args[0])
		if isSymlinkCommand(argv0) {
			command = argv0
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

func isSymlinkCommand(name string) bool {
	if name == "readonlybox" || name == "main" {
		return false
	}

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
