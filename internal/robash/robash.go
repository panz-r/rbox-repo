package robash

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// Dangerous commands that should be blocked
var dangerousCommands = map[string]bool{
	"rm": true, "mv": true, "cp": true, "dd": true, "chmod": true, "chown": true,
	"mkdir": true, "rmdir": true, "ln": true, "touch": true,
	"sed": true, "awk": true, "perl": true, "python": true,
	"wget": true, "curl": true, "scp": true, "rsync": true, "ssh": true, "git": true,
	"apt": true, "yum": true, "dnf": true, "pip": true, "npm": true, "yarn": true,
	"make": true, "gcc": true, "g++": true, "go": true, "javac": true, "docker": true,
	"systemctl": true, "service": true, "useradd": true, "userdel": true, "passwd": true,
	"su": true, "sudo": true, "kill": true, "pkill": true, "killall": true, "shutdown": true,
	"reboot": true, "halt": true, "poweroff": true, "crontab": true, "at": true,
	"chsh": true, "chfn": true, "visudo": true, "adduser": true, "deluser": true,
	"mount": true, "umount": true, "fdisk": true, "mkfs": true, "format": true,
	"parted": true, "iptables": true, "ufw": true, "firewall-cmd": true, "nc": true,
	"netcat": true, "nmap": true, "tcpdump": true, "wireshark": true, "tshark": true,
	"gdb": true, "strace": true, "ltrace": true, "valgrind": true, "ldd": true,
	"nm": true, "objdump": true, "readelf": true, "strings": true, "file": true,
	"tar": true, "zip": true, "unzip": true, "gzip": true, "gunzip": true,
	"bzip2": true, "bunzip2": true, "xz": true, "unxz": true, "rar": true,
	"unrar": true, "7z": true, "find": true, "xargs": true, "parallel": true,
	"timeout": true, "nohup": true, "screen": true, "tmux": true, "expect": true,
	"sendmail": true, "mail": true, "mutt": true, "postfix": true, "exim": true,
	"doveadm": true, "mysql": true, "mysqldump": true, "psql": true, "pg_dump": true,
	"mongo": true, "mongodump": true, "redis-cli": true, "sqlite3": true,
	"nginx": true, "apache2": true, "httpd": true, "lighttpd": true, "php": true,
	"node": true, "ruby": true, "lua": true, "bash": true, "sh": true, "dash": true,
	"zsh": true, "fish": true, "ksh": true, "csh": true, "tcsh": true,
	"vim": true, "vi": true, "nano": true, "emacs": true, "ed": true, "pico": true,
	"alias": true, "unalias": true, "export": true, "unset": true, "source": true,
	"eval": true, "exec": true, "trap": true, "ulimit": true, "umask": true,
	"wait": true, "sleep": true, "usleep": true, "nice": true, "renice": true,
	"ionice": true, "taskset": true, "cgroups": true, "systemd": true,
}

// Safe commands that are allowed
var safeCommands = map[string]bool{
	"ls": true, "cd": true, "pwd": true, "whoami": true, "id": true, "date": true,
	"cal": true, "uptime": true, "uname": true, "hostname": true, "arch": true,
	"echo": true, "printf": true, "cat": true, "head": true, "tail": true,
	"grep": true, "egrep": true, "fgrep": true, "zgrep": true, "less": true,
	"more": true, "most": true, "man": true, "info": true, "whatis": true,
	"whereis": true, "which": true, "type": true, "help": true, "compgen": true,
	"complete": true, "dir": true, "vdir": true, "stat": true, "readlink": true,
	"realpath": true, "basename": true, "dirname": true, "file": true, "test": true,
	"[": true, "[[": true, "true": true, "false": true, "yes": true, "no": true,
	"seq": true, "shuf": true, "sort": true, "uniq": true, "wc": true, "cut": true,
	"paste": true, "join": true, "comm": true, "diff": true, "cmp": true, "sum": true,
	"cksum": true, "md5sum": true, "sha1sum": true, "sha256sum": true, "sha512sum": true,
	"base64": true, "uuencode": true, "uudecode": true, "xxd": true, "od": true,
	"hexdump": true, "strings": true, "tr": true, "fold": true, "fmt": true,
	"pr": true, "nl": true, "tac": true, "rev": true, "expand": true, "unexpand": true,
	"column": true, "csplit": true, "split": true, "tee": true,
	"env": true, "printenv": true, "set": true, "unset": true, "readonly": true,
	"getopts": true, "shift": true, "exit": true, "return": true, "break": true,
	"continue": true, ":": true, ".": true, "source": true, "alias": true,
	"unalias": true, "bind": true, "caller": true, "command": true, "declare": true,
	"typeset": true, "local": true, "logout": true, "mapfile": true, "popd": true,
	"pushd": true, "dirs": true, "shopt": true, "suspend": true, "times": true,
	"trap": true, "ulimit": true, "umask": true, "wait": true, "sleep": true,
	"usleep": true,
}

// Dangerous patterns to detect
var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`>\s*[^\s]+`),           // Output redirection >
	regexp.MustCompile(`>>\s*[^\s]+`),          // Append redirection >>
	regexp.MustCompile(`\|\s*[^\s]+`),          // Pipe |
	regexp.MustCompile(`\$\s*\([^)]+\)`),       // Command substitution $(...)
	regexp.MustCompile("`[^`]+`"),               // Backtick command substitution
	regexp.MustCompile(`\$\s*\{[^}]+\}`),      // Variable expansion ${...}
	regexp.MustCompile(`\$\s*[A-Za-z_][A-Za-z0-9_]*`), // Simple variable $VAR
	regexp.MustCompile(`\s*;\s*`),               // Command chaining with ;
	regexp.MustCompile(`\s*&&\s*`),              // Command chaining with &&
	regexp.MustCompile(`\s*\|\|\s*`),           // Command chaining with ||
	regexp.MustCompile(`&\s*$`),                  // Background process &
	regexp.MustCompile(`\s*&\s*`),                // Background process &
	regexp.MustCompile(`\s*\\\s*$`),             // Line continuation \
	regexp.MustCompile(`\s*\\\n\s*`),           // Line continuation with newline
	regexp.MustCompile(`\s*\\\r\n\s*`),        // Line continuation with CRLF
}

// IsCommandAllowed checks if a command is allowed in read-only mode
func IsCommandAllowed(command string) bool {
	// Check if it's explicitly dangerous
	if dangerousCommands[command] {
		return false
	}

	// Check if it's explicitly safe
	if safeCommands[command] {
		return true
	}

	// If we don't know the command, be conservative and block it
	// This is the safest approach for a read-only wrapper
	return false
}

// ContainsDangerousPattern checks if script contains dangerous patterns
func ContainsDangerousPattern(script string) (bool, string) {
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(script) {
			return true, fmt.Sprintf("contains dangerous pattern: %s", pattern.String())
		}
	}
	return false, ""
}

// IsScriptSafe checks if a bash script is safe for read-only execution
func IsScriptSafe(script string) (bool, string) {
	// Check for dangerous patterns first
	if dangerous, reason := ContainsDangerousPattern(script); dangerous {
		return false, reason
	}

	// Parse script line by line
	scanner := bufio.NewScanner(strings.NewReader(script))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Extract command (first word)
		parts := strings.Fields(trimmed)
		if len(parts) == 0 {
			continue
		}

		command := parts[0]

		// Check if command is allowed
		if !IsCommandAllowed(command) {
			return false, fmt.Sprintf("line %d: command '%s' not allowed in read-only mode", lineNum, command)
		}
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Sprintf("error reading script: %v", err)
	}

	return true, ""
}

// IsScriptFileSafe checks if a bash script file is safe for read-only execution
func IsScriptFileSafe(filename string) (bool, string) {
	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return false, fmt.Sprintf("cannot open file: %v", err)
	}
	defer file.Close()

	// Read the file content
	content, err := io.ReadAll(file)
	if err != nil {
		return false, fmt.Sprintf("cannot read file: %v", err)
	}

	// Check if the script is safe
	return IsScriptSafe(string(content))
}

// IsCommandLineSafe checks if a command line is safe for read-only execution
func IsCommandLineSafe(args []string) (bool, string) {
	if len(args) == 0 {
		return false, "no command provided"
	}

	// Reconstruct the command line
	commandLine := strings.Join(args, " ")

	// Check for dangerous patterns
	if dangerous, reason := ContainsDangerousPattern(commandLine); dangerous {
		return false, reason
	}

	// Extract the command
	command := args[0]

	// Check if command is allowed
	if !IsCommandAllowed(command) {
		return false, fmt.Sprintf("command '%s' not allowed in read-only mode", command)
	}

	return true, ""
}

// IsInteractiveCommandSafe checks if an interactive bash command is safe
func IsInteractiveCommandSafe(command string) (bool, string) {
	// For interactive commands, we're more restrictive
	// Only allow very basic safe commands
	safeInteractiveCommands := map[string]bool{
		"ls": true, "cd": true, "pwd": true, "whoami": true, "date": true,
		"echo": true, "cat": true, "head": true, "tail": true, "grep": true,
		"less": true, "man": true, "help": true, "exit": true, "clear": true,
	}

	// Extract command (first word)
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return false, "no command provided"
	}

	cmd := parts[0]

	// Check if it's a safe interactive command
	if !safeInteractiveCommands[cmd] {
		return false, fmt.Sprintf("interactive command '%s' not allowed in read-only mode", cmd)
	}

	// Check for dangerous patterns in the full command
	if dangerous, reason := ContainsDangerousPattern(command); dangerous {
		return false, reason
	}

	return true, ""
}