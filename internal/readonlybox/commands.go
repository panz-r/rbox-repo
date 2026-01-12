package readonlybox

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/panz/openroutertest/internal/rogit"
	"github.com/panz/openroutertest/internal/rofind"
	"github.com/panz/openroutertest/internal/rols"
	"github.com/panz/openroutertest/internal/rocat"
	"github.com/panz/openroutertest/internal/rogrep"
	"github.com/panz/openroutertest/internal/rohead"
	"github.com/panz/openroutertest/internal/rotail"
	"github.com/panz/openroutertest/internal/rotimeout"
	"github.com/panz/openroutertest/internal/roecho"
	"github.com/panz/openroutertest/internal/rodate"
	"github.com/panz/openroutertest/internal/rocd"
	"github.com/panz/openroutertest/internal/robash"
	"github.com/panz/openroutertest/internal/rosort"
	"github.com/panz/openroutertest/internal/roulimit"
	"github.com/panz/openroutertest/internal/rosed"
	"github.com/panz/openroutertest/internal/rochmod"
	"github.com/panz/openroutertest/internal/rochown"
	"github.com/panz/openroutertest/internal/romkdir"
	"github.com/panz/openroutertest/internal/rormdir"
	"github.com/panz/openroutertest/internal/roln"
	"github.com/panz/openroutertest/internal/romv"
	"github.com/panz/openroutertest/internal/rocp"
	"github.com/panz/openroutertest/internal/roremove"
	"github.com/panz/openroutertest/internal/rotouch"
	"github.com/panz/openroutertest/internal/rodd"
	"github.com/panz/openroutertest/internal/rops"
	"github.com/panz/openroutertest/internal/rodf"
	"github.com/panz/openroutertest/internal/rodu"
	"github.com/panz/openroutertest/internal/rowc"
	"github.com/panz/openroutertest/internal/rouname"
	"github.com/panz/openroutertest/internal/rostat"
	"github.com/panz/openroutertest/internal/rofile"
	"github.com/panz/openroutertest/internal/rodiff"
	"github.com/panz/openroutertest/internal/rotr"
	"github.com/panz/openroutertest/internal/rocut"
	"github.com/panz/openroutertest/internal/rowhoami"
	"github.com/panz/openroutertest/internal/rohostname"
	"github.com/panz/openroutertest/internal/roprintenv"
	"github.com/panz/openroutertest/internal/rosleep"
	"github.com/panz/openroutertest/internal/roexpr"
	"github.com/panz/openroutertest/internal/roman"
	"github.com/panz/openroutertest/internal/access"
	"github.com/panz/openroutertest/internal/dsl"
	"strings"
)

// Command represents a read-only command wrapper
type Command struct {
	Name        string
	Description string
	Handler     func([]string) error
}

// Global access control engine
var AccessEngine *access.AccessControlEngine

// CommandRegistry maps command names to their handlers
var CommandRegistry = map[string]Command{
	"git": {
		Name:        "git",
		Description: "Read-only git operations",
		Handler:     handleGit,
	},
	"find": {
		Name:        "find",
		Description: "Read-only file searching",
		Handler:     handleFind,
	},
	"ls": {
		Name:        "ls",
		Description: "Read-only directory listing",
		Handler:     handleLs,
	},
	"cat": {
		Name:        "cat",
		Description: "Read-only file concatenation",
		Handler:     handleCat,
	},
	"grep": {
		Name:        "grep",
		Description: "Read-only pattern searching",
		Handler:     handleGrep,
	},
	"head": {
		Name:        "head",
		Description: "Read-only file head display",
		Handler:     handleHead,
	},
	"tail": {
		Name:        "tail",
		Description: "Read-only file tail display",
		Handler:     handleTail,
	},
	"timeout": {
		Name:        "timeout",
		Description: "Read-only command timeout",
		Handler:     handleTimeout,
	},
	"echo": {
		Name:        "echo",
		Description: "Read-only text echo",
		Handler:     handleEcho,
	},
	"date": {
		Name:        "date",
		Description: "Read-only date display",
		Handler:     handleDate,
	},
	"cd": {
		Name:        "cd",
		Description: "Read-only directory change",
		Handler:     handleCd,
	},
	"bash": {
		Name:        "bash",
		Description: "Read-only bash execution",
		Handler:     handleBash,
	},
	"sort": {
		Name:        "sort",
		Description: "Read-only sorting",
		Handler:     handleSort,
	},
	"ulimit": {
		Name:        "ulimit",
		Description: "Read-only resource limits",
		Handler:     handleUlimit,
	},
	"sed": {
		Name:        "sed",
		Description: "Read-only stream editing",
		Handler:     handleSed,
	},
	"chmod": {
		Name:        "chmod",
		Description: "Read-only file mode checking",
		Handler:     handleChmod,
	},
	"chown": {
		Name:        "chown",
		Description: "Read-only file ownership checking",
		Handler:     handleChown,
	},
	"mkdir": {
		Name:        "mkdir",
		Description: "Read-only directory creation checking",
		Handler:     handleMkdir,
	},
	"rmdir": {
		Name:        "rmdir",
		Description: "Read-only directory removal checking",
		Handler:     handleRmdir,
	},
	"ln": {
		Name:        "ln",
		Description: "Read-only link operations",
		Handler:     handleLn,
	},
	"mv": {
		Name:        "mv",
		Description: "Read-only file moving",
		Handler:     handleMv,
	},
	"cp": {
		Name:        "cp",
		Description: "Read-only file copying",
		Handler:     handleCp,
	},
	"rm": {
		Name:        "rm",
		Description: "Read-only file removal checking",
		Handler:     handleRm,
	},
	"touch": {
		Name:        "touch",
		Description: "Read-only file timestamp checking",
		Handler:     handleTouch,
	},
	"dd": {
		Name:        "dd",
		Description: "Read-only data duplication",
		Handler:     handleDd,
	},
	"ps": {
		Name:        "ps",
		Description: "Read-only process status",
		Handler:     handlePs,
	},
	"df": {
		Name:        "df",
		Description: "Read-only disk space usage",
		Handler:     handleDf,
	},
	"du": {
		Name:        "du",
		Description: "Read-only disk usage",
		Handler:     handleDu,
	},
	"wc": {
		Name:        "wc",
		Description: "Read-only word count",
		Handler:     handleWc,
	},
	"uname": {
		Name:        "uname",
		Description: "Read-only system information",
		Handler:     handleUname,
	},
	"stat": {
		Name:        "stat",
		Description: "Read-only file information",
		Handler:     handleStat,
	},
	"file": {
		Name:        "file",
		Description: "Read-only file type detection",
		Handler:     handleFile,
	},
	"which": {
		Name:        "which",
		Description: "Read-only command location",
		Handler:     handleWhich,
	},
	"free": {
		Name:        "free",
		Description: "Read-only memory usage",
		Handler:     handleFree,
	},
	"tar": {
		Name:        "tar",
		Description: "Read-only archive inspection",
		Handler:     handleTar,
	},
	"pwd": {
		Name:        "pwd",
		Description: "Read-only print working directory",
		Handler:     handlePwd,
	},
	"diff": {
		Name:        "diff",
		Description: "Read-only file comparison",
		Handler:     handleDiff,
	},
	"tr": {
		Name:        "tr",
		Description: "Read-only character translation",
		Handler:     handleTr,
	},
	"cut": {
		Name:        "cut",
		Description: "Read-only cut sections from lines",
		Handler:     handleCut,
	},
	"whoami": {
		Name:        "whoami",
		Description: "Read-only current user",
		Handler:     handleWhoami,
	},
	"hostname": {
		Name:        "hostname",
		Description: "Read-only system hostname",
		Handler:     handleHostname,
	},
	"printenv": {
		Name:        "printenv",
		Description: "Read-only print environment",
		Handler:     handlePrintenv,
	},
	"sleep": {
		Name:        "sleep",
		Description: "Read-only delay execution",
		Handler:     handleSleep,
	},
	"expr": {
		Name:        "expr",
		Description: "Read-only evaluate expressions",
		Handler:     handleExpr,
	},
	"man": {
		Name:        "man",
		Description: "Read-only manual pages",
		Handler:     handleMan,
	},
}

// ListCommands prints all available commands
func ListCommands() {
	fmt.Println("Available read-only commands:")
	for _, cmd := range CommandRegistry {
		fmt.Printf("  %-12s - %s\n", cmd.Name, cmd.Description)
	}
}

// ExecuteCommand executes the specified command with arguments
func ExecuteCommand(command string, args []string) error {
	cmd, exists := CommandRegistry[command]
	if !exists {
		return fmt.Errorf("unknown command: %s", command)
	}

	return cmd.Handler(args)
}

// SetAccessEngine sets the global access control engine
func SetAccessEngine(engine *access.AccessControlEngine) {
	AccessEngine = engine
}

// GetAccessEngine returns the global access control engine
func GetAccessEngine() *access.AccessControlEngine {
	return AccessEngine
}

// CheckFileAccess checks if a command can access a file with the given operation
func CheckFileAccess(cmd string, path string, opType dsl.OperationType) (bool, error) {
	if AccessEngine == nil {
		// No access control engine, allow all read operations
		if opType == dsl.OpRead {
			return true, nil
		}
		return false, fmt.Errorf("write operations not allowed without access control")
	}

	return AccessEngine.CanAccess(cmd, path, opType)
}

// CheckCommandAccess checks if a command can access all required files with the given operation type
func CheckCommandAccess(cmd string, filePaths []string, opType dsl.OperationType) error {
	if AccessEngine == nil {
		// No access control engine, allow all read operations
		if opType == dsl.OpRead {
			return nil
		}
		return fmt.Errorf("write operations not allowed without access control")
	}

	for _, path := range filePaths {
		allowed, err := AccessEngine.CanAccess(cmd, path, opType)
		if err != nil {
			return fmt.Errorf("access control error for %s: %v", path, err)
		}
		if !allowed {
			return fmt.Errorf("access denied: %s cannot %s %s", cmd, opType, path)
		}
	}

	return nil
}

// Command handlers

func handleGit(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("git: no subcommand provided")
	}
	gitCommand := args[0]
	gitArgs := args[1:]

	if allowed, reason := rogit.IsAllowedCommand(gitCommand, gitArgs); !allowed {
		return fmt.Errorf("git %s: %s", gitCommand, reason)
	}

	return runCommand("git", append([]string{gitCommand}, gitArgs...)...)
}

func handleFind(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("find: no path provided")
	}

	if safe, reason := rofind.AreFindArgsSafe(args); !safe {
		return fmt.Errorf("find: %s", reason)
	}

	return runCommand("find", args...)
}

func handleLs(args []string) error {
	// Parse command to extract directory paths
	dirs, err := rols.ParseLsDirectories(args)
	if err != nil {
		return fmt.Errorf("ls: %v", err)
	}

	// Check access control for all directories
	if err := CheckCommandAccess("ls", dirs, dsl.OpRead); err != nil {
		return err
	}

	// Also check original safety validation
	if safe, reason := rols.AreLsArgsSafe(args); !safe {
		return fmt.Errorf("ls: %s", reason)
	}

	return runCommand("ls", args...)
}

func handleCat(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("cat: no file provided")
	}

	// Parse command to extract file paths
	files, err := rocat.ParseCatFiles(args)
	if err != nil {
		return fmt.Errorf("cat: %v", err)
	}

	// Check access control for all files
	if err := CheckCommandAccess("cat", files, dsl.OpRead); err != nil {
		return err
	}

	// Also check original safety validation
	if safe, reason := rocat.AreCatArgsSafe(args); !safe {
		return fmt.Errorf("cat: %s", reason)
	}

	return runCommand("cat", args...)
}

func handleGrep(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("grep: no pattern provided")
	}

	if safe, reason := rogrep.AreGrepArgsSafe(args); !safe {
		return fmt.Errorf("grep: %s", reason)
	}

	return runCommand("grep", args...)
}

func handleHead(args []string) error {
	if safe, reason := rohead.AreHeadArgsSafe(args); !safe {
		return fmt.Errorf("head: %s", reason)
	}

	return runCommand("head", args...)
}

func handleTail(args []string) error {
	if safe, reason := rotail.AreTailArgsSafe(args); !safe {
		return fmt.Errorf("tail: %s", reason)
	}

	return runCommand("tail", args...)
}

func handleTimeout(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("timeout: requires duration and command")
	}

	if safe, reason := rotimeout.AreTimeoutArgsSafe(args); !safe {
		return fmt.Errorf("timeout: %s", reason)
	}

	return runCommand("timeout", args...)
}

func handleEcho(args []string) error {
	if safe, reason := roecho.AreEchoArgsSafe(args); !safe {
		return fmt.Errorf("echo: %s", reason)
	}

	return runCommand("echo", args...)
}

func handleDate(args []string) error {
	if safe, reason := rodate.AreDateArgsSafe(args); !safe {
		return fmt.Errorf("date: %s", reason)
	}

	return runCommand("date", args...)
}

func handleCd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("cd: no directory provided")
	}

	if safe, reason := rocd.AreCdArgsSafe(args); !safe {
		return fmt.Errorf("cd: %s", reason)
	}

	return runCommand("cd", args...)
}

func handleBash(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("bash: no command provided")
	}

	if safe, reason := robash.IsCommandLineSafe(args); !safe {
		return fmt.Errorf("bash: %s", reason)
	}

	return runCommand("bash", args...)
}

func handleSort(args []string) error {
	if safe, reason := rosort.AreSortArgsSafe(args); !safe {
		return fmt.Errorf("sort: %s", reason)
	}

	return runCommand("sort", args...)
}

func handleUlimit(args []string) error {
	if safe, reason := roulimit.IsUlimitSafe(args); !safe {
		return fmt.Errorf("ulimit: %s", reason)
	}

	return runCommand("ulimit", args...)
}

func handleSed(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("sed: no script provided")
	}

	if safe, reason := rosed.IsSedSafe(args); !safe {
		return fmt.Errorf("sed: %s", reason)
	}

	return runCommand("sed", args...)
}

func handleChmod(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("chmod: requires mode and file")
	}

	if safe, reason := rochmod.IsChmodSafe(args); !safe {
		return fmt.Errorf("chmod: %s", reason)
	}

	return runCommand("chmod", args...)
}

func handleChown(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("chown: requires owner and file")
	}

	if safe, reason := rochown.IsChownSafe(args); !safe {
		return fmt.Errorf("chown: %s", reason)
	}

	return runCommand("chown", args...)
}

func handleMkdir(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("mkdir: no directory provided")
	}

	if safe, reason := romkdir.IsMkdirSafe(args); !safe {
		return fmt.Errorf("mkdir: %s", reason)
	}

	return runCommand("mkdir", args...)
}

func handleRmdir(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("rmdir: no directory provided")
	}

	if safe, reason := rormdir.IsRmdirSafe(args); !safe {
		return fmt.Errorf("rmdir: %s", reason)
	}

	return runCommand("rmdir", args...)
}

func handleLn(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("ln: requires target and link name")
	}

	if safe, reason := roln.IsLnSafe(args); !safe {
		return fmt.Errorf("ln: %s", reason)
	}

	return runCommand("ln", args...)
}

func handleMv(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("mv: requires source and destination")
	}

	if safe, reason := romv.IsMoveSafe(args); !safe {
		return fmt.Errorf("mv: %s", reason)
	}

	return runCommand("mv", args...)
}

func handleCp(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("cp: requires source and destination")
	}

	if safe, reason := rocp.IsCopySafe(args); !safe {
		return fmt.Errorf("cp: %s", reason)
	}

	return runCommand("cp", args...)
}

func handleRm(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("rm: no file provided")
	}

	if safe, reason := roremove.IsRemoveSafe(args); !safe {
		return fmt.Errorf("rm: %s", reason)
	}

	return runCommand("rm", args...)
}

func handleTouch(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("touch: no file provided")
	}

	if safe, reason := rotouch.IsTouchSafe(args); !safe {
		return fmt.Errorf("touch: %s", reason)
	}

	return runCommand("touch", args...)
}

func handleDd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("dd: no operands provided")
	}

	if safe, reason := rodd.IsDdSafe(args); !safe {
		return fmt.Errorf("dd: %s", reason)
	}

	return runCommand("dd", args...)
}

func handlePs(args []string) error {
	if safe, reason := rops.ArePsArgsSafe(args); !safe {
		return fmt.Errorf("ps: %s", reason)
	}

	return runCommand("ps", args...)
}

func handleDf(args []string) error {
	if safe, reason := rodf.AreDfArgsSafe(args); !safe {
		return fmt.Errorf("df: %s", reason)
	}

	return runCommand("df", args...)
}

func handleDu(args []string) error {
	if safe, reason := rodu.AreDuArgsSafe(args); !safe {
		return fmt.Errorf("du: %s", reason)
	}

	return runCommand("du", args...)
}

func handleWc(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("wc: no file provided")
	}

	if safe, reason := rowc.AreWcArgsSafe(args); !safe {
		return fmt.Errorf("wc: %s", reason)
	}

	return runCommand("wc", args...)
}

func handleUname(args []string) error {
	if safe, reason := rouname.AreUnameArgsSafe(args); !safe {
		return fmt.Errorf("uname: %s", reason)
	}

	return runCommand("uname", args...)
}

// New command handlers

func handlePwd(args []string) error {
	// pwd is generally safe, but let's add basic validation
	for _, arg := range args {
		if strings.Contains(arg, "`") || strings.Contains(arg, "$") {
			return fmt.Errorf("pwd: contains potential command injection characters")
		}
		if len(arg) >= 50 {
			return fmt.Errorf("pwd: suspiciously long option")
		}
	}

	return runCommand("pwd", args...)
}

func handleDiff(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("diff: at least two files required")
	}

	if safe, reason := rodiff.AreDiffArgsSafe(args); !safe {
		return fmt.Errorf("diff: %s", reason)
	}

	return runCommand("diff", args...)
}

func handleTr(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("tr: at least one argument required")
	}

	if safe, reason := rotr.AreTrArgsSafe(args); !safe {
		return fmt.Errorf("tr: %s", reason)
	}

	return runCommand("tr", args...)
}

func handleCut(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("cut: at least list and file arguments required")
	}

	if safe, reason := rocut.AreCutArgsSafe(args); !safe {
		return fmt.Errorf("cut: %s", reason)
	}

	return runCommand("cut", args...)
}

func handleStat(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("stat: no file provided")
	}

	if safe, reason := rostat.AreStatArgsSafe(args); !safe {
		return fmt.Errorf("stat: %s", reason)
	}

	return runCommand("stat", args...)
}

func handleWhoami(args []string) error {
	if safe, reason := rowhoami.AreWhoamiArgsSafe(args); !safe {
		return fmt.Errorf("whoami: %s", reason)
	}

	return runCommand("whoami", args...)
}

func handleHostname(args []string) error {
	if safe, reason := rohostname.AreHostnameArgsSafe(args); !safe {
		return fmt.Errorf("hostname: %s", reason)
	}

	return runCommand("hostname", args...)
}

func handlePrintenv(args []string) error {
	if safe, reason := roprintenv.ArePrintenvArgsSafe(args); !safe {
		return fmt.Errorf("printenv: %s", reason)
	}

	return runCommand("printenv", args...)
}

func handleSleep(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("sleep: no duration provided")
	}

	if safe, reason := rosleep.AreSleepArgsSafe(args); !safe {
		return fmt.Errorf("sleep: %s", reason)
	}

	return runCommand("sleep", args...)
}

func handleExpr(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("expr: no expression provided")
	}

	if safe, reason := roexpr.AreExprArgsSafe(args); !safe {
		return fmt.Errorf("expr: %s", reason)
	}

	return runCommand("expr", args...)
}

func handleMan(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("man: no manual page specified")
	}

	if safe, reason := roman.AreManArgsSafe(args); !safe {
		return fmt.Errorf("man: %s", reason)
	}

	return runCommand("man", args...)
}

func handleFile(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("file: no file provided")
	}

	if safe, reason := rofile.AreFileArgsSafe(args); !safe {
		return fmt.Errorf("file: %s", reason)
	}

	return runCommand("file", args...)
}

func handleWhich(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("which: no command provided")
	}

	// which is generally safe, but let's add basic validation
	for _, arg := range args {
		if strings.Contains(arg, "`") || strings.Contains(arg, "$") {
			return fmt.Errorf("which: contains potential command injection characters")
		}
		if len(arg) >= 50 {
			return fmt.Errorf("which: suspiciously long option")
		}
	}

	return runCommand("which", args...)
}

func handleFree(args []string) error {
	// free is generally safe - mostly informational options
	for _, arg := range args {
		if strings.Contains(arg, "`") || strings.Contains(arg, "$") {
			return fmt.Errorf("free: contains potential command injection characters")
		}
		if len(arg) >= 50 {
			return fmt.Errorf("free: suspiciously long option")
		}
	}

	return runCommand("free", args...)
}

func handleTar(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("tar: no arguments provided")
	}

	// Block dangerous tar operations (extract to filesystem)
	for i, arg := range args {
		if arg == "-x" || arg == "--extract" || arg == "-c" || arg == "--create" {
			// Check if next arg is not a dangerous operation
			if i+1 < len(args) {
				nextArg := args[i+1]
				// Allow extract to stdout but block extract to filesystem
				if (arg == "-x" || arg == "--extract") && !strings.HasPrefix(nextArg, "-") {
					return fmt.Errorf("tar: extract to filesystem not allowed in read-only mode")
				}
			}
		}
	}

	// General security checks
	for _, arg := range args {
		if strings.Contains(arg, "`") || strings.Contains(arg, "$") {
			return fmt.Errorf("tar: contains potential command injection characters")
		}
		if len(arg) >= 50 {
			return fmt.Errorf("tar: suspiciously long option")
		}
	}

	return runCommand("tar", args...)
}

// runCommand executes the actual system command
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("failed to execute %s: %v", name, err)
	}
	return nil
}