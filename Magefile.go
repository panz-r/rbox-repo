//go:build mage
// +build mage

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
)

// Constants for paths used throughout the build
const (
	binDir          = "bin"
	clientDir       = "rbox-preload"
	cDfaDir         = "c-dfa"
	cDfaToolsDir    = cDfaDir + "/build/tools"
	cDfaSrcDir      = cDfaDir + "/src"
	cDfaIncludeDir  = cDfaDir + "/include"
	draugrDir       = "draugr"
	shellsplitDir   = "shellsplit"
	rboxProtocolDir = "rbox-protocol"
	rboxWrapDir     = "rbox-wrap"
	rboxPtraceDir   = "rbox-ptrace"
	rboxServerDir   = "rbox-server"
	rboxRulesetDir  = "rbox-ruleset"
	shelltypeDir    = "shelltype"
	shellgateDir    = "shellgate"

	socketDir  = "/run/readonlybox"
	socketPath = socketDir + "/readonlybox.sock"

	// Version string
	VersionStr = "readonlybox build system 1.0.0"
)

// Default target
var Default = Build

// Desc returns description for mage -l output
func Desc(target string) string {
	descriptions := map[string]string{
		"Build":             "Build all binaries (default)",
		"BuildBinaries":     "Build main binaries (rbox-wrap, rbox-server, rbox-ptrace)",
		"BuildDFA":          "Build DFA data for client library",
		"BuildDependencies": "Build base C libraries and tools",
		"Clean":             "Remove all build artifacts",
		"Test":              "Run all tests",
		"ValidatePatterns":  "Validate command pattern files (needs c-dfa tools)",
		"Deps":              "Build DFA tools (cdfatool) first",
		"Install":           "Install binaries to system (requires root)",
		"ServerCapture":     "Build rbox-server with capture mode enabled (-tags capture)",
	}
	return descriptions[target]
}

// Help returns help text for mage
func Help() string {
	return `Magefile for readonlybox:

Build:
  mage build      - Build all binaries (default)
  mage build:deps - Build DFA tools only
  mage build:dfa  - Build DFA data for client library

Test:
  mage test       - Run all tests

Clean:
  mage clean      - Remove all build artifacts

Install:
  mage install    - Install binaries to /usr/local (requires root)

Dependencies:
  mage deps       - Build DFA tools (cdfatool)

Validation:
  mage validate   - Validate command pattern files
`
}

// Version returns version string
func Version() string {
	return VersionStr
}

// BuildDependencies builds base C libraries
func BuildDependencies() error {
	wd, _ := os.Getwd()
	oldCGO := os.Getenv("CGO_ENABLED")
	os.Setenv("CGO_ENABLED", "1")
	defer os.Setenv("CGO_ENABLED", oldCGO)
	os.MkdirAll(binDir, 0755)

	// Build draugr submodule first — shellgate, rbox-protocol, rbox-ruleset,
	// and c-dfa all link against the pre-built static library in draugr/build/
	if err := buildCMake(filepath.Join(wd, draugrDir)); err != nil {
		return fmt.Errorf("draugr build failed: %w", err)
	}

	// Build c-dfa (produces tools needed for pattern validation)
	if err := runCMake(filepath.Join(wd, cDfaDir), true); err != nil {
		return fmt.Errorf("c-dfa build failed: %w", err)
	}

	// Now validate patterns (needs cdfatool from c-dfa)
	if err := ValidatePatterns(); err != nil {
		return fmt.Errorf("pattern validation failed: %w", err)
	}

	if err := runMake(filepath.Join(wd, shellsplitDir), true); err != nil {
		return fmt.Errorf("shellsplit build failed: %w", err)
	}
	if err := runMake(filepath.Join(wd, shelltypeDir), true); err != nil {
		return fmt.Errorf("shelltype build failed: %w", err)
	}
	if err := buildCMake(filepath.Join(wd, shellgateDir)); err != nil {
		return fmt.Errorf("shellgate build failed: %w", err)
	}
	if err := buildCMake(filepath.Join(wd, rboxProtocolDir)); err != nil {
		return fmt.Errorf("rbox-protocol build failed: %w", err)
	}

	// Build rbox-ruleset (landlock policy builder library)
	if err := buildCMake(filepath.Join(wd, rboxRulesetDir)); err != nil {
		return fmt.Errorf("rbox-ruleset build failed: %w", err)
	}

	// Create lib directory for librbox_protocol.so (dev build)
	libDir := filepath.Join(wd, "lib")
	if err := os.MkdirAll(libDir, 0755); err != nil {
		return fmt.Errorf("creating lib dir failed: %w", err)
	}
	// Create symlinks in ./lib for rbox-wrap dependency
	// Point to the library in rbox-protocol/build/
	protoLibActual := filepath.Join(wd, rboxProtocolDir, "build", "librbox_protocol.so.1.0.0")
	protoSo1 := filepath.Join(wd, "lib", "librbox_protocol.so.1")
	protoSo := filepath.Join(wd, "lib", "librbox_protocol.so")

	// Remove existing symlinks
	os.Remove(protoSo1)
	os.Remove(protoSo)

	// Create .so.1 symlink directly to actual file
	if err := os.Symlink(protoLibActual, protoSo1); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create lib/librbox_protocol.so.1 symlink: %w", err)
	}
	// Create .so symlink to .so.1
	if err := os.Symlink("librbox_protocol.so.1", protoSo); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create lib/librbox_protocol.so symlink: %w", err)
	}

	return nil
}

// Deps builds DFA tools explicitly before other operations
func Deps() error {
	fmt.Println("=== Building DFA tools ===")
	wd, _ := os.Getwd()

	// Build c-dfa using CMake which produces cdfatool
	if err := runCMake(filepath.Join(wd, cDfaDir), true); err != nil {
		return fmt.Errorf("c-dfa build failed: %w", err)
	}

	// Verify tools exist
	tools := []string{
		filepath.Join(wd, cDfaToolsDir, "cdfatool"),
	}
	for _, tool := range tools {
		if _, err := os.Stat(tool); os.IsNotExist(err) {
			return fmt.Errorf("DFA tool not found: %s (build may have failed)", tool)
		}
	}

	fmt.Println("DFA tools built successfully")
	return nil
}

// BuildDFA builds the DFA data for the client library
// needsRebuild returns true if any input is newer than the output
func needsRebuild(output string, inputs ...string) bool {
	outStat, err := os.Stat(output)
	if err != nil {
		return true // output doesn't exist
	}
	for _, input := range inputs {
		inStat, err := os.Stat(input)
		if err != nil {
			fmt.Printf("Warning: input %s missing, rebuilding\n", input)
			return true // input missing, rebuild to get proper error
		}
		if inStat.ModTime().After(outStat.ModTime()) {
			return true
		}
	}
	return false
}

// validateDFATools checks that required DFA tools exist before building DFA
func validateDFATools(wd string) error {
	tools := []struct {
		path string
		name string
	}{
		{filepath.Join(wd, cDfaToolsDir, "cdfatool"), "cdfatool"},
	}

	var missing []string
	for _, tool := range tools {
		info, err := os.Stat(tool.path)
		if err != nil {
			missing = append(missing, tool.name)
			continue
		}
		if info.Mode()&0111 == 0 {
			missing = append(missing, tool.name+" (not executable)")
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing DFA tools: %s\n  Run 'mage deps' to build them", strings.Join(missing, ", "))
	}
	return nil
}

// Depends on BuildDependencies which creates the nfa tools
func BuildDFA() error {
	wd, _ := os.Getwd()

	// Validate tools exist before attempting DFA build
	if err := validateDFATools(wd); err != nil {
		return err
	}

	mg.Deps(BuildDependencies)

	os.Setenv("CGO_ENABLED", "1")

	cc := os.Getenv("CC")
	if cc == "" {
		cc = "gcc"
	}

	cdfatool := filepath.Join(wd, cDfaToolsDir, "cdfatool")
	clientDirPath := filepath.Join(wd, clientDir)

	patternFile := filepath.Join(clientDirPath, "rbox_client_safe_commands.txt")
	dfaFile := filepath.Join(clientDirPath, "readonlybox.dfa")
	cArrayFile := filepath.Join(clientDirPath, "readonlybox_dfa.c")
	staticDataFile := filepath.Join(clientDirPath, "dfa_static_data.c")
	outputFile := filepath.Join(wd, binDir, "libreadonlybox_client.so")

	// Step 1: Pattern → DFA (direct, no NFA intermediate)
	if needsRebuild(dfaFile, patternFile) {
		fmt.Println("=== Pattern file changed, regenerating DFA ===")
		cmd := exec.Command(cdfatool, "compile", patternFile, "-o", dfaFile)
		cmd.Dir = clientDirPath
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("cdfatool compile failed: %w", err)
		}
	}

	// Step 2: DFA → C array
	if needsRebuild(cArrayFile, dfaFile) {
		cmd := exec.Command(cdfatool, "embedd", dfaFile, "-o", cArrayFile)
		cmd.Dir = clientDirPath
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("cdfatool embedd failed: %w", err)
		}
	}

	// Step 4: Copy to dfa_static_data.c
	if needsRebuild(staticDataFile, cArrayFile) {
		if err := copyFile(cArrayFile, staticDataFile); err != nil {
			return fmt.Errorf("copying dfa data failed: %w", err)
		}
	}

	// Step 5: Compile shared library
	if needsRebuild(outputFile, staticDataFile,
		filepath.Join(clientDirPath, "client.c"),
		filepath.Join(clientDirPath, "dfa.c"),
		filepath.Join(wd, cDfaDir, "lib_eval/dfa_eval.c"),
		filepath.Join(wd, shellsplitDir, "src/shell_tokenizer.c"),
		filepath.Join(wd, shellsplitDir, "src/shell_tokenizer_full.c")) {

		fmt.Println("=== Building libreadonlybox_client.so ===")
		cmd := exec.Command(cc, "-shared", "-fPIC", "-O2", "-DFA_EVAL_DEBUG=0", "-o", outputFile,
			filepath.Join(clientDirPath, "client.c"),
			filepath.Join(clientDirPath, "dfa.c"),
			staticDataFile,
			filepath.Join(wd, cDfaDir, "lib_eval/dfa_eval.c"),
			filepath.Join(wd, shellsplitDir, "src/shell_tokenizer.c"),
			filepath.Join(wd, shellsplitDir, "src/shell_tokenizer_full.c"),
			"-I"+filepath.Join(wd, cDfaIncludeDir),
			"-I"+filepath.Join(wd, shellsplitDir, "include"),
			"-lpthread", "-ldl")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("compiling libreadonlybox_client.so failed: %w", err)
		}
	}

	return nil
}

// forceRebuildIfNewer removes target if dependency is newer
func forceRebuildIfNewer(target, dependency string) {
	if depStat, err := os.Stat(dependency); err == nil {
		if targetStat, err := os.Stat(target); err == nil {
			if depStat.ModTime().After(targetStat.ModTime()) {
				os.RemoveAll(target)
			}
		}
	}
}

// BuildBinaries builds the main binaries
func BuildBinaries() error {
	mg.Deps(BuildDFA)

	wd, _ := os.Getwd()
	os.Setenv("CGO_ENABLED", "1")

	cc := os.Getenv("CC")
	if cc == "" {
		cc = "gcc"
	}

	// Ensure c-dfa tools are fully built before rbox-wrap (which needs cdfatool)
	// Build c-dfa tools using CMake
	if err := runCMakeTools(filepath.Join(wd, cDfaDir)); err != nil {
		return fmt.Errorf("c-dfa tools build failed: %w", err)
	}

	// Force rebuild checks
	dfaC := filepath.Join(wd, clientDir, "readonlybox_dfa.c")
	dfaSo := filepath.Join(wd, binDir, "libreadonlybox_client.so")
	forceRebuildIfNewer(dfaSo, dfaC)

	for _, bin := range []string{"readonlybox-ptrace"} {
		binPath := filepath.Join(wd, binDir, bin)
		forceRebuildIfNewer(binPath, dfaSo)
		forceRebuildIfNewer(binPath, filepath.Join(wd, rboxRulesetDir, "build", "lib", "liblandlock-builder.a"))
		forceRebuildIfNewer(binPath, filepath.Join(wd, cDfaDir, "libdfa_eval.a"))
	}

	protoLib := filepath.Join(wd, rboxProtocolDir, "librbox_protocol.so")
	serverBin := filepath.Join(wd, binDir, "readonlybox-server")
	forceRebuildIfNewer(serverBin, protoLib)

	// rbox-wrap
	if err := runMakeWithCC(filepath.Join(wd, rboxWrapDir), cc); err != nil {
		return fmt.Errorf("rbox-wrap build failed: %w", err)
	}
	// Copy rbox-wrap to bin directory
	if err := copyFile(filepath.Join(wd, rboxWrapDir, "rbox-wrap"),
		filepath.Join(wd, binDir, "rbox-wrap")); err != nil {
		return fmt.Errorf("copying rbox-wrap failed: %w", err)
	}

	// Fix rbox-wrap library path with patchelf:
	// - Replace NEEDED path with just library name
	// - Set RUNPATH to $ORIGIN/../lib
	rboxWrapBin := filepath.Join(wd, binDir, "rbox-wrap")
	var cmd *exec.Cmd
	if _, err := os.Stat(rboxWrapBin); err == nil {
		// Replace NEEDED entry: ../rbox-protocol/librbox_protocol.so -> librbox_protocol.so
		cmd = exec.Command("patchelf", "--replace-needed", "../rbox-protocol/librbox_protocol.so", "librbox_protocol.so", rboxWrapBin)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("patchelf replace-needed failed: %w", err)
		}
		// Set RUNPATH to $ORIGIN/../lib
		cmd = exec.Command("patchelf", "--set-rpath", "$ORIGIN/../lib", rboxWrapBin)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("patchelf set-rpath failed: %w", err)
		}
	}

	// Create lib directory for librbox_protocol.so (dev build)
	libDir := filepath.Join(wd, "lib")
	if err := os.MkdirAll(libDir, 0755); err != nil {
		return fmt.Errorf("creating lib dir failed: %w", err)
	}
	// Copy librbox_protocol.so to lib directory for dev builds
	if err := copyFile(filepath.Join(wd, rboxProtocolDir, "librbox_protocol.so"),
		filepath.Join(wd, "lib", "librbox_protocol.so")); err != nil {
		return fmt.Errorf("copying librbox_protocol.so failed: %w", err)
	}

	// rbox-server (Go with C library)
	fmt.Println("=== Building readonlybox-server ===")
	rboxProto := filepath.Join(wd, rboxProtocolDir)
	shellSplit := filepath.Join(wd, shellsplitDir)
	shellGate := filepath.Join(wd, shellgateDir)
	shellType := filepath.Join(wd, shelltypeDir)
	cmd = exec.Command("go", "build", "-tags", "cgo",
		"-o", filepath.Join(wd, binDir, "readonlybox-server"))
	cmd.Dir = filepath.Join(wd, rboxServerDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"CGO_LDFLAGS=-L"+rboxProto+" -L"+shellGate+"/build -lrbox_protocol -lshellgate -lshelltype_gate -lshellsplit_gate -lpthread -lm",
		"CGO_CFLAGS=-I"+rboxProto+"/include -I"+shellSplit+"/include -I"+shellType+"/include -I"+shellGate+"/include",
		"CC="+cc)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("readonlybox-server build failed: %w", err)
	}

	// Set rpath for server binary to find librbox_protocol.so in $ORIGIN/../lib
	cmd = exec.Command("patchelf", "--set-rpath", "$ORIGIN/../lib", serverBin)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("patchelf set-rpath for server failed: %w", err)
	}

	// readonlybox-ptrace
	if err := runMakeWithCC(filepath.Join(wd, rboxPtraceDir), cc); err != nil {
		return fmt.Errorf("rbox-ptrace build failed: %w", err)
	}
	if err := copyFile(filepath.Join(wd, rboxPtraceDir, "readonlybox-ptrace"),
		filepath.Join(wd, binDir, "readonlybox-ptrace")); err != nil {
		return fmt.Errorf("copying readonlybox-ptrace failed: %w", err)
	}

	fmt.Println("=== All binaries built successfully ===")
	return nil
}

// Build rbox-server with capture mode enabled for request logging.
func ServerCapture() error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	cc := os.Getenv("CC")
	if cc == "" {
		cc = "gcc"
	}
	var cmd *exec.Cmd
	rboxProto := filepath.Join(wd, rboxProtocolDir)
	shellSplit := filepath.Join(wd, shellsplitDir)
	shellGate := filepath.Join(wd, shellgateDir)
	shellType := filepath.Join(wd, shelltypeDir)
	captureBin := filepath.Join(wd, binDir, "readonlybox-server-capture")
	cmd = exec.Command("go", "build", "-tags", "cgo,capture",
		"-o", captureBin)
	cmd.Dir = filepath.Join(wd, rboxServerDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"CGO_LDFLAGS=-L"+rboxProto+" -L"+shellGate+"/build -lrbox_protocol -lshellgate -lshelltype_gate -lshellsplit_gate -lpthread -lm",
		"CGO_CFLAGS=-I"+rboxProto+"/include -I"+shellSplit+"/include -I"+shellType+"/include -I"+shellGate+"/include",
		"CC="+cc)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("readonlybox-server-capture build failed: %w", err)
	}

	cmd = exec.Command("patchelf", "--set-rpath", "$ORIGIN/../lib", captureBin)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("patchelf set-rpath for server-capture failed: %w", err)
	}

	fmt.Printf("=== Capture-enabled binary: %s ===\n", captureBin)
	fmt.Println("Usage: readonlybox-server-capture --capture requests.jsonl ...")
	return nil
}

// Build everything in correct order: deps -> DFA -> binaries
func Build() error {
	mg.Deps(BuildDependencies)
	mg.Deps(BuildDFA)
	mg.Deps(BuildBinaries)
	return nil
}

// Clean removes build artifacts
func Clean() error {
	wd, _ := os.Getwd()
	var errs []error

	// Clean c-dfa (CMake-based)
	cDfaPath := filepath.Join(wd, cDfaDir)
	if err := os.RemoveAll(filepath.Join(cDfaPath, "build")); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("c-dfa build dir clean failed: %w", err))
	}

	// Clean other subprojects (Make-based)
	otherSubprojects := []string{shellsplitDir, rboxProtocolDir, rboxWrapDir, rboxPtraceDir, rboxServerDir}
	for _, dir := range otherSubprojects {
		if err := runMakeClean(filepath.Join(wd, dir)); err != nil {
			errs = append(errs, fmt.Errorf("%s clean failed: %w", dir, err))
		}
	}
	// rbox-protocol and shellgate use cmake
	for _, dir := range []string{rboxProtocolDir, shellgateDir} {
		if err := cleanCMake(filepath.Join(wd, dir)); err != nil {
			errs = append(errs, fmt.Errorf("%s clean failed: %w", dir, err))
		}
	}

	// rbox-ruleset uses cmake
	if err := cleanCMake(filepath.Join(wd, rboxRulesetDir)); err != nil {
		errs = append(errs, fmt.Errorf("%s clean failed: %w", rboxRulesetDir, err))
	}

	// Remove bin directory
	binPath := filepath.Join(wd, binDir)
	if err := os.RemoveAll(binPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("removing %s failed: %w", binDir, err))
	}

	// Remove lib directory (dev build artifact)
	libPath := filepath.Join(wd, "lib")
	if err := os.RemoveAll(libPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("removing lib failed: %w", libPath, err))
	}

	// Clean generated DFA files
	generatedFiles := []string{
		filepath.Join(wd, clientDir, "readonlybox.nfa"),
		filepath.Join(wd, clientDir, "readonlybox.dfa"),
		filepath.Join(wd, clientDir, "readonlybox_dfa.c"),
		filepath.Join(wd, clientDir, "dfa_static_data.c"),
		filepath.Join(wd, "readonlybox"),
		filepath.Join(wd, "readonlybox-server"),
		filepath.Join(wd, "libreadonlybox_client.so"),
		filepath.Join(wd, rboxServerDir, "server"),
	}
	for _, f := range generatedFiles {
		if err := os.RemoveAll(f); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("removing %s failed: %w", filepath.Base(f), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("clean completed with errors: %v", errs)
	}
	fmt.Println("Clean complete")
	return nil
}

// Test runs all tests
func Test() error {
	if err := Build(); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	// Run c-dfa tests using CMake/ctest
	fmt.Println("=== Running c-dfa tests ===")
	if err := runCMakeTest(filepath.Join(cDfaDir)); err != nil {
		return fmt.Errorf("c-dfa tests failed: %w", err)
	}

	// Run shellsplit tests
	fmt.Println("=== Running shellsplit tests ===")
	if err := runMakeTest(filepath.Join(shellsplitDir)); err != nil {
		return fmt.Errorf("shellsplit tests failed: %w", err)
	}

	// Run rbox-protocol tests (uses cmake/ctest)
	fmt.Println("=== Running rbox-protocol tests ===")
	if err := runCMakeTest(filepath.Join(rboxProtocolDir)); err != nil {
		return fmt.Errorf("rbox-protocol tests failed: %w", err)
	}

	// Run rbox-ruleset tests (CMake-built test_runner)
	fmt.Println("=== Running rbox-ruleset tests ===")
	if err := runTestBinary(filepath.Join(rboxRulesetDir, "build", "bin", "test_runner")); err != nil {
		return fmt.Errorf("rbox-ruleset tests failed: %w", err)
	}

	// Run rbox-wrap tests
	fmt.Println("=== Running rbox-wrap tests ===")
	if err := runMakeTest(filepath.Join(rboxWrapDir)); err != nil {
		return fmt.Errorf("rbox-wrap tests failed: %w", err)
	}

	// Run rbox-ptrace tests
	fmt.Println("=== Running rbox-ptrace tests ===")
	if err := runMakeTest(rboxPtraceDir); err != nil {
		return fmt.Errorf("rbox-ptrace tests failed: %w", err)
	}

	// Run shelltype tests
	fmt.Println("=== Running shelltype tests ===")
	if err := runMakeTest(shelltypeDir); err != nil {
		return fmt.Errorf("shelltype tests failed: %w", err)
	}

	// Run shellgate tests
	fmt.Println("=== Running shellgate tests ===")
	if err := runCMakeTest(shellgateDir); err != nil {
		return fmt.Errorf("shellgate tests failed: %w", err)
	}

	// Run rbox-server shell tests
	fmt.Println("=== Running rbox-server shell tests ===")
	if err := runGoTest(rboxServerDir, "shell"); err != nil {
		return fmt.Errorf("rbox-server shell tests failed: %w", err)
	}

	fmt.Println("=== All tests passed ===")
	return nil
}

// ValidatePatterns validates command patterns
func ValidatePatterns() error {
	fmt.Println("Validating patterns...")
	wd, _ := os.Getwd()

	// Check that cdfatool exists before trying to use it
	cdfatool := filepath.Join(wd, cDfaToolsDir, "cdfatool")
	if _, err := os.Stat(cdfatool); os.IsNotExist(err) {
		return fmt.Errorf("cdfatool not found: %s (run 'mage deps' first)", cdfatool)
	}

	cmd := exec.Command(cdfatool, "validate",
		filepath.Join(wd, clientDir, "rbox_client_safe_commands.txt"))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pattern validation failed: %w", err)
	}
	return nil
}

// Install builds everything then installs binaries to system
func Install() error {
	mg.Deps(Build)

	wd, _ := os.Getwd()
	binDirPath := filepath.Join(wd, binDir)

	// Use sudo if not running as root
	sudo := ""
	if os.Getuid() != 0 {
		sudo = "sudo"
	}

	fmt.Printf("Installing to /usr/local (%sinstall)\n", sudo)

	// Build rbox-protocol shared library via cmake
	fmt.Printf("  Building rbox-protocol...\n")
	if err := buildCMake(filepath.Join(wd, rboxProtocolDir)); err != nil {
		return fmt.Errorf("rbox-protocol build failed: %w", err)
	}

	// Install shared library to /usr/local/lib
	libs := []struct {
		src  string
		dst  string
		name string
	}{
		{filepath.Join(wd, rboxProtocolDir, "librbox_protocol.so"), "/usr/local/lib/librbox_protocol.so", "librbox_protocol.so"},
	}
	for _, lib := range libs {
		if _, err := os.Stat(lib.src); os.IsNotExist(err) {
			return fmt.Errorf("shared library not found: %s (build may have failed)", lib.src)
		}
		var cmd *exec.Cmd
		if sudo != "" {
			cmd = exec.Command(sudo, "cp", lib.src, lib.dst)
		} else {
			cmd = exec.Command("cp", lib.src, lib.dst)
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("installing %s failed: %w", lib.name, err)
		}
		fmt.Printf("  Installed %s\n", lib.dst)
	}

	// Run ldconfig to update library cache
	fmt.Printf("  Running ldconfig...\n")
	var ldconfigCmd *exec.Cmd
	if sudo != "" {
		ldconfigCmd = exec.Command(sudo, "ldconfig")
	} else {
		ldconfigCmd = exec.Command("ldconfig")
	}
	ldconfigCmd.Stdout = os.Stdout
	ldconfigCmd.Stderr = os.Stderr
	if err := ldconfigCmd.Run(); err != nil {
		fmt.Printf("  Warning: ldconfig failed: %v\n", err)
	}

	installCmd := func(src, dst string) error {
		var cmd *exec.Cmd
		if sudo != "" {
			cmd = exec.Command(sudo, "install", "-m", "755", "-o", "root", "-g", "root", src, dst)
		} else {
			cmd = exec.Command("install", "-m", "755", src, dst)
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	// Install executables to /usr/local/bin
	executables := []string{
		filepath.Join(binDirPath, "readonlybox-server"),
		filepath.Join(binDirPath, "readonlybox-ptrace"),
		filepath.Join(binDirPath, "rbox-wrap"),
	}
	for _, bin := range executables {
		base := filepath.Base(bin)
		if err := installCmd(bin, filepath.Join("/usr/local/bin", base)); err != nil {
			return fmt.Errorf("installing %s failed: %w", base, err)
		}
		fmt.Printf("  Installed /usr/local/bin/%s\n", base)
	}

	// Set capabilities on readonlybox-ptrace (requires CAP_SYS_PTRACE + CAP_SYS_ADMIN)
	ptraceBinary := filepath.Join("/usr/local/bin", "readonlybox-ptrace")
	capStr := "cap_sys_ptrace,cap_sys_admin+ep"
	fmt.Printf("  Setting capabilities on readonlybox-ptrace...\n")
	var capCmd *exec.Cmd
	if sudo != "" {
		capCmd = exec.Command(sudo, "setcap", capStr, ptraceBinary)
	} else {
		capCmd = exec.Command("setcap", capStr, ptraceBinary)
	}
	capCmd.Stdout = os.Stdout
	capCmd.Stderr = os.Stderr
	if err := capCmd.Run(); err != nil {
		return fmt.Errorf("setting capabilities on readonlybox-ptrace failed: %w", err)
	}
	// Verify the binary was installed correctly
	if _, err := os.Stat(ptraceBinary); err != nil {
		return fmt.Errorf("readonlybox-ptrace not found after installation: %w", err)
	}
	fmt.Printf("  Set %s on readonlybox-ptrace\n", capStr)

	// Install PolicyKit policy file for custom authentication dialog (optional)
	policySrc := filepath.Join(wd, rboxPtraceDir, "readonlybox-ptrace.policy")
	policyDst := "/usr/share/polkit-1/actions/org.freedesktop.policykit.pkexec.readonlybox-ptrace.policy"
	if _, err := os.Stat(policySrc); err == nil {
		fmt.Printf("  Installing PolicyKit policy file...\n")
		var policyCmd *exec.Cmd
		if sudo != "" {
			policyCmd = exec.Command(sudo, "cp", policySrc, policyDst)
		} else {
			policyCmd = exec.Command("cp", policySrc, policyDst)
		}
		policyCmd.Stdout = os.Stdout
		policyCmd.Stderr = os.Stderr
		if err := policyCmd.Run(); err != nil {
			fmt.Printf("  Warning: could not install PolicyKit policy: %v\n", err)
		} else {
			fmt.Printf("  Installed PolicyKit policy to %s\n", policyDst)
		}
	}

	// Create socket directory (required for server to work)
	if sudo != "" {
		cmd := exec.Command(sudo, "mkdir", "-p", socketDir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("could not create socket directory %s: %w", socketDir, err)
		}
		cmd = exec.Command(sudo, "chmod", "755", socketDir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("could not chmod socket directory %s: %w", socketDir, err)
		}
		fmt.Printf("  Created socket directory %s\n", socketDir)
	} else {
		if err := os.MkdirAll(socketDir, 0755); err != nil {
			return fmt.Errorf("could not create socket directory %s: %w", socketDir, err)
		}
		fmt.Printf("  Created socket directory %s\n", socketDir)
	}

	fmt.Println("Installation complete")
	return nil
}

// Uninstall removes binaries and libraries from system
func Uninstall() error {
	// Use sudo if not running as root
	sudo := ""
	if os.Getuid() != 0 {
		sudo = "sudo"
	}

	fmt.Printf("Uninstalling from /usr/local (%sinstall)\n", sudo)

	// Remove executables from /usr/local/bin
	executables := []string{
		"/usr/local/bin/readonlybox-server",
		"/usr/local/bin/readonlybox-ptrace",
		"/usr/local/bin/rbox-wrap",
	}
	for _, bin := range executables {
		base := filepath.Base(bin)
		var cmd *exec.Cmd
		if sudo != "" {
			cmd = exec.Command(sudo, "rm", "-f", bin)
		} else {
			cmd = exec.Command("rm", "-f", bin)
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("  Warning: removing %s failed: %v\n", base, err)
		} else {
			fmt.Printf("  Removed %s\n", bin)
		}
	}

	// Remove shared library
	libSrc := "/usr/local/lib/librbox_protocol.so"
	var libCmd *exec.Cmd
	if sudo != "" {
		libCmd = exec.Command(sudo, "rm", "-f", libSrc)
	} else {
		libCmd = exec.Command("rm", "-f", libSrc)
	}
	libCmd.Stdout = os.Stdout
	libCmd.Stderr = os.Stderr
	if err := libCmd.Run(); err != nil {
		fmt.Printf("  Warning: removing %s failed: %v\n", libSrc, err)
	} else {
		fmt.Printf("  Removed %s\n", libSrc)
	}

	// Run ldconfig to update library cache
	fmt.Printf("  Running ldconfig...\n")
	var ldconfigCmd *exec.Cmd
	if sudo != "" {
		ldconfigCmd = exec.Command(sudo, "ldconfig")
	} else {
		ldconfigCmd = exec.Command("ldconfig")
	}
	ldconfigCmd.Stdout = os.Stdout
	ldconfigCmd.Stderr = os.Stderr
	if err := ldconfigCmd.Run(); err != nil {
		fmt.Printf("  Warning: ldconfig failed: %v\n", err)
	}

	// Remove PolicyKit policy file
	policyDst := "/usr/share/polkit-1/actions/org.freedesktop.policykit.pkexec.readonlybox-ptrace.policy"
	var policyCmd *exec.Cmd
	if sudo != "" {
		policyCmd = exec.Command(sudo, "rm", "-f", policyDst)
	} else {
		policyCmd = exec.Command("rm", "-f", policyDst)
	}
	policyCmd.Stdout = os.Stdout
	policyCmd.Stderr = os.Stderr
	if err := policyCmd.Run(); err != nil {
		fmt.Printf("  Warning: removing PolicyKit policy failed: %v\n", err)
	} else {
		fmt.Printf("  Removed %s\n", policyDst)
	}

	// Remove socket directory
	var socketCmd *exec.Cmd
	if sudo != "" {
		socketCmd = exec.Command(sudo, "rm", "-rf", socketDir)
	} else {
		socketCmd = exec.Command("rm", "-rf", socketDir)
	}
	socketCmd.Stdout = os.Stdout
	socketCmd.Stderr = os.Stderr
	if err := socketCmd.Run(); err != nil {
		fmt.Printf("  Warning: removing socket directory failed: %v\n", err)
	} else {
		fmt.Printf("  Removed %s\n", socketDir)
	}

	fmt.Println("Uninstallation complete")
	return nil
}

// runMakeClean runs make clean in a directory
func runMakeClean(dir string) error {
	cmd := exec.Command("make", "clean")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to clean %s: %w", dir, err)
	}
	return nil
}

// runCMakeConfig runs cmake configure in a directory
func runCMakeConfig(dir string) error {
	os.MkdirAll(filepath.Join(dir, "build"), 0755)
	cmd := exec.Command("cmake", "-B", "build")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cmake configure failed for %s: %w", dir, err)
	}
	return nil
}

// runCMakeBuild runs cmake --build in a directory
func runCMakeBuild(dir string) error {
	cmd := exec.Command("cmake", "--build", "build")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cmake build failed for %s: %w", dir, err)
	}
	return nil
}

// runCMake runs cmake configure + build in a directory
func runCMake(dir string, parallel bool) error {
	if err := runCMakeConfig(dir); err != nil {
		return err
	}
	if parallel {
		nproc := os.Getenv("NPROC")
		// With parallel, use cmake --build with -j to pass to underlying make
		cmd := exec.Command("cmake", "--build", "build")
		if nproc != "" && nproc != "0" {
			cmd = exec.Command("cmake", "--build", "build", "--parallel", nproc)
		} else {
			cmd = exec.Command("cmake", "--build", "build", "--parallel")
		}
		cmd.Dir = dir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("cmake build failed for %s: %w", dir, err)
		}
	} else {
		if err := runCMakeBuild(dir); err != nil {
			return err
		}
	}
	return nil
}

// runCMakeTools runs cmake --build with tools target
func runCMakeTools(dir string) error {
	cmd := exec.Command("cmake", "--build", "build", "--target", "tools")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cmake build tools failed for %s: %w", dir, err)
	}
	return nil
}

// runCMakeTest runs cmake --build then ctest for a project
func runCMakeTest(dir string) error {
	// First configure and build
	if err := runCMakeConfig(dir); err != nil {
		return err
	}
	if err := runCMakeBuild(dir); err != nil {
		return err
	}

	buildDir := filepath.Join(dir, "build")

	// Try test-full target first (provides aggregated summary with JUnit XML)
	cmd := exec.Command("cmake", "--build", buildDir, "--target", "test-full")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// Fall back to plain ctest if test-full doesn't exist
		cmd = exec.Command("ctest", "--test-dir", buildDir, "--output-on-failure")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("ctest failed for %s: %w", dir, err)
		}
	}
	return nil
}

// runMake runs make in a directory with optional parallel build
func runMake(dir string, parallel bool) error {
	args := []string{}
	if parallel {
		nproc := os.Getenv("NPROC")
		if nproc != "" && nproc != "0" {
			args = append(args, "-j"+nproc)
		} else {
			// Just -j without number means use all available cores
			args = append(args, "-j")
		}
	}
	args = append(args, "all")

	cmd := exec.Command("make", args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// buildCMake builds a cmake project in the given directory
func buildCMake(dir string) error {
	// Create build directory alongside source
	buildDir := filepath.Join(dir, "build")
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		return fmt.Errorf("failed to create build dir: %w", err)
	}

	// Run cmake configure
	cmd := exec.Command("cmake", "-B", "build", "-S", ".")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cmake configure failed: %w", err)
	}

	// Run cmake build with parallel jobs
	nproc := os.Getenv("NPROC")
	if nproc == "" || nproc == "0" {
		// Use all available cores (don't specify -j, let cmake decide)
		cmd = exec.Command("cmake", "--build", "build")
	} else {
		cmd = exec.Command("cmake", "--build", "build", "--parallel", nproc)
	}
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cmake build failed: %w", err)
	}

	return nil
}

// cleanCMake removes cmake build directory and generated artifacts
func cleanCMake(dir string) error {
	// Remove build directory
	buildDir := filepath.Join(dir, "build")
	if err := os.RemoveAll(buildDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove build dir: %w", err)
	}

	// Remove generated library symlinks in source directory
	// These are created by cmake POST_BUILD commands
	libs := []string{"librbox_protocol.so", "librbox_protocol.so.1"}
	for _, lib := range libs {
		p := filepath.Join(dir, lib)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			// Log but don't fail - might be a real file not a symlink
			fmt.Printf("Warning: could not remove %s: %v\n", p, err)
		}
	}
	return nil
}

// runMakeTest runs make test in a directory
func runMakeTest(dir string) error {
	cmd := exec.Command("make", "test")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tests failed in %s: %w\n  See output above for details", dir, err)
	}
	return nil
}

// runTestBinary runs a test executable directly
func runTestBinary(binPath string) error {
	cmd := exec.Command(binPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("test binary failed: %w", err)
	}
	return nil
}

// runMakeWithCC runs make with a specific C compiler
func runMakeWithCC(dir string, cc string) error {
	nproc := os.Getenv("NPROC")
	jarg := "-j"
	if nproc != "" && nproc != "0" {
		jarg = "-j" + nproc
	}

	cmd := exec.Command("make", jarg, "all", "CC="+cc)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0755)
}

func runGoTest(dir string, pkg string) error {
	wd, _ := os.Getwd()
	shellSplit := filepath.Join(wd, shellsplitDir)
	shellGate := filepath.Join(wd, shellgateDir)
	shellType := filepath.Join(wd, shelltypeDir)
	rboxProto := filepath.Join(wd, rboxProtocolDir)

	cmd := exec.Command("go", "test", "-tags", "cgo", "-v", "./"+pkg)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=1",
		"CGO_LDFLAGS=-L"+shellGate+"/build -L"+rboxProto+" -lshellgate -lshelltype_gate -lshellsplit_gate -lrbox_protocol -lpthread -lm",
		"CGO_CFLAGS=-I"+shellSplit+"/include -I"+shellType+"/include -I"+shellGate+"/include -I"+rboxProto+"/include",
	)
	return cmd.Run()
}
