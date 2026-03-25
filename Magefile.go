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

// Default target
var Default = Build

// Desc returns description for mage -l output
func Desc(target string) string {
	descriptions := map[string]string{
		"Build":             "Build all binaries (default)",
		"BuildBinaries":     "Build main binaries (rbox-wrap, rbox-server, rbox-ptrace)",
		"BuildDFA":          "Build DFA data for client library",
		"BuildDependencies":  "Build base C libraries and tools",
		"Clean":             "Remove all build artifacts",
		"Test":              "Run all tests",
		"ValidatePatterns":  "Validate command pattern files",
		"Deps":              "Build DFA tools (nfa_builder, nfa2dfa, dfa2c) first",
		"Install":           "Install binaries to system (requires root)",
	}
	return descriptions[target]
}

// Version returns version string
func Version() string {
	return "readonlybox build system 1.0.0"
}

// BuildDependencies builds base C libraries
func BuildDependencies() error {
	wd, _ := os.Getwd()
	os.Setenv("CGO_ENABLED", "1")
	os.MkdirAll("bin", 0755)

	// Build c-dfa FIRST (produces tools needed for pattern validation)
	if err := runMake(filepath.Join(wd, "c-dfa"), true); err != nil {
		return fmt.Errorf("c-dfa build failed: %w", err)
	}

	// Now validate patterns (needs nfa_builder from c-dfa)
	if err := ValidatePatterns(); err != nil {
		return fmt.Errorf("pattern validation failed: %w", err)
	}

	if err := runMake(filepath.Join(wd, "shellsplit"), true); err != nil {
		return fmt.Errorf("shellsplit build failed: %w", err)
	}
	if err := runMake(filepath.Join(wd, "rbox-protocol"), true); err != nil {
		return fmt.Errorf("rbox-protocol build failed: %w", err)
	}
	return nil
}

// Deps builds DFA tools explicitly before other operations
func Deps() error {
	fmt.Println("=== Building DFA tools ===")
	wd, _ := os.Getwd()

	// Build c-dfa which produces nfa_builder, nfa2dfa_advanced, dfa2c_array
	if err := runMake(filepath.Join(wd, "c-dfa"), true); err != nil {
		return fmt.Errorf("c-dfa build failed: %w", err)
	}

	// Verify tools exist
	tools := []string{
		filepath.Join(wd, "c-dfa/tools/nfa_builder"),
		filepath.Join(wd, "c-dfa/tools/nfa2dfa_advanced"),
		filepath.Join(wd, "c-dfa/tools/dfa2c_array"),
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
		{filepath.Join(wd, "c-dfa/tools/nfa_builder"), "nfa_builder"},
		{filepath.Join(wd, "c-dfa/tools/nfa2dfa_advanced"), "nfa2dfa_advanced"},
		{filepath.Join(wd, "c-dfa/tools/dfa2c_array"), "dfa2c_array"},
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

	nfaBuilder := filepath.Join(wd, "c-dfa/tools/nfa_builder")
	nfa2dfa := filepath.Join(wd, "c-dfa/tools/nfa2dfa_advanced")
	dfa2cArray := filepath.Join(wd, "c-dfa/tools/dfa2c_array")
	clientDir := filepath.Join(wd, "internal/client")

	patternFile := filepath.Join(clientDir, "rbox_client_safe_commands.txt")
	nfaFile := filepath.Join(clientDir, "readonlybox.nfa")
	dfaFile := filepath.Join(clientDir, "readonlybox.dfa")
	cArrayFile := filepath.Join(clientDir, "readonlybox_dfa.c")
	staticDataFile := filepath.Join(clientDir, "dfa_static_data.c")
	outputFile := filepath.Join(wd, "bin", "libreadonlybox_client.so")

	// Step 1: Pattern → NFA
	if needsRebuild(nfaFile, patternFile) {
		fmt.Println("=== Pattern file changed, regenerating DFA ===")
		cmd := exec.Command(nfaBuilder, patternFile, nfaFile)
		cmd.Dir = clientDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("nfa_builder failed: %w", err)
		}
	}

	// Step 2: NFA → DFA
	if needsRebuild(dfaFile, nfaFile) {
		cmd := exec.Command(nfa2dfa, nfaFile, dfaFile)
		cmd.Dir = clientDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("nfa2dfa_advanced failed: %w", err)
		}
	}

	// Step 3: DFA → C array
	if needsRebuild(cArrayFile, dfaFile) {
		cmd := exec.Command(dfa2cArray, dfaFile, cArrayFile, "readonlybox_dfa_data")
		cmd.Dir = clientDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("dfa2c_array failed: %w", err)
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
		filepath.Join(clientDir, "client.c"),
		filepath.Join(clientDir, "dfa.c"),
		filepath.Join(wd, "c-dfa/src/dfa_eval.c"),
		filepath.Join(wd, "shellsplit/src/shell_tokenizer.c"),
		filepath.Join(wd, "shellsplit/src/shell_tokenizer_full.c")) {

		fmt.Println("=== Building libreadonlybox_client.so ===")
		cmd := exec.Command(cc, "-shared", "-fPIC", "-O2", "-DFA_EVAL_DEBUG=0", "-o", outputFile,
			filepath.Join(clientDir, "client.c"),
			filepath.Join(clientDir, "dfa.c"),
			staticDataFile,
			filepath.Join(wd, "c-dfa/src/dfa_eval.c"),
			filepath.Join(wd, "shellsplit/src/shell_tokenizer.c"),
			filepath.Join(wd, "shellsplit/src/shell_tokenizer_full.c"),
			"-I"+filepath.Join(wd, "c-dfa/include"),
			"-I"+filepath.Join(wd, "shellsplit/include"),
			"-lpthread", "-ldl")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("compiling libreadonlybox_client.so failed: %w", err)
		}
	}

	return nil
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

	// Force rebuild if DFA .c file is newer than .so
	dfaC := filepath.Join(wd, "internal/client/readonlybox_dfa.c")
	dfaSo := filepath.Join(wd, "bin/libreadonlybox_client.so")
	dfaStat, err := os.Stat(dfaC)
	if err == nil {
		if soStat, err := os.Stat(dfaSo); err == nil {
			if dfaStat.ModTime().After(soStat.ModTime()) {
				// DFA is newer, force rebuild of .so
				os.RemoveAll(dfaSo)
			}
		}
	}

	// Force rebuild if .so is newer than binary
	soStat, err := os.Stat(dfaSo)
	if err == nil {
		for _, bin := range []string{"readonlybox-ptrace"} {
			binPath := filepath.Join(wd, "bin", bin)
			if binStat, err := os.Stat(binPath); err == nil && soStat.ModTime().After(binStat.ModTime()) {
				os.RemoveAll(binPath)
			}
		}
	}

	// rbox-wrap (LD_PRELOAD client)
	if err := runMakeWithCC(filepath.Join(wd, "rbox-wrap"), cc); err != nil {
		return fmt.Errorf("rbox-wrap build failed: %w", err)
	}
	// Copy rbox-wrap to bin directory
	if err := copyFile(filepath.Join(wd, "rbox-wrap", "rbox-wrap"),
		filepath.Join(wd, "bin", "rbox-wrap")); err != nil {
		return fmt.Errorf("copying rbox-wrap failed: %w", err)
	}

	// Force rebuild if rbox-protocol library is newer than binary
	protoLib := filepath.Join(wd, "rbox-protocol/librbox_protocol.a")
	serverBin := filepath.Join(wd, "bin", "readonlybox-server")
	if libStat, err := os.Stat(protoLib); err == nil {
		if binStat, err := os.Stat(serverBin); err == nil {
			if libStat.ModTime().After(binStat.ModTime()) {
				os.RemoveAll(serverBin)
			}
		}
	}

	// rbox-server (Go with C library)
	fmt.Println("=== Building readonlybox-server ===")
	rboxProto := filepath.Join(wd, "rbox-protocol")
	shellSplit := filepath.Join(wd, "shellsplit")
	cmd := exec.Command("go", "build", "-tags", "cgo",
		"-o", filepath.Join(wd, "bin", "readonlybox-server"))
	cmd.Dir = filepath.Join(wd, "rbox-server")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"CGO_LDFLAGS=-L"+rboxProto+" -L"+shellSplit+" -lrbox_protocol -lshellsplit -lpthread -lm",
		"CGO_CFLAGS=-I"+rboxProto+"/include -I"+shellSplit+"/include",
		"CC="+cc)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("readonlybox-server build failed: %w", err)
	}

	// readonlybox-ptrace
	if err := runMakeWithCC(filepath.Join(wd, "rbox-ptrace"), cc); err != nil {
		return fmt.Errorf("rbox-ptrace build failed: %w", err)
	}
	if err := copyFile(filepath.Join(wd, "rbox-ptrace", "readonlybox-ptrace"),
		filepath.Join(wd, "bin", "readonlybox-ptrace")); err != nil {
		return fmt.Errorf("copying readonlybox-ptrace failed: %w", err)
	}

	fmt.Println("=== All binaries built successfully ===")
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

	// Remove bin directory
	os.RemoveAll(filepath.Join(wd, "bin"))

	// Clean subprojects
	runMakeClean := func(dir string) error {
		cmd := exec.Command("make", "clean")
		cmd.Dir = dir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	if err := runMakeClean(filepath.Join(wd, "c-dfa")); err != nil {
		return fmt.Errorf("c-dfa clean failed: %w", err)
	}
	if err := runMakeClean(filepath.Join(wd, "shellsplit")); err != nil {
		return fmt.Errorf("shellsplit clean failed: %w", err)
	}
	if err := runMakeClean(filepath.Join(wd, "rbox-protocol")); err != nil {
		return fmt.Errorf("rbox-protocol clean failed: %w", err)
	}
	if err := runMakeClean(filepath.Join(wd, "rbox-ptrace")); err != nil {
		return fmt.Errorf("rbox-ptrace clean failed: %w", err)
	}

	// Clean generated DFA files
	os.RemoveAll(filepath.Join(wd, "internal/client/readonlybox.nfa"))
	os.RemoveAll(filepath.Join(wd, "internal/client/readonlybox.dfa"))
	os.RemoveAll(filepath.Join(wd, "internal/client/readonlybox_dfa.c"))
	os.RemoveAll(filepath.Join(wd, "internal/client/dfa_static_data.c"))

	// Clean c-dfa tools
	os.RemoveAll(filepath.Join(wd, "c-dfa/tools/nfa_builder"))
	os.RemoveAll(filepath.Join(wd, "c-dfa/tools/nfa2dfa_advanced"))
	os.RemoveAll(filepath.Join(wd, "c-dfa/tools/dfa2c_array"))

	// Clean any stale binaries in project root
	os.RemoveAll(filepath.Join(wd, "readonlybox"))
	os.RemoveAll(filepath.Join(wd, "readonlybox-server"))
	os.RemoveAll(filepath.Join(wd, "libreadonlybox_client.so"))
	os.RemoveAll(filepath.Join(wd, "rbox-server/server"))

	fmt.Println("Clean complete")
	return nil
}

// Test runs all tests
func Test() error {
	mg.Deps(Build)

	// Run rbox-protocol tests
	if err := runMake("rbox-protocol", false); err != nil {
		return fmt.Errorf("rbox-protocol tests failed: %w", err)
	}

	// Run rbox-wrap tests
	if err := runMake("rbox-wrap", false); err != nil {
		return fmt.Errorf("rbox-wrap tests failed: %w", err)
	}

	return nil
}

// ValidatePatterns validates command patterns
func ValidatePatterns() error {
	fmt.Println("Validating patterns...")
	wd, _ := os.Getwd()

	// nfa_builder is already built by make c-dfa
	nfaBuilder := filepath.Join(wd, "c-dfa/tools/nfa_builder")

	cmd := exec.Command(nfaBuilder, "--validate-only",
		filepath.Join(wd, "internal/client/rbox_client_safe_commands.txt"))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pattern validation failed: %w", err)
	}
	return nil
}

// Install installs binaries to system
func Install() error {
	wd, _ := os.Getwd()
	binDir := filepath.Join(wd, "bin")

	// Check if binaries exist (note: libreadonlybox_client.so is not installed - experimental)
	binaries := []string{
		filepath.Join(binDir, "readonlybox-server"),
		filepath.Join(binDir, "readonlybox-ptrace"),
		filepath.Join(binDir, "rbox-wrap"),
	}
	for _, bin := range binaries {
		if _, err := os.Stat(bin); os.IsNotExist(err) {
			return fmt.Errorf("binary not found: %s (run 'mage build' first)", bin)
		}
	}

	// Use sudo if not running as root
	sudo := ""
	if os.Getuid() != 0 {
		sudo = "sudo"
	}

	fmt.Printf("Installing to /usr/local (%sinstall)\n", sudo)

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
		filepath.Join(binDir, "readonlybox-server"),
		filepath.Join(binDir, "readonlybox-ptrace"),
		filepath.Join(binDir, "rbox-wrap"),
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
	fmt.Printf("  Set %s on readonlybox-ptrace\n", capStr)

	// Create socket directory
	socketDir := "/run/readonlybox"
	if sudo != "" {
		cmd := exec.Command(sudo, "mkdir", "-p", socketDir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("  Warning: could not create %s: %v\n", socketDir, err)
		} else {
			cmd = exec.Command(sudo, "chmod", "755", socketDir)
			cmd.Run()
			fmt.Printf("  Created socket directory %s\n", socketDir)
		}
	} else {
		os.MkdirAll(socketDir, 0755)
		fmt.Printf("  Created socket directory %s\n", socketDir)
	}

	fmt.Println("Installation complete")
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
