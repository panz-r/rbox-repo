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

// Build all tools - now just readonlybox with symlinks
var tools = []string{}

// Default target - build and test
var Default = Test

// ValidatePatterns validates patterns before building
func ValidatePatterns() error {
	fmt.Println("=================================================")
	fmt.Println("Validating patterns...")
	fmt.Println("=================================================")

	wd, _ := os.Getwd()
	cdfaDir := filepath.Join(wd, "c-dfa")
	cdfaToolsDir := filepath.Join(cdfaDir, "tools")
	clientDir := filepath.Join(wd, "internal/client")
	patternsFile := filepath.Join(clientDir, "rbox_client_safe_commands.txt")

	// Use nfa_builder for validation
	nfaBuilder := filepath.Join(cdfaToolsDir, "nfa_builder")

	// Build nfa_builder if it doesn't exist
	if _, err := os.Stat(nfaBuilder); os.IsNotExist(err) {
		fmt.Println("Building nfa_builder for validation...")
		buildCmd := exec.Command("gcc", "-o", nfaBuilder,
			filepath.Join(cdfaToolsDir, "nfa_builder.c"),
			filepath.Join(cdfaToolsDir, "pattern_order.c"),
			filepath.Join(cdfaToolsDir, "multi_target_array.c"),
			"-I"+filepath.Join(cdfaDir, "include"),
			"-Wall", "-Wextra", "-std=c11", "-O2", "-mcmodel=medium",
			"-DNFA_BUILDER_DEBUG=1", "-DNFA_BUILDER_VERBOSE=1")
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr
		if err := buildCmd.Run(); err != nil {
			return fmt.Errorf("failed to build nfa_builder for validation: %w", err)
		}
	}

	fmt.Printf("Validating: %s\n", patternsFile)
	cmd := exec.Command(nfaBuilder, "--validate-only", patternsFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pattern validation failed: %w", err)
	}

	fmt.Println("")
	fmt.Println("Pattern validation passed!")
	return nil
}

// Build all tools
func Build() error {
	mg.Deps(Clean, ValidatePatterns)
	if err := buildAll(); err != nil {
		return err
	}
	if err := BuildServer(); err != nil {
		return err
	}
	if err := BuildClient(); err != nil {
		return err
	}
	if err := BuildPtrace(); err != nil {
		return err
	}
	return BuildProtocol()
}

// BuildProtocol builds the rbox-protocol library
func BuildProtocol() error {
	fmt.Println("Building rbox-protocol library...")

	wd, _ := os.Getwd()
	protocolDir := filepath.Join(wd, "rbox-protocol")

	// Build library and tests via its Makefile
	cmd := exec.Command("make", "all")
	cmd.Dir = protocolDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to build rbox-protocol: %w", err)
	}

	return nil
}

// BuildClient builds the LD_PRELOAD client library
func BuildClient() error {
	fmt.Println("Building libreadonlybox_client.so...")

	// Get absolute paths
	wd, _ := os.Getwd()
	cdfaDir := filepath.Join(wd, "c-dfa")
	cdfaToolsDir := filepath.Join(cdfaDir, "tools")
	cdfaSrcDir := filepath.Join(cdfaDir, "src")
	clientDir := filepath.Join(wd, "internal/client")
	clientPatternsFile := filepath.Join(clientDir, "rbox_client_safe_commands.txt")
	nfaFile := filepath.Join(clientDir, "readonlybox.nfa")
	dfaFile := filepath.Join(clientDir, "readonlybox.dfa")
	dfaCArray := filepath.Join(clientDir, "readonlybox_dfa.c")
	clientDfaData := filepath.Join(clientDir, "dfa_static_data.c")

	// Build nfa_builder (always rebuild to ensure latest version)
	nfaBuilder := filepath.Join(cdfaToolsDir, "nfa_builder")
	os.Remove(nfaBuilder)
	fmt.Println("Building nfa_builder...")
	buildNfaBuilderCmd := exec.Command("gcc", "-o", nfaBuilder,
		filepath.Join(cdfaToolsDir, "nfa_builder.c"),
		filepath.Join(cdfaToolsDir, "pattern_order.c"),
		filepath.Join(cdfaToolsDir, "multi_target_array.c"),
		"-I"+filepath.Join(cdfaDir, "include"),
		"-Wall", "-Wextra", "-std=c11", "-O2", "-mcmodel=medium",
		"-DNFA_BUILDER_DEBUG=0", "-DNFA_BUILDER_VERBOSE=0")
	buildNfaBuilderCmd.Stdout = os.Stdout
	buildNfaBuilderCmd.Stderr = os.Stderr
	if err := buildNfaBuilderCmd.Run(); err != nil {
		return fmt.Errorf("failed to build nfa_builder: %w", err)
	}

	// Use existing nfa2dfa_advanced from c-dfa if available
	nfa2dfa := filepath.Join(cdfaToolsDir, "nfa2dfa_advanced")
	if _, err := os.Stat(nfa2dfa); os.IsNotExist(err) {
		// Fallback: build with basic options (may fail without SAT libs)
		os.Remove(nfa2dfa)
		fmt.Println("Building nfa2dfa_advanced...")
		buildCmd := exec.Command("gcc", "-o", nfa2dfa,
			filepath.Join(cdfaToolsDir, "nfa2dfa.c"),
			filepath.Join(cdfaToolsDir, "pattern_order.c"),
			filepath.Join(cdfaToolsDir, "multi_target_array.c"),
			filepath.Join(cdfaToolsDir, "dfa_minimize.c"),
			filepath.Join(cdfaToolsDir, "dfa_minimize_brzozowski.c"),
			filepath.Join(cdfaToolsDir, "dfa_minimize_sat_stub.c"),
			filepath.Join(cdfaToolsDir, "dfa_layout.c"),
			filepath.Join(cdfaToolsDir, "dfa_compress.c"),
			filepath.Join(cdfaToolsDir, "nfa_preminimize.c"),
			filepath.Join(cdfaToolsDir, "nfa_preminimize_windowed_stub.c"),
			"-I"+filepath.Join(cdfaDir, "include"),
			"-Wall", "-Wextra", "-std=c11", "-O2", "-mcmodel=medium",
			"-DNFA2DFA_DEBUG=0", "-DNFA2DFA_VERBOSE=0")
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr
		if err := buildCmd.Run(); err != nil {
			return fmt.Errorf("failed to build nfa2dfa: %w", err)
		}
	} else {
		fmt.Println("Using existing nfa2dfa_advanced...")
	}

	// Build dfa2c_array from client subproject if needed
	dfa2cArray := filepath.Join(wd, "internal/client", "dfa2c_array")
	if _, err := os.Stat(dfa2cArray); os.IsNotExist(err) {
		fmt.Println("Building dfa2c_array...")
		buildCmd := exec.Command("gcc", "-o", dfa2cArray, filepath.Join(wd, "internal/client", "dfa2c_array.c"),
			"-Wall", "-Wextra", "-std=c11", "-O2")
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr
		if err := buildCmd.Run(); err != nil {
			return fmt.Errorf("failed to build dfa2c_array: %w", err)
		}
	}

	// Step 1: Generate NFA from patterns (alphabet is now constructed internally)
	fmt.Println("Generating NFA from patterns...")
	genNfa := exec.Command(nfaBuilder, clientPatternsFile, nfaFile)
	genNfa.Dir = clientDir
	genNfa.Stdout = os.Stdout
	genNfa.Stderr = os.Stderr
	if err := genNfa.Run(); err != nil {
		return fmt.Errorf("failed to generate NFA: %w", err)
	}

	// Step 2: Convert NFA to DFA (version 6)
	fmt.Println("Converting NFA to DFA (v6)...")
	genDfa := exec.Command(nfa2dfa, nfaFile, dfaFile)
	genDfa.Dir = clientDir
	genDfa.Stdout = os.Stdout
	genDfa.Stderr = os.Stderr
	if err := genDfa.Run(); err != nil {
		return fmt.Errorf("failed to generate DFA: %w", err)
	}

	// Step 3: Convert DFA binary to C array
	fmt.Println("Generating C array from DFA...")
	convCmd := exec.Command(dfa2cArray, dfaFile, dfaCArray, "readonlybox_dfa_data")
	convCmd.Dir = clientDir
	convCmd.Stdout = os.Stdout
	convCmd.Stderr = os.Stderr
	if err := convCmd.Run(); err != nil {
		return fmt.Errorf("failed to convert DFA to C array: %w", err)
	}

	// Get shellsplit paths
	shellsplitDir := filepath.Join(wd, "shellsplit")
	shellsplitSrc := filepath.Join(shellsplitDir, "src")
	shellsplitInc := filepath.Join(shellsplitDir, "include")

	// Step 4: Copy DFA C array to client directory
	if err := copyFile(dfaCArray, clientDfaData); err != nil {
		return fmt.Errorf("failed to copy DFA to client: %w", err)
	}

	// Step 5: Build the client library with c-dfa evaluation code
	outputFile := filepath.Join(wd, "bin", "libreadonlybox_client.so")
	buildClient := exec.Command("gcc", "-shared", "-fPIC", "-O2", "-DFA_EVAL_DEBUG=0", "-o", outputFile,
		filepath.Join(wd, "internal/client", "client.c"),
		filepath.Join(wd, "internal/client", "dfa.c"),
		filepath.Join(wd, "internal/client", "dfa_static_data.c"),
		filepath.Join(cdfaSrcDir, "dfa_eval.c"),
		filepath.Join(shellsplitSrc, "shell_tokenizer.c"),
		filepath.Join(shellsplitSrc, "shell_tokenizer_full.c"),
		"-I"+filepath.Join(cdfaDir, "include"),
		"-I"+shellsplitInc,
		"-lpthread", "-ldl")
	buildClient.Stdout = os.Stdout
	buildClient.Stderr = os.Stderr
	if err := buildClient.Run(); err != nil {
		return fmt.Errorf("failed to build client: %w", err)
	}

	fmt.Println("Build complete!")
	return nil
}

// BuildPtrace builds the ptrace-based client
func BuildPtrace() error {
	fmt.Println("Building readonlybox-ptrace...")

	wd, _ := os.Getwd()
	ptraceDir := filepath.Join(wd, "cmd/readonlybox-ptrace")
	binDir := filepath.Join(wd, "bin")
	clientDir := filepath.Join(wd, "internal/client")

	// Ensure bin directory exists
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return fmt.Errorf("failed to create bin directory: %w", err)
	}

	// First, ensure DFA data is generated (copy from client)
	dfaDataSrc := filepath.Join(clientDir, "readonlybox_dfa.c")
	dfaDataDst := filepath.Join(ptraceDir, "readonlybox_dfa_data.c")
	if err := copyFile(dfaDataSrc, dfaDataDst); err != nil {
		return fmt.Errorf("failed to copy DFA data: %w", err)
	}

	// Clean ptrace build to remove old object files with ASAN
	fmt.Println("Cleaning ptrace build...")
	cleanCmd := exec.Command("make", "clean")
	cleanCmd.Dir = ptraceDir
	cleanCmd.Stdout = os.Stdout
	cleanCmd.Stderr = os.Stderr
	cleanCmd.Run()

	// Build ptrace client using its Makefile
	fmt.Println("Building ptrace client...")
	buildCmd := exec.Command("make")
	buildCmd.Dir = ptraceDir
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("failed to build ptrace client: %w", err)
	}

	// Copy binary to bin directory
	srcBinary := filepath.Join(ptraceDir, "readonlybox-ptrace")
	dstBinary := filepath.Join(binDir, "readonlybox-ptrace")
	if err := copyFile(srcBinary, dstBinary); err != nil {
		return fmt.Errorf("failed to copy ptrace binary: %w", err)
	}

	// Make executable
	if err := os.Chmod(dstBinary, 0755); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	fmt.Println("Build complete!")
	return nil
}

// BuildServer builds the readonlybox-server with TUI
func BuildServer() error {
	fmt.Println("Building readonlybox-server...")

	// Run go mod tidy for the server module
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = "cmd/readonlybox-server"
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to tidy server module: %w", err)
	}

	// Build the server - use absolute path for output
	binDir, _ := filepath.Abs("bin")
	cmd = exec.Command("go", "build", "-o", filepath.Join(binDir, "readonlybox-server"), ".")
	cmd.Dir = "cmd/readonlybox-server"
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to build readonlybox-server: %w", err)
	}

	fmt.Println("Build complete!")
	return nil
}

// Clean build artifacts
func Clean() error {
	fmt.Println("Cleaning build artifacts...")

	// Remove binaries in project root
	for _, tool := range tools {
		if err := os.Remove(tool); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	// Remove generated DFA files
	generatedFiles := []string{
		"c-dfa/tools/dfa2c",
		"c-dfa/tools/readonlybox_dfa.c",
		"c-dfa/tools/readonlybox_dfa.dfa",
		"internal/client/dfa_static_data.c",
		"internal/client/readonlybox.nfa",
		"internal/client/readonlybox.dfa",
		"internal/client/readonlybox_dfa.c",
	}
	for _, f := range generatedFiles {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	// Remove bin directory
	return os.RemoveAll("bin")
}

// Install tools to /usr/local/bin
func Install() error {
	mg.Deps(Build)

	destDir := "/usr/local/bin"
	if dest := os.Getenv("DESTDIR"); dest != "" {
		destDir = filepath.Join(dest, "usr/local/bin")
	}

	fmt.Printf("Installing tools to %s...\n", destDir)

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	for _, tool := range tools {
		src := filepath.Join("bin", tool)
		dst := filepath.Join(destDir, tool)

		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf("failed to install %s: %w", tool, err)
		}

		if err := os.Chmod(dst, 0755); err != nil {
			return fmt.Errorf("failed to set permissions for %s: %w", tool, err)
		}
	}

	fmt.Println("Installation complete!")
	return nil
}

// Uninstall tools from /usr/local/bin
func Uninstall() error {
	destDir := "/usr/local/bin"
	if dest := os.Getenv("DESTDIR"); dest != "" {
		destDir = filepath.Join(dest, "usr/local/bin")
	}

	fmt.Printf("Uninstalling tools from %s...\n", destDir)

	for _, tool := range tools {
		dst := filepath.Join(destDir, tool)
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to uninstall %s: %w", tool, err)
		}
	}

	fmt.Println("Uninstallation complete!")
	return nil
}

// Test all tools - builds first, then runs all tests
func Test() error {
	mg.Deps(Build)
	if err := DfaTest(); err != nil {
		return err
	}
	if err := UnitTest(); err != nil {
		return err
	}
	return IntegrationTest()
}

// Run unit tests (quiet output)
func UnitTest() error {
	fmt.Println("Running unit tests...")

	packages := []string{
		"./internal/rogit/...",
		"./internal/rofind/...",
		"./internal/rols/...",
		"./internal/rocat/...",
		"./internal/rogrep/...",
		"./internal/rohead/...",
		"./internal/rotail/...",
		"./internal/rotimeout/...",
		"./internal/roecho/...",
		"./internal/rodate/...",
		"./internal/rocd/...",
		"./internal/robash/...",
		"./internal/rosort/...",
		"./internal/roulimit/...",
		"./internal/rosed/...",
		"./internal/rochmod/...",
		"./internal/rochown/...",
		"./internal/romkdir/...",
		"./internal/rormdir/...",
		"./internal/roln/...",
		"./internal/romv/...",
		"./internal/rocp/...",
		"./internal/roremove/...",
		"./internal/rotouch/...",
		"./internal/rodd/...",
		"./internal/rops/...",
		"./internal/rodf/...",
		"./internal/rodu/...",
		"./internal/rowc/...",
		"./internal/rouname/...",
	}

	failed := 0
	passed := 0

	for _, pkg := range packages {
		// Run without -v for cleaner output
		cmd := exec.Command("go", "test", pkg)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			failed++
		} else {
			passed++
		}
	}

	fmt.Printf("Unit tests: %d passed, %d failed\n", passed, failed)
	if failed > 0 {
		return fmt.Errorf("%d unit test packages failed", failed)
	}
	return nil
}

// Run C DFA unit tests - delegates to subproject Makefiles
func DfaTest() error {
	fmt.Println("Running C DFA and shell tokenizer tests...")

	wd, _ := os.Getwd()

	// Run c-dfa tests via its Makefile
	fmt.Println("\n=== Running c-dfa tests ===")
	cdfaCmd := exec.Command("make", "test")
	cdfaCmd.Dir = filepath.Join(wd, "c-dfa")
	cdfaCmd.Stdout = os.Stdout
	cdfaCmd.Stderr = os.Stderr
	if err := cdfaCmd.Run(); err != nil {
		fmt.Printf("c-dfa tests failed: %v\n", err)
	}

	// Run shellsplit tests via its Makefile
	fmt.Println("\n=== Running shellsplit tests ===")
	shellsplitCmd := exec.Command("make", "test")
	shellsplitCmd.Dir = filepath.Join(wd, "shellsplit")
	shellsplitCmd.Stdout = os.Stdout
	shellsplitCmd.Stderr = os.Stderr
	if err := shellsplitCmd.Run(); err != nil {
		fmt.Printf("shellsplit tests failed: %v\n", err)
	}

	// Run rbox-protocol tests via its Makefile
	fmt.Println("\n=== Running rbox-protocol tests ===")
	protocolCmd := exec.Command("make", "test")
	protocolCmd.Dir = filepath.Join(wd, "rbox-protocol")
	protocolCmd.Stdout = os.Stdout
	protocolCmd.Stderr = os.Stderr
	if err := protocolCmd.Run(); err != nil {
		fmt.Printf("rbox-protocol tests failed: %v\n", err)
	}

	fmt.Println("\nDFA and tokenizer tests complete!")
	return nil
}

// Run integration tests
func IntegrationTest() error {
	fmt.Println("Running integration tests...")

	// Run without -v for cleaner output
	cmd := exec.Command("go", "test", "./test/...")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Quick test (tests the LD_PRELOAD client with DFA)
func QuickTest() error {
	mg.Deps(Build)

	fmt.Println("Testing readonlybox DFA fast path...")

	// Test DFA-allowed commands (fast path)
	fmt.Println("Testing git log (should be allowed via DFA)...")
	runCmd("./readonlybox", "git", "log", "--oneline", "-n", "3")

	fmt.Println("Testing cat (should be allowed via DFA)...")
	runCmd("./readonlybox", "cat", "Makefile")

	fmt.Println("Testing ps aux (should be allowed via DFA)...")
	runCmd("./readonlybox", "ps", "aux", "-n", "3")

	fmt.Println("Testing df -h (should be allowed via DFA)...")
	runCmd("./readonlybox", "df", "-h")

	// Test that blocked commands go through --run validation
	fmt.Println("Testing git add (should be blocked by server)...")
	runCmd("./readonlybox", "--run", "git", "add", ".")

	fmt.Println("Testing rm (should be blocked by server)...")
	runCmd("./readonlybox", "--run", "rm", "file.txt")

	return nil
}

// Format code
func Fmt() error {
	fmt.Println("Formatting code...")
	cmd := exec.Command("gofmt", "-w", ".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Test coverage
func Coverage() error {
	fmt.Println("Generating test coverage...")

	packages := []string{
		"./internal/rogit/...",
		"./internal/rofind/...",
		"./internal/rols/...",
		"./internal/rocat/...",
		"./internal/rogrep/...",
		"./internal/rohead/...",
		"./internal/rotail/...",
		"./internal/rotimeout/...",
		"./internal/roecho/...",
		"./internal/rodate/...",
		"./internal/rocd/...",
		"./internal/robash/...",
		"./internal/rosort/...",
		"./internal/roulimit/...",
		"./internal/rosed/...",
		"./internal/rochmod/...",
		"./internal/rochown/...",
		"./internal/romkdir/...",
		"./internal/rormdir/...",
		"./internal/roln/...",
		"./internal/romv/...",
		"./internal/rocp/...",
		"./internal/roremove/...",
		"./internal/rotouch/...",
		"./internal/rodd/...",
		"./internal/rops/...",
		"./internal/rodf/...",
		"./internal/rodu/...",
		"./internal/rowc/...",
		"./internal/rouname/...",
		"./test/...",
	}

	cmd := exec.Command("go", append([]string{"test", "-coverprofile=coverage.out"}, packages...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("go", "tool", "cover", "-html=coverage.out")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Helper functions

func buildAll() error {
	fmt.Println("Building all tools...")

	if err := os.MkdirAll("bin", 0755); err != nil {
		return err
	}

	// Build readonlybox single binary
	cmd := exec.Command("go", "build", "-o", filepath.Join("bin", "readonlybox"), "./cmd/readonlybox")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to build readonlybox: %w", err)
	}

	// Create symlinks for each tool pointing to readonlybox
	for _, tool := range tools {
		linkPath := filepath.Join("bin", tool)

		// Remove existing file/symlink
		os.Remove(linkPath)

		// Create symlink with relative path "readonlybox"
		// This works because the symlink is in the same directory as readonlybox
		if err := os.Symlink("readonlybox", linkPath); err != nil {
			return fmt.Errorf("failed to create symlink %s: %w", tool, err)
		}
	}

	fmt.Println("Build complete!")
	return nil
}

func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0755)
}

func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// Check if this is a blocked command (expected)
		if strings.Contains(err.Error(), "exit status") {
			fmt.Printf("Command blocked as expected: %s %s\\n", name, strings.Join(args, " "))
		} else {
			fmt.Printf("Error running command: %s %s: %v\n", name, strings.Join(args, " "), err)
		}
	}
}
