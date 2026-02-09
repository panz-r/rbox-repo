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
	patternsFile := filepath.Join(cdfaDir, "patterns_safe_commands.txt")

	// Use nfa_builder for validation
	nfaBuilder := filepath.Join(cdfaToolsDir, "nfa_builder")

	// Build nfa_builder if it doesn't exist
	if _, err := os.Stat(nfaBuilder); os.IsNotExist(err) {
		fmt.Println("Building nfa_builder for validation...")
		buildCmd := exec.Command("gcc", "-o", nfaBuilder,
			filepath.Join(cdfaToolsDir, "nfa_builder.c"),
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
	return BuildClient()
}

// BuildClient builds the LD_PRELOAD client library
func BuildClient() error {
	fmt.Println("Building libreadonlybox_client.so...")

	// Get absolute paths
	wd, _ := os.Getwd()
	cdfaDir := filepath.Join(wd, "c-dfa")
	cdfaToolsDir := filepath.Join(cdfaDir, "tools")
	cdfaSrcDir := filepath.Join(cdfaDir, "src")
	patternsFile := filepath.Join(cdfaDir, "patterns_safe_commands.txt")
	nfaFile := filepath.Join(cdfaDir, "readonlybox.nfa")
	dfaFile := filepath.Join(cdfaDir, "readonlybox.dfa")
	dfaCArray := filepath.Join(cdfaToolsDir, "readonlybox_dfa.c")
	clientDfaData := filepath.Join(wd, "internal/client", "dfa_static_data.c")

	// Build nfa_builder (always rebuild to ensure latest version)
	nfaBuilder := filepath.Join(cdfaToolsDir, "nfa_builder")
	os.Remove(nfaBuilder)
	fmt.Println("Building nfa_builder...")
	buildNfaBuilderCmd := exec.Command("gcc", "-o", nfaBuilder,
		filepath.Join(cdfaToolsDir, "nfa_builder.c"),
		filepath.Join(cdfaToolsDir, "multi_target_array.c"),
		"-I"+filepath.Join(cdfaDir, "include"),
		"-Wall", "-Wextra", "-std=c11", "-O2", "-mcmodel=medium",
		"-DNFA_BUILDER_DEBUG=0", "-DNFA_BUILDER_VERBOSE=0")
	buildNfaBuilderCmd.Stdout = os.Stdout
	buildNfaBuilderCmd.Stderr = os.Stderr
	if err := buildNfaBuilderCmd.Run(); err != nil {
		return fmt.Errorf("failed to build nfa_builder: %w", err)
	}

	// Build nfa2dfa (always rebuild to ensure latest version)
	nfa2dfa := filepath.Join(cdfaToolsDir, "nfa2dfa")
	os.Remove(nfa2dfa)
	fmt.Println("Building nfa2dfa...")
	buildCmd := exec.Command("gcc", "-o", nfa2dfa,
		filepath.Join(cdfaToolsDir, "nfa2dfa.c"),
		filepath.Join(cdfaToolsDir, "multi_target_array.c"),
		filepath.Join(cdfaToolsDir, "dfa_minimize.c"),
		filepath.Join(cdfaToolsDir, "dfa_minimize_brzozowski.c"),
		"-I"+filepath.Join(cdfaDir, "include"),
		"-Wall", "-Wextra", "-std=c11", "-O2", "-mcmodel=medium",
		"-DNFA2DFA_DEBUG=0", "-DNFA2DFA_VERBOSE=0")
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("failed to build nfa2dfa: %w", err)
	}

	// Build dfa2c_array if needed
	dfa2cArray := filepath.Join(cdfaToolsDir, "dfa2c_array")
	if _, err := os.Stat(dfa2cArray); os.IsNotExist(err) {
		fmt.Println("Building dfa2c_array...")
		buildCmd := exec.Command("gcc", "-o", dfa2cArray, filepath.Join(cdfaToolsDir, "dfa2c_array.c"),
			"-Wall", "-Wextra", "-std=c11", "-O2")
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr
		if err := buildCmd.Run(); err != nil {
			return fmt.Errorf("failed to build dfa2c_array: %w", err)
		}
	}

	// Step 1: Generate NFA from patterns (alphabet is now constructed internally)
	fmt.Println("Generating NFA from patterns...")
	genNfa := exec.Command(nfaBuilder, patternsFile, nfaFile)
	genNfa.Dir = cdfaDir
	genNfa.Stdout = os.Stdout
	genNfa.Stderr = os.Stderr
	if err := genNfa.Run(); err != nil {
		return fmt.Errorf("failed to generate NFA: %w", err)
	}

	// Step 2: Convert NFA to DFA (version 3 - character-based)
	fmt.Println("Converting NFA to DFA (v3)...")
	genDfa := exec.Command(nfa2dfa, nfaFile, dfaFile)
	genDfa.Dir = cdfaDir
	genDfa.Stdout = os.Stdout
	genDfa.Stderr = os.Stderr
	if err := genDfa.Run(); err != nil {
		return fmt.Errorf("failed to generate DFA: %w", err)
	}

	// Step 3: Convert DFA binary to C array
	fmt.Println("Generating C array from DFA...")
	convCmd := exec.Command(dfa2cArray, dfaFile, dfaCArray, "readonlybox_dfa")
	convCmd.Dir = cdfaDir
	convCmd.Stdout = os.Stdout
	convCmd.Stderr = os.Stderr
	if err := convCmd.Run(); err != nil {
		return fmt.Errorf("failed to convert DFA to C array: %w", err)
	}

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
		filepath.Join(cdfaSrcDir, "shell_tokenizer.c"),
		filepath.Join(cdfaSrcDir, "shell_tokenizer_ext.c"),
		"-I"+filepath.Join(cdfaDir, "include"),
		"-lpthread", "-ldl")
	buildClient.Stdout = os.Stdout
	buildClient.Stderr = os.Stderr
	if err := buildClient.Run(); err != nil {
		return fmt.Errorf("failed to build client: %w", err)
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

// Run C DFA unit tests
func DfaTest() error {
	fmt.Println("Running DFA unit tests...")

	wd, _ := os.Getwd()
	cdfaDir := filepath.Join(wd, "c-dfa")
	cdfaToolsDir := filepath.Join(cdfaDir, "tools")
	cdfaSrcDir := filepath.Join(cdfaDir, "src")
	dfaTestNew := filepath.Join(cdfaDir, "dfa_test_new")
	shellTest := filepath.Join(cdfaDir, "shell_tokenizer_test")

	// Build nfa_builder if needed
	nfaBuilder := filepath.Join(cdfaToolsDir, "nfa_builder")
	if _, err := os.Stat(nfaBuilder); os.IsNotExist(err) {
		fmt.Println("Building nfa_builder...")
		buildCmd := exec.Command("gcc", "-o", nfaBuilder,
			filepath.Join(cdfaToolsDir, "nfa_builder.c"),
			filepath.Join(cdfaToolsDir, "multi_target_array.c"),
			"-I"+filepath.Join(cdfaDir, "include"),
			"-Wall", "-Wextra", "-std=c11", "-O2", "-mcmodel=medium",
			"-DNFA_BUILDER_DEBUG=1", "-DNFA_BUILDER_VERBOSE=1")
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr
		if err := buildCmd.Run(); err != nil {
			return fmt.Errorf("failed to build nfa_builder: %w", err)
		}
	}

	// Build nfa2dfa (always rebuild to ensure latest version)
	nfa2dfa := filepath.Join(cdfaToolsDir, "nfa2dfa")
	os.Remove(nfa2dfa)
	fmt.Println("Building nfa2dfa...")
	buildCmd := exec.Command("gcc", "-o", nfa2dfa,
		filepath.Join(cdfaToolsDir, "nfa2dfa.c"),
		filepath.Join(cdfaToolsDir, "multi_target_array.c"),
		filepath.Join(cdfaToolsDir, "dfa_minimize.c"),
		filepath.Join(cdfaToolsDir, "dfa_minimize_brzozowski.c"),
		"-I"+filepath.Join(cdfaDir, "include"),
		"-Wall", "-Wextra", "-std=c11", "-O2", "-mcmodel=medium",
		"-DNFA2DFA_DEBUG=0", "-DNFA2DFA_VERBOSE=0")
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("failed to build nfa2dfa: %w", err)
	}

	// Build dfa_test_new (new comprehensive test binary that reads DFA from file)
	fmt.Println("Building dfa_test_new...")
	buildCmd = exec.Command("gcc", "-o", dfaTestNew,
		"-DFA_EVAL_DEBUG=0",
		filepath.Join(cdfaSrcDir, "dfa_eval.c"),
		filepath.Join(cdfaSrcDir, "dfa_loader.c"),
		filepath.Join(cdfaSrcDir, "dfa_test.c"),
		"-I"+filepath.Join(cdfaDir, "include"),
		"-lm", "-O2")
	buildCmd.Dir = cdfaDir
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("failed to build dfa_test_new: %w", err)
	}

	// Define test groups with their patterns files
	testGroups := []struct {
		name         string
		patternsFile string
		testArgs     []string
		optional     bool // if true, continue even if this group fails
	}{
		{
			name:         "Main Safe Commands",
			patternsFile: "patterns_safe_commands.txt",
			testArgs:     []string{},
			optional:     false,
		},
		{
			name:         "Quantifier Tests",
			patternsFile: "patterns_quantifier_test.txt",
			testArgs:     []string{"--quantifier-test"},
			optional:     false,
		},
		{
			name:         "Comprehensive Quantifier Tests",
			patternsFile: "patterns_quantifier_comprehensive.txt",
			testArgs:     []string{"--comprehensive-quantifier-test", "--quiet"},
			optional:     true,
		},
		{
			name:         "Capture Pattern Tests",
			patternsFile: "patterns_with_captures.txt",
			testArgs:     []string{"--capture-test"},
			optional:     true,
		},
		{
			name:         "Dangerous Commands (Negative Tests)",
			patternsFile: "patterns_dangerous_commands.txt",
			testArgs:     []string{"--negative-test"},
			optional:     true,
		},
		{
			name:         "Space Character Tests",
			patternsFile: "patterns_space_test.txt",
			testArgs:     []string{"--space-test"},
			optional:     true,
		},
		{
			name:         "Digit Specificity Tests",
			patternsFile: "patterns_digit_test.txt",
			testArgs:     []string{"--digit-test"},
			optional:     true,
		},
		{
			name:         "Acceptance Category Isolation Tests",
			patternsFile: "patterns_acceptance_category_test.txt",
			testArgs:     []string{"--acceptance-test"},
			optional:     true,
		},
	}

	// Track failures across all groups
	var failedGroups []string

	// Run each test group
	for _, group := range testGroups {
		patternsPath := filepath.Join(cdfaDir, group.patternsFile)

		// Skip if patterns file doesn't exist
		if _, err := os.Stat(patternsPath); os.IsNotExist(err) {
			fmt.Printf("Skipping %s - patterns file not found: %s\n", group.name, group.patternsFile)
			continue
		}

		fmt.Printf("\n=== %s ===\n", group.name)
		fmt.Printf("Patterns: %s\n", group.patternsFile)

		// Validate patterns before building NFA
		validateCmd := exec.Command(nfaBuilder, "--validate-only", patternsPath)
		validateCmd.Dir = cdfaDir
		validateCmd.Stdout = os.Stdout
		validateCmd.Stderr = os.Stderr
		if err := validateCmd.Run(); err != nil {
			if group.optional {
				fmt.Printf("Skipping %s due to pattern validation error: %v\n", group.name, err)
				continue
			}
			failedGroups = append(failedGroups, fmt.Sprintf("%s (pattern validation)", group.name))
			fmt.Printf("ERROR: Pattern validation failed for %s: %v\n", group.name, err)
			continue
		}

		// Generate NFA (alphabet is now constructed internally by nfa_builder)
		nfaFile := filepath.Join(cdfaDir, "test_group.nfa")
		genNfa := exec.Command(nfaBuilder,
			patternsPath,
			nfaFile)
		genNfa.Dir = cdfaDir
		genNfa.Stdout = os.Stdout
		genNfa.Stderr = os.Stderr
		if err := genNfa.Run(); err != nil {
			if group.optional {
				fmt.Printf("Skipping %s due to NFA generation error: %v\n", group.name, err)
				continue
			}
			failedGroups = append(failedGroups, fmt.Sprintf("%s (NFA generation)", group.name))
			fmt.Printf("ERROR: Failed to generate NFA for %s: %v\n", group.name, err)
			continue
		}

		// Generate DFA
		dfaFile := filepath.Join(cdfaDir, "test_group.dfa")
		genDfa := exec.Command(nfa2dfa, nfaFile, dfaFile)
		genDfa.Dir = cdfaDir
		genDfa.Stdout = os.Stdout
		genDfa.Stderr = os.Stderr
		if err := genDfa.Run(); err != nil {
			if group.optional {
				fmt.Printf("Skipping %s due to DFA generation error: %v\n", group.name, err)
				continue
			}
			failedGroups = append(failedGroups, fmt.Sprintf("%s (DFA generation)", group.name))
			fmt.Printf("ERROR: Failed to generate DFA for %s: %v\n", group.name, err)
			continue
		}

		// Run tests
		cmd := exec.Command(dfaTestNew, append(group.testArgs, dfaFile)...)
		cmd.Dir = cdfaDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if testErr := cmd.Run(); testErr != nil {
			if !group.optional {
				failedGroups = append(failedGroups, group.name)
			}
			// Continue to next group even if this one failed
			fmt.Printf("NOTE: Tests for %s had failures\n", group.name)
		}
	}

	// Report any failures
	if len(failedGroups) > 0 {
		fmt.Printf("\n=== Failed Test Groups ===\n")
		for _, name := range failedGroups {
			fmt.Printf("  - %s\n", name)
		}
		return fmt.Errorf("some test groups failed")
	}

	// Build shell_tokenizer_test if needed
	if _, err := os.Stat(shellTest); os.IsNotExist(err) {
		fmt.Println("\nBuilding shell_tokenizer_test...")
		buildCmd := exec.Command("gcc", "-o", shellTest,
			filepath.Join(cdfaSrcDir, "shell_tokenizer_test.c"),
			filepath.Join(cdfaSrcDir, "shell_tokenizer.c"),
			filepath.Join(cdfaSrcDir, "shell_tokenizer_ext.c"),
			"-I"+filepath.Join(cdfaDir, "include"),
			"-O2")
		buildCmd.Dir = cdfaDir
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr
		if err := buildCmd.Run(); err != nil {
			return fmt.Errorf("failed to build shell_tokenizer_test: %w", err)
		}
	}

	// Run shell_tokenizer_test
	fmt.Println("\n=== Shell Tokenizer Tests ===")
	cmd := exec.Command(shellTest)
	cmd.Dir = cdfaDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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
