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

// Tools to build
var tools = []string{
	"ro-git", "ro-find", "ro-ls", "ro-cat", "ro-grep", "ro-head", "ro-tail",
	"ro-timeout", "ro-echo", "ro-date", "ro-cd", "ro-bash", "ro-sort", "ro-ulimit",
	"ro-sed", "ro-chmod", "ro-chown", "ro-mkdir", "ro-rmdir", "ro-ln", "ro-mv",
	"ro-cp", "ro-rm", "ro-touch", "ro-dd", "ro-ps", "ro-df", "ro-du", "ro-wc", "ro-uname",
}

// Default target to run when none is specified
var Default = Build

// Build all tools
func Build() error {
	mg.Deps(Clean)
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

	// Step 1: Generate DFA from commands.txt
	dfaToolsDir := "c-dfa/tools"
	dfa2cPath := filepath.Join(dfaToolsDir, "dfa2c")
	commandsTxt := filepath.Join(dfaToolsDir, "commands.txt")
	dfaCArray := filepath.Join(dfaToolsDir, "readonlybox_dfa.c")
	clientDfaData := filepath.Join("internal/client", "dfa_static_data.c")

	// Build dfa2c if needed
	if _, err := os.Stat(dfa2cPath); os.IsNotExist(err) {
		fmt.Println("Building dfa2c...")
		buildCmd := exec.Command("gcc", "-o", dfa2cPath, filepath.Join(dfaToolsDir, "dfa2c.c"))
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr
		if err := buildCmd.Run(); err != nil {
			fmt.Printf("gcc error: %v\n", err)
			return fmt.Errorf("failed to build dfa2c: %w", err)
		}
		info, _ := os.Stat(dfa2cPath)
		fmt.Printf("After gcc: %s exists=%v size=%d\n", dfa2cPath, info != nil, info.Size())
	}

	// Generate DFA C array
	fmt.Println("Generating DFA...")
	dfaBinaryFile := filepath.Join(dfaToolsDir, "readonlybox_dfa.dfa")
	genDfa := exec.Command(dfa2cPath, commandsTxt, dfaBinaryFile, "readonlybox_dfa", dfaCArray)
	wd, _ := os.Getwd()
	genDfa.Dir = wd
	genDfa.Stdout = os.Stdout
	genDfa.Stderr = os.Stderr
	if err := genDfa.Run(); err != nil {
		return fmt.Errorf("failed to generate DFA: %w", err)
	}

	// Copy DFA C array to client directory (dfa2c writes directly there now)
	if err := copyFile(dfaCArray, clientDfaData); err != nil {
		return fmt.Errorf("failed to copy DFA to client: %w", err)
	}

	// Build the client library with DFA
	outputFile := filepath.Join("bin", "libreadonlybox_client.so")
	buildClient := exec.Command("gcc", "-shared", "-fPIC", "-O2", "-o", outputFile,
		filepath.Join("internal/client", "client.c"),
		filepath.Join("internal/client", "dfa.c"),
		filepath.Join("internal/client", "dfa_static_data.c"),
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

// Test all tools
func Test() error {
	if err := UnitTest(); err != nil {
		return err
	}
	return IntegrationTest()
}

// Run unit tests
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

	for _, pkg := range packages {
		cmd := exec.Command("go", "test", "-v", pkg)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("unit tests failed for %s: %w", pkg, err)
		}
	}

	return nil
}

// Run integration tests
func IntegrationTest() error {
	fmt.Println("Running integration tests...")

	cmd := exec.Command("go", "test", "-v", "./test/...")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Quick test (original simple test)
func QuickTest() error {
	mg.Deps(Build)

	fmt.Println("Testing ro-git with safe commands...")
	runCmd("./bin/ro-git", "--version")

	fmt.Println("Testing ro-git with blocked commands...")
	runCmd("./bin/ro-git", "add", ".")

	fmt.Println("Testing ro-find with safe commands...")
	runCmd("./bin/ro-find", ".", "-name", "*.go", "-type", "f")

	fmt.Println("Testing ro-find with blocked commands...")
	runCmd("./bin/ro-find", ".", "-name", "*.tmp", "-exec", "rm", "{}", `;`)

	fmt.Println("Testing ro-ls with safe commands...")
	runCmd("./bin/ro-ls", "-la")

	fmt.Println("Testing ro-ls with blocked commands...")
	runCmd("./bin/ro-ls", ">output.txt")

	fmt.Println("Testing ro-cat with safe commands...")
	runCmd("./bin/ro-cat", "Makefile")

	fmt.Println("Testing ro-cat with blocked commands...")
	runCmd("./bin/ro-cat", ">output.txt")

	fmt.Println("Testing ro-grep with safe commands...")
	runCmd("./bin/ro-grep", "-r", "package", ".")

	fmt.Println("Testing ro-grep with blocked commands...")
	runCmd("./bin/ro-grep", ">output.txt")

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

	for _, tool := range tools {
		cmd := exec.Command("go", "build", "-o", filepath.Join("bin", tool), "./"+filepath.Join("cmd", tool))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to build %s: %w", tool, err)
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
