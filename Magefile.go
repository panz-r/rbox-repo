//go:build mage
// +build mage

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/magefile/mage/mg"
)

// Default target
var Default = Build

// BuildDependencies builds base C libraries
func BuildDependencies() error {
	mg.Deps(ValidatePatterns)
	
	wd, _ := os.Getwd()
	os.Setenv("CGO_ENABLED", "1")
	os.MkdirAll("bin", 0755)
	
	if err := runMake(filepath.Join(wd, "c-dfa")); err != nil {
		return err
	}
	if err := runMake(filepath.Join(wd, "shellsplit")); err != nil {
		return err
	}
	if err := runMake(filepath.Join(wd, "rbox-protocol")); err != nil {
		return err
	}
	return nil
}

// BuildDFA builds the DFA data for the client library
// Depends on BuildDependencies which creates the nfa tools
func BuildDFA() error {
	mg.Deps(BuildDependencies)
	
	wd, _ := os.Getwd()
	os.Setenv("CGO_ENABLED", "1")
	
	fmt.Println("=== Building libreadonlybox_client.so ===")
	
	// Build nfa_builder
	nfaBuilder := filepath.Join(wd, "c-dfa/tools/nfa_builder")
	os.Remove(nfaBuilder)
	cmd := exec.Command("gcc", "-o", nfaBuilder,
		filepath.Join(wd, "c-dfa/tools/nfa_builder.c"),
		filepath.Join(wd, "c-dfa/tools/pattern_order.c"),
		filepath.Join(wd, "c-dfa/tools/multi_target_array.c"),
		"-I"+filepath.Join(wd, "c-dfa/include"),
		"-Wall", "-Wextra", "-std=c11", "-O2")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	
	// Build nfa2dfa
	nfa2dfa := filepath.Join(wd, "c-dfa/tools/nfa2dfa_advanced")
	if _, err := os.Stat(nfa2dfa); os.IsNotExist(err) {
		os.Remove(nfa2dfa)
		cmd = exec.Command("gcc", "-o", nfa2dfa,
			filepath.Join(wd, "c-dfa/tools/nfa2dfa.c"),
			filepath.Join(wd, "c-dfa/tools/pattern_order.c"),
			filepath.Join(wd, "c-dfa/tools/multi_target_array.c"),
			filepath.Join(wd, "c-dfa/tools/dfa_minimize.c"),
			filepath.Join(wd, "c-dfa/tools/dfa_minimize_brzozowski.c"),
			filepath.Join(wd, "c-dfa/tools/dfa_layout.c"),
			filepath.Join(wd, "c-dfa/tools/dfa_compress.c"),
			"-I"+filepath.Join(wd, "c-dfa/include"),
			"-Wall", "-Wextra", "-std=c11", "-O2")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	
	clientDir := filepath.Join(wd, "internal/client")
	
	// Generate NFA
	cmd = exec.Command(nfaBuilder, 
		filepath.Join(clientDir, "rbox_client_safe_commands.txt"),
		filepath.Join(clientDir, "readonlybox.nfa"))
	cmd.Dir = clientDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	
	// Generate DFA
	cmd = exec.Command(nfa2dfa, 
		filepath.Join(clientDir, "readonlybox.nfa"),
		filepath.Join(clientDir, "readonlybox.dfa"))
	cmd.Dir = clientDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	
	// Build dfa2c_array
	dfa2cArray := filepath.Join(clientDir, "dfa2c_array")
	if _, err := os.Stat(dfa2cArray); os.IsNotExist(err) {
		cmd = exec.Command("gcc", "-o", dfa2cArray, filepath.Join(clientDir, "dfa2c_array.c"),
			"-Wall", "-Wextra", "-std=c11", "-O2")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	
	// Generate C array
	dfaCArray := filepath.Join(clientDir, "readonlybox_dfa.c")
	cmd = exec.Command(dfa2cArray, 
		filepath.Join(clientDir, "readonlybox.dfa"),
		dfaCArray, "readonlybox_dfa_data")
	cmd.Dir = clientDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	
	// Copy to dfa_static_data.c
	copyFile(dfaCArray, filepath.Join(clientDir, "dfa_static_data.c"))
	
	// Compile object files needed for Go binary linking
	cflags := fmt.Sprintf("-I%s -I%s -I%s -O2", 
		filepath.Join(wd, "c-dfa/include"),
		filepath.Join(wd, "internal/client"),
		filepath.Join(wd, "shellsplit/include"))
	
	// Compile dfa.o
	cmd = exec.Command("gcc", "-c", "-o", filepath.Join(clientDir, "dfa.o"),
		filepath.Join(clientDir, "dfa.c"), cflags)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	
	// Compile readonlybox_dfa_data.o
	cmd = exec.Command("gcc", "-c", "-o", filepath.Join(clientDir, "readonlybox_dfa_data.o"),
		dfaCArray, cflags)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	
	// Compile dfa_eval.o
	cmd = exec.Command("gcc", "-c", "-o", filepath.Join(clientDir, "dfa_eval.o"),
		filepath.Join(wd, "c-dfa/src/dfa_eval.c"), cflags)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	
	// Build shared library
	outputFile := filepath.Join(wd, "bin", "libreadonlybox_client.so")
	cmd = exec.Command("gcc", "-shared", "-fPIC", "-O2", "-DFA_EVAL_DEBUG=0", "-o", outputFile,
		filepath.Join(clientDir, "client.c"),
		filepath.Join(clientDir, "dfa.c"),
		filepath.Join(clientDir, "dfa_static_data.c"),
		filepath.Join(wd, "c-dfa/src/dfa_eval.c"),
		filepath.Join(wd, "shellsplit/src/shell_tokenizer.c"),
		filepath.Join(wd, "shellsplit/src/shell_tokenizer_full.c"),
		"-I"+filepath.Join(wd, "c-dfa/include"),
		"-I"+filepath.Join(wd, "shellsplit/include"),
		"-lpthread", "-ldl")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// BuildBinaries builds the main binaries
func BuildBinaries() error {
	mg.Deps(BuildDFA)
	
	wd, _ := os.Getwd()
	os.Setenv("CGO_ENABLED", "1")
	
	// Force rebuild if DFA .c file is newer than .so
	dfaC := filepath.Join(wd, "internal/client/readonlybox_dfa.c")
	dfaSo := filepath.Join(wd, "bin/libreadonlybox_client.so")
	dfaStat, err := os.Stat(dfaC)
	if err == nil {
		if soStat, err := os.Stat(dfaSo); err != nil || dfaStat.ModTime().After(soStat.ModTime()) {
			// DFA is newer, force rebuild of .so
			os.RemoveAll(dfaSo)
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
	if err := runMake(filepath.Join(wd, "rbox-wrap")); err != nil {
		return err
	}
	
	// rbox-server (Go with C library)
	cmd := exec.Command("go", "build", "-tags", "cgo",
		"-o", filepath.Join(wd, "bin", "readonlybox-server"))
	cmd.Dir = filepath.Join(wd, "rbox-server")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("readonlybox-server: %w", err)
	}
	
	// readonlybox-ptrace
	if err := runMake(filepath.Join(wd, "cmd/readonlybox-ptrace")); err != nil {
		return err
	}
	copyFile(filepath.Join(wd, "cmd/readonlybox-ptrace", "readonlybox-ptrace"), 
		filepath.Join(wd, "bin", "readonlybox-ptrace"))
	
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
		return err
	}
	if err := runMakeClean(filepath.Join(wd, "shellsplit")); err != nil {
		return err
	}
	if err := runMakeClean(filepath.Join(wd, "rbox-protocol")); err != nil {
		return err
	}
	if err := runMakeClean(filepath.Join(wd, "cmd/readonlybox-ptrace")); err != nil {
		return err
	}
	
	// Clean generated DFA files
	os.RemoveAll(filepath.Join(wd, "internal/client/readonlybox.nfa"))
	os.RemoveAll(filepath.Join(wd, "internal/client/readonlybox.dfa"))
	os.RemoveAll(filepath.Join(wd, "internal/client/readonlybox_dfa.c"))
	os.RemoveAll(filepath.Join(wd, "internal/client/dfa_static_data.c"))
	os.RemoveAll(filepath.Join(wd, "internal/client/dfa2c_array"))
	
	// Clean nfa_builder and nfa2dfa tools
	os.RemoveAll(filepath.Join(wd, "c-dfa/tools/nfa_builder"))
	os.RemoveAll(filepath.Join(wd, "c-dfa/tools/nfa2dfa_advanced"))
	
	// Clean any stale binaries in project root
	os.RemoveAll(filepath.Join(wd, "readonlybox"))
	os.RemoveAll(filepath.Join(wd, "readonlybox-server"))
	os.RemoveAll(filepath.Join(wd, "readonlybox-ptrace"))
	os.RemoveAll(filepath.Join(wd, "libreadonlybox_client.so"))
	
	fmt.Println("Clean complete")
	return nil
}

// Test runs all tests
func Test() error {
	mg.Deps(Build)
	
	// Run rbox-protocol tests
	if err := runMake("rbox-protocol"); err != nil {
		return err
	}
	
	// Run rbox-wrap tests
	if err := runMake("rbox-wrap"); err != nil {
		return err
	}
	
	return nil
}

// ValidatePatterns validates command patterns
func ValidatePatterns() error {
	fmt.Println("Validating patterns...")
	wd, _ := os.Getwd()
	
	nfaBuilder := filepath.Join(wd, "c-dfa/tools/nfa_builder")
	if _, err := os.Stat(nfaBuilder); os.IsNotExist(err) {
		cmd := exec.Command("gcc", "-o", nfaBuilder,
			filepath.Join(wd, "c-dfa/tools/nfa_builder.c"),
			filepath.Join(wd, "c-dfa/tools/pattern_order.c"),
			filepath.Join(wd, "c-dfa/tools/multi_target_array.c"),
			"-I"+filepath.Join(wd, "c-dfa/include"),
			"-Wall", "-Wextra", "-std=c11", "-O2")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	
	cmd := exec.Command(nfaBuilder, "--validate-only", 
		filepath.Join(wd, "internal/client/rbox_client_safe_commands.txt"))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runMake(dir string) error {
	cmd := exec.Command("make")
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runTests() error {
	// Run unit tests
	cmd := exec.Command("go", "test", "./test/...")
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
