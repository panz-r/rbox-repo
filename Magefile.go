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
	wd, _ := os.Getwd()
	os.Setenv("CGO_ENABLED", "1")
	os.MkdirAll("bin", 0755)

	// Build c-dfa FIRST (produces tools needed for pattern validation)
	if err := runMake(filepath.Join(wd, "c-dfa")); err != nil {
		return err
	}

	// Now validate patterns (needs nfa_builder from c-dfa)
	mg.Deps(ValidatePatterns)

	if err := runMake(filepath.Join(wd, "shellsplit")); err != nil {
		return err
	}
	if err := runMake(filepath.Join(wd, "rbox-protocol")); err != nil {
		return err
	}
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

// Depends on BuildDependencies which creates the nfa tools
func BuildDFA() error {
	mg.Deps(BuildDependencies)

	wd, _ := os.Getwd()
	os.Setenv("CGO_ENABLED", "1")

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
			return err
		}
	}

	// Step 2: NFA → DFA
	if needsRebuild(dfaFile, nfaFile) {
		cmd := exec.Command(nfa2dfa, nfaFile, dfaFile)
		cmd.Dir = clientDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	// Step 3: DFA → C array
	if needsRebuild(cArrayFile, dfaFile) {
		cmd := exec.Command(dfa2cArray, dfaFile, cArrayFile, "readonlybox_dfa_data")
		cmd.Dir = clientDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}

	// Step 4: Copy to dfa_static_data.c
	if needsRebuild(staticDataFile, cArrayFile) {
		copyFile(cArrayFile, staticDataFile)
	}

	// Step 5: Compile shared library
	if needsRebuild(outputFile, staticDataFile,
		filepath.Join(clientDir, "client.c"),
		filepath.Join(clientDir, "dfa.c"),
		filepath.Join(wd, "c-dfa/src/dfa_eval.c"),
		filepath.Join(wd, "shellsplit/src/shell_tokenizer.c"),
		filepath.Join(wd, "shellsplit/src/shell_tokenizer_full.c")) {

		fmt.Println("=== Building libreadonlybox_client.so ===")
		cmd := exec.Command("gcc", "-shared", "-fPIC", "-O2", "-DFA_EVAL_DEBUG=0", "-o", outputFile,
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
			return err
		}
	}

	return nil
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

	// Force rebuild if rbox-protocol library is newer than binary
	protoLib := filepath.Join(wd, "rbox-protocol/librbox_protocol.a")
	serverBin := filepath.Join(wd, "bin", "readonlybox-server")
	if libStat, err := os.Stat(protoLib); err == nil {
		if binStat, err := os.Stat(serverBin); err != nil || libStat.ModTime().After(binStat.ModTime()) {
			os.RemoveAll(serverBin)
		}
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
	if err := runMake(filepath.Join(wd, "rbox-ptrace")); err != nil {
		return err
	}
	copyFile(filepath.Join(wd, "rbox-ptrace", "readonlybox-ptrace"),
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
	if err := runMakeClean(filepath.Join(wd, "rbox-ptrace")); err != nil {
		return err
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

	// nfa_builder is already built by make c-dfa
	nfaBuilder := filepath.Join(wd, "c-dfa/tools/nfa_builder")

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
