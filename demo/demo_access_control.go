package main

import (
	"fmt"

	"github.com/panz/openroutertest/internal/access"
	"github.com/panz/openroutertest/internal/dsl"
)

func main() {
	// Create a demo configuration
	config := dsl.AST{
		BaseDir: "/home/user/project",
		Rules: []dsl.AccessRule{
			{
				Command: "ls",
				Operations: []dsl.FileOperation{
					{OpType: dsl.OpRead},
				},
				Directories: []dsl.DirectoryAccess{
					{
						Path:  "/home/user/project",
						Level: dsl.AccessAt,
					},
					{
						Path:  "/home/user/project/src",
						Level: dsl.AccessSub,
						Depth: 2,
					},
				},
			},
			{
				Command: "cat",
				Operations: []dsl.FileOperation{
					{OpType: dsl.OpRead},
				},
				Directories: []dsl.DirectoryAccess{
					{
						Path:  "/home/user/project",
						Level: dsl.AccessSuper,
						Depth: 1,
					},
				},
			},
			{
				Command: "sort",
				Operations: []dsl.FileOperation{
					{
						OpType:   dsl.OpRedirect,
						Path:     "/tmp/readonlybox_*.txt",
						IsTemp:   true,
					},
				},
				Directories: []dsl.DirectoryAccess{
					{
						Path:  "/home/user/project",
						Level: dsl.AccessAt,
					},
				},
			},
		},
	}

	engine := access.NewAccessControlEngine(config)

	fmt.Println("🔒 ReadOnlyBox Access Control Demo")
	fmt.Println("=================================\n")

	// Test cases
	testCases := []struct {
		cmd      string
		path     string
		opType   dsl.OperationType
		desc     string
	}{
		// ls command tests
		{"ls", "/home/user/project/README.md", dsl.OpRead, "List files in project root"},
		{"ls", "/home/user/project/src/utils/helper.go", dsl.OpRead, "List files in subdirectory"},
		{"ls", "/home/user/project/src/utils/tests/helper_test.go", dsl.OpRead, "List files 2 levels deep"},
		{"ls", "/home/user/project/src/utils/tests/deep/file.go", dsl.OpRead, "List files 3 levels deep (should fail)"},
		{"ls", "/home/user/other/secret.txt", dsl.OpRead, "List files outside project (should fail)"},

		// cat command tests
		{"cat", "/home/user/project/config.yaml", dsl.OpRead, "Read config file"},
		{"cat", "/home/user/.bashrc", dsl.OpRead, "Read file in parent directory"},
		{"cat", "/home/.hidden", dsl.OpRead, "Read file 2 levels up (should fail)"},

		// sort command tests
		{"sort", "/tmp/readonlybox_results.txt", dsl.OpRedirect, "Redirect sort output to temp file"},
		{"sort", "/tmp/other_results.txt", dsl.OpRedirect, "Redirect to non-readonlybox temp (should fail)"},

		// Invalid command
		{"rm", "/home/user/project/important.txt", dsl.OpRead, "Dangerous command (should fail)"},
	}

	for i, tc := range testCases {
		canAccess, err := engine.CanAccess(tc.cmd, tc.path, tc.opType)

		status := "✅ ALLOWED"
		if err != nil {
			status = "❌ DENIED"
		} else if !canAccess {
			status = "❌ DENIED"
		}

		fmt.Printf("%d. %s\n", i+1, tc.desc)
		fmt.Printf("   Command: readonlybox %s %s\n", tc.cmd, tc.path)
		fmt.Printf("   Operation: %s\n", tc.opType)
		fmt.Printf("   Result: %s\n", status)
		if err != nil {
			fmt.Printf("   Reason: %v\n", err)
		}
		fmt.Println()
	}

	// Show allowed commands
	allowedCommands := engine.GetAllowedCommands()
	fmt.Println("📋 Allowed Commands:")
	for _, cmd := range allowedCommands {
		fmt.Printf("   • %s\n", cmd)
	}

	// Show rules for specific command
	fmt.Println("\n📜 Rules for 'ls' command:")
	rules := engine.GetCommandRules("ls")
	for _, rule := range rules {
		fmt.Printf("   Command: %s\n", rule.Command)
		fmt.Printf("   Operations: ")
		for _, op := range rule.Operations {
			fmt.Printf("%s ", op.OpType)
		}
		fmt.Println()
		fmt.Printf("   Directories:\n")
		for _, dir := range rule.Directories {
			fmt.Printf("     - %s (Level: %s", dir.Path, dir.Level)
			if dir.Depth > 0 {
				fmt.Printf(", Depth: %d", dir.Depth)
			}
			fmt.Println(")")
		}
	}

	fmt.Println("\n🎉 Demo completed!")
}