package access

import (
	"fmt"
	"path/filepath"
	"github.com/panz/openroutertest/internal/semantic"
	"github.com/panz/openroutertest/internal/dsl"
)

// ValidateOperationGraph validates an operation graph against access control rules
func (ace *AccessControlEngine) ValidateOperationGraph(graph *semantic.OperationGraph) (bool, error) {
	// Early exit for high-risk commands
	if graph.RiskScore > 80 {
		return false, fmt.Errorf("command too risky (score: %d)", graph.RiskScore)
	}

	// Validate each operation against access rules
	for _, op := range graph.Operations {
		// Skip read operations for performance (they're usually safe)
		if op.OperationType == semantic.OpRead {
			continue
		}

		// Get the directory context for this operation
		context := getContextForOperation(op, ace.BaseDir)

		// Convert to our internal operation type
		internalOp := convertToInternalOperation(op)

		// Check if this operation is allowed
		allowed, err := ace.CanPerform(graph.Command, internalOp, context)
		if !allowed {
			if err != nil {
				return false, fmt.Errorf("operation denied: %v", err)
			}
			return false, nil
		}
	}

	// Validate temp files
	for _, tempFile := range graph.TempFiles {
		for _, opIndex := range tempFile.Operations {
			op := graph.Operations[opIndex]
			if allowed, err := ace.CanAccess(graph.Command, tempFile.Path, convertOpType(op.OperationType)); !allowed {
				if err != nil {
					return false, fmt.Errorf("temp file operation denied: %v", err)
				}
				return false, nil
			}
		}
	}

	return true, nil
}

// Helper functions

func getContextForOperation(op semantic.SemanticOperation, baseDir string) string {
	if op.IsTemp {
		return baseDir
	}

	context := filepath.Dir(op.TargetPath)
	if context == "." {
		return baseDir
	}
	return context
}

func convertToInternalOperation(op semantic.SemanticOperation) dsl.FileOperation {
	return dsl.FileOperation{
		OpType:      convertOpType(op.OperationType),
		Path:        op.TargetPath,
		IsTemp:      op.IsTemp,
		CreatedByUs: op.CreatedByUs,
	}
}

func convertOpType(opType semantic.OperationType) dsl.OperationType {
	switch opType {
	case semantic.OpRead:
		return dsl.OpRead
	case semantic.OpWrite:
		return dsl.OpWrite
	case semantic.OpCreate:
		return dsl.OpCreate
	case semantic.OpOverwrite:
		return dsl.OpOverwrite
	case semantic.OpRedirect:
		return dsl.OpRedirect
	case semantic.OpEdit:
		return dsl.OpEdit
	default:
		return dsl.OpRead
	}
}