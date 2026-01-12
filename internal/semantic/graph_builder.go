package semantic

import (
	"strings"
)

// OperationGraphBuilder builds operation graphs from parsed commands
type OperationGraphBuilder struct {
	// Can add configuration here
}

// BuildOperationGraph builds an operation graph from command and shell operations
func (ogb *OperationGraphBuilder) BuildOperationGraph(
	command string,
	cmdOperations []SemanticOperation,
	shellOperations []SemanticOperation,
) *OperationGraph {
	graph := &OperationGraph{
		Command:     command,
		Operations:  make([]SemanticOperation, 0),
		DataFlow:    make([]DataFlowEdge, 0),
		TempFiles:   make([]TempFileNode, 0),
	}

	// Combine command and shell operations
	graph.Operations = append(graph.Operations, cmdOperations...)
	graph.Operations = append(graph.Operations, shellOperations...)

	// Build data flow edges
	ogb.buildDataFlowEdges(graph)

	// Identify temp files
	ogb.identifyTempFiles(graph)

	// Calculate risk score
	graph.RiskScore = ogb.calculateRiskScore(graph)

	return graph
}

func (ogb *OperationGraphBuilder) buildDataFlowEdges(graph *OperationGraph) {
	if len(graph.Operations) == 0 {
		return
	}

	inputIndices := make([]int, 0)
	outputIndices := make([]int, 0)

	for i, op := range graph.Operations {
		if op.OperationType == OpRead {
			inputIndices = append(inputIndices, i)
		} else if isWriteOperation(op.OperationType) {
			outputIndices = append(outputIndices, i)
		}
	}

	// Connect inputs to outputs
	for _, inputIdx := range inputIndices {
		for _, outputIdx := range outputIndices {
			graph.DataFlow = append(graph.DataFlow, DataFlowEdge{
				FromOperation: inputIdx,
				ToOperation:   outputIdx,
				DataType:      "processed",
				Volume:        1024 * 1024, // 1MB default
			})
		}
	}
}

func (ogb *OperationGraphBuilder) identifyTempFiles(graph *OperationGraph) {
	tempFileMap := make(map[string]*TempFileNode)

	for i, op := range graph.Operations {
		if isTempFilePath(op.TargetPath) {
			if node, exists := tempFileMap[op.TargetPath]; exists {
				node.Operations = append(node.Operations, i)
			} else {
				tempFileMap[op.TargetPath] = &TempFileNode{
					Path:        op.TargetPath,
					Operations:  []int{i},
					AutoCleanup: true,
					MaxSize:     10 * 1024 * 1024, // 10MB default
				}
			}
		}
	}

	// Convert map to slice
	for _, node := range tempFileMap {
		graph.TempFiles = append(graph.TempFiles, *node)
	}
}

func (ogb *OperationGraphBuilder) calculateRiskScore(graph *OperationGraph) int {
	score := 0

	// Base score based on command
	baseScores := map[string]int{
		"cat": 10, "ls": 5, "grep": 15, "sort": 20,
		"find": 25, "git": 30, "bash": 50, "sh": 50,
	}

	if baseScore, exists := baseScores[graph.Command]; exists {
		score += baseScore
	} else {
		score += 40 // Default for unknown commands
	}

	// Add score for each operation type
	opScores := map[OperationType]int{
		OpRead: 5, OpWrite: 50, OpCreate: 40,
		OpOverwrite: 60, OpRedirect: 30, OpEdit: 45,
	}

	for _, op := range graph.Operations {
		if opScore, exists := opScores[op.OperationType]; exists {
			score += opScore

			// Penalize operations outside safe directories
			if !isSafePath(op.TargetPath) {
				score += 30
			}

			// Penalize operations on system directories
			if isSystemPath(op.TargetPath) {
				score += 50
			}
		}
	}

	// Add score for data flow complexity
	score += len(graph.DataFlow) * 5

	// Add score for temp files
	score += len(graph.TempFiles) * 3

	// Cap the maximum score
	if score > 100 {
		score = 100
	}

	return score
}

// Helper functions

func isWriteOperation(opType OperationType) bool {
	return opType == OpWrite || opType == OpCreate ||
			opType == OpOverwrite || opType == OpRedirect
}

func isTempFilePath(path string) bool {
	return strings.HasPrefix(path, "/tmp/readonlybox_") ||
			strings.Contains(path, "readonlybox") && strings.HasPrefix(path, "/tmp/")
}

func isSafePath(path string) bool {
	safePrefixes := []string{
		"/home/", "/tmp/readonlybox_", "/var/tmp/readonlybox_",
		"/usr/local/readonlybox/", "./", "../",
	}

	for _, prefix := range safePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	return false
}

func isSystemPath(path string) bool {
	systemPaths := []string{
		"/etc/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
		"/lib/", "/usr/lib/", "/boot/", "/dev/", "/proc/",
		"/sys/", "/root/", "/var/lib/", "/var/log/",
	}

	for _, sysPath := range systemPaths {
		if strings.HasPrefix(path, sysPath) {
			return true
		}
	}

	return false
}