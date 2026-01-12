package semantic

// OperationType represents the type of file operation
type OperationType int

const (
	OpRead OperationType = iota
	OpWrite
	OpCreate
	OpOverwrite
	OpRedirect
	OpEdit
	OpExecute
)

// SemanticOperation represents a single atomic operation
type SemanticOperation struct {
	OperationType OperationType
	TargetPath    string
	IsTemp        bool
	CreatedByUs   bool
	Context       string
	Parameters    map[string]interface{}
}

// OperationGraph represents the complete semantic meaning of a command
type OperationGraph struct {
	Command     string
	Operations  []SemanticOperation
	DataFlow    []DataFlowEdge
	TempFiles   []TempFileNode
	RiskScore   int
}

// DataFlowEdge represents data movement between operations
type DataFlowEdge struct {
	FromOperation int
	ToOperation   int
	DataType      string
	Volume        int
}

// TempFileNode represents a temporary file in the operation graph
type TempFileNode struct {
	Path        string
	Operations  []int
	AutoCleanup bool
	MaxSize     int
}