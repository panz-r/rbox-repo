package dsl

// AST represents the abstract syntax tree of the DSL
// This is the core data structure for the access control language
type AST struct {
	Version    string      `yaml:"version"`
	BaseDir    string      `yaml:"base_directory,omitempty"`
	Rules      []AccessRule `yaml:"commands,omitempty"`
	Workflows  []Workflow  `yaml:"workflows,omitempty"`
	TempConfig *TempConfig `yaml:"temp_files,omitempty"`
}

// AccessLevel represents the type of directory access
type AccessLevel int

const (
	AccessAt AccessLevel = iota
	AccessSuper
	AccessSub
)

// DirectoryAccess represents access to a directory hierarchy
type DirectoryAccess struct {
	Path   string     `yaml:"path"`
	Level  AccessLevel `yaml:"level"`
	Depth  int        `yaml:"depth,omitempty"`
}

// OperationType represents the type of file operation
type OperationType int

const (
	OpRead OperationType = iota
	OpEdit
	OpCreate
	OpWrite
	OpRedirect
	OpOverwrite
)

// FileOperation represents a file operation with access rules
type FileOperation struct {
	OpType      OperationType `yaml:"op_type"`
	Path        string        `yaml:"path,omitempty"`
	IsTemp      bool          `yaml:"is_temp,omitempty"`
	CreatedByUs bool          `yaml:"created_by_us,omitempty"`
}

// AccessRule represents a complete access rule for a command
type AccessRule struct {
	Command     string           `yaml:"command"`
	Operations  []FileOperation  `yaml:"operations,omitempty"`
	Directories []DirectoryAccess `yaml:"directories,omitempty"`
}

// Workflow represents a named set of access rules
type Workflow struct {
	Name    string      `yaml:"name"`
	Rules   []AccessRule `yaml:"rules"`
}

// TempConfig represents configuration for temporary file management
type TempConfig struct {
	Pattern     string `yaml:"pattern"`
	MaxSize     string `yaml:"max_size,omitempty"`
	MaxCount    int    `yaml:"max_count,omitempty"`
	AutoCleanup string `yaml:"auto_cleanup,omitempty"`
}

// String representations for debugging
func (a AccessLevel) String() string {
	switch a {
	case AccessAt:
		return "at"
	case AccessSuper:
		return "super"
	case AccessSub:
		return "sub"
	default:
		return "unknown"
	}
}

func (o OperationType) String() string {
	switch o {
	case OpRead:
		return "read"
	case OpEdit:
		return "edit"
	case OpCreate:
		return "create"
	case OpWrite:
		return "write"
	case OpRedirect:
		return "redirect"
	case OpOverwrite:
		return "overwrite"
	default:
		return "unknown"
	}
}