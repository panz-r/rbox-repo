package semantic

import (
	"fmt"
	"strings"
)

// KubectlCommand represents a parsed kubectl command
type KubectlCommand struct {
	SubCommand    string
	Resource      string
	Name          string
	Namespace     string
	Options       map[string]interface{}
	Labels        map[string]string
	Annotations   map[string]string
	Filename      string
	Output        string
	Verbose       bool
	AllNamespaces bool
	Force         bool
	GracePeriod   int
	Timeout       string
	Selector      string
}

// KubectlParser parses kubectl commands
type KubectlParser struct {
	utils *ParserUtils
}

// NewKubectlParser creates a new KubectlParser
func NewKubectlParser() *KubectlParser {
	return &KubectlParser{
		utils: ParserUtilsInstance,
	}
}

// ParseArguments implements CommandParser for kubectl commands
func (k *KubectlParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified for kubectl parser")
	}

	cmd := &KubectlCommand{
		Options:     make(map[string]interface{}),
		Labels:      make(map[string]string),
		Annotations: make(map[string]string),
	}

	i := 0

	// Parse global flags
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-n", "--namespace":
			if i+1 < len(args) {
				cmd.Namespace = args[i+1]
				cmd.Options["namespace"] = args[i+1]
				i += 2
				continue
			}
		case "-A", "--all-namespaces":
			cmd.AllNamespaces = true
			cmd.Options["all_namespaces"] = true
		case "-v", "--verbose":
			cmd.Verbose = true
			cmd.Options["verbose"] = true
		case "--kubeconfig":
			if i+1 < len(args) {
				cmd.Options["kubeconfig"] = args[i+1]
				i += 2
				continue
			}
		case "--context":
			if i+1 < len(args) {
				cmd.Options["context"] = args[i+1]
				i += 2
				continue
			}
		case "--as":
			if i+1 < len(args) {
				cmd.Options["as"] = args[i+1]
				i += 2
				continue
			}
		case "-o", "--output":
			if i+1 < len(args) {
				cmd.Output = args[i+1]
				cmd.Options["output"] = args[i+1]
				i += 2
				continue
			}
		case "--dry-run":
			cmd.Options["dry_run"] = true
		case "--grace-period":
			if i+1 < len(args) {
				cmd.GracePeriod = i + 1
				cmd.Options["grace_period"] = args[i+1]
				i += 2
				continue
			}
		case "--timeout":
			if i+1 < len(args) {
				cmd.Timeout = args[i+1]
				cmd.Options["timeout"] = args[i+1]
				i += 2
				continue
			}
		case "-l", "--selector":
			if i+1 < len(args) {
				cmd.Selector = args[i+1]
				cmd.Options["selector"] = args[i+1]
				i += 2
				continue
			}
		case "--force":
			cmd.Force = true
			cmd.Options["force"] = true
		case "--help":
			cmd.Options["help"] = true
			return cmd, nil
		}
		i++
	}

	// Get subcommand
	if i < len(args) {
		cmd.SubCommand = args[i]
		i++
	} else {
		return nil, fmt.Errorf("no kubectl subcommand specified")
	}

	// Parse subcommand-specific args
	switch cmd.SubCommand {
	case "get", "describe", "delete", "edit", "label", "annotate", "scale", "expose":
		i = k.parseResourceCommand(args, i, cmd)
	case "apply", "create", "replace", "patch":
		i = k.parseApplyCommand(args, i, cmd)
	case "logs", "exec", "port-forward", "attach":
		i = k.parsePodCommand(args, i, cmd)
	case "rollout":
		i = k.parseRolloutCommand(args, i, cmd)
	case "top":
		i = k.parseTopCommand(args, i, cmd)
	case "auth", "config", "cluster-info", "api-resources", "api-versions", "plugin", "version":
		// Informational commands
		i = k.parseInfoCommand(args, i, cmd)
	}

	return cmd, nil
}

// parseResourceCommand parses resource-related subcommands
func (k *KubectlParser) parseResourceCommand(args []string, i int, cmd *KubectlCommand) int {
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-l", "--selector":
			if i+1 < len(args) {
				cmd.Selector = args[i+1]
				cmd.Options["selector"] = args[i+1]
				i += 2
				continue
			}
		case "-o", "--output":
			if i+1 < len(args) {
				cmd.Output = args[i+1]
				cmd.Options["output"] = args[i+1]
				i += 2
				continue
			}
		case "-w", "--watch":
			cmd.Options["watch"] = true
		case "--all":
			cmd.Options["all"] = true
		case "--show-labels":
			cmd.Options["show_labels"] = true
		case "--show-annotations":
			cmd.Options["show_annotations"] = true
		}
		i++
	}

	// Parse resource type and name
	if i < len(args) {
		resourceName := args[i]
		i++

		// Check if it's a resource type (pods, services, etc.) or a resource type with name
		if strings.Contains(resourceName, "/") {
			parts := strings.SplitN(resourceName, "/", 2)
			cmd.Resource = parts[0]
			cmd.Name = parts[1]
		} else if i < len(args) && !strings.HasPrefix(args[i], "-") {
			// Next arg is the name
			cmd.Resource = resourceName
			cmd.Name = args[i]
			i++
		} else {
			cmd.Resource = resourceName
		}
	}

	return i
}

// parseApplyCommand parses apply/create subcommands
func (k *KubectlParser) parseApplyCommand(args []string, i int, cmd *KubectlCommand) int {
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-f", "--filename":
			if i+1 < len(args) {
				cmd.Filename = args[i+1]
				cmd.Options["filename"] = args[i+1]
				i += 2
				continue
			}
		case "-k":
			if i+1 < len(args) {
				cmd.Options["kustomize"] = args[i+1]
				i += 2
				continue
			}
		case "--dry-run":
			cmd.Options["dry_run"] = true
		case "--validate":
			if i+1 < len(args) {
				cmd.Options["validate"] = args[i+1]
				i += 2
				continue
			}
		case "--force":
			cmd.Force = true
			cmd.Options["force"] = true
		case "--record":
			cmd.Options["record"] = true
		}
		i++
	}

	return i
}

// parsePodCommand parses pod-related subcommands
func (k *KubectlParser) parsePodCommand(args []string, i int, cmd *KubectlCommand) int {
	cmd.Resource = "pod"

	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-c", "--container":
			if i+1 < len(args) {
				cmd.Options["container"] = args[i+1]
				i += 2
				continue
			}
		case "-p", "--pod":
			if i+1 < len(args) {
				cmd.Name = args[i+1]
				i += 2
				continue
			}
		case "-f", "--filename":
			if i+1 < len(args) {
				cmd.Filename = args[i+1]
				i += 2
				continue
			}
		}
		i++
	}

	// Get pod name if not set
	if cmd.Name == "" && i < len(args) && !strings.HasPrefix(args[i], "-") {
		cmd.Name = args[i]
	}

	return i
}

// parseRolloutCommand parses rollout subcommands
func (k *KubectlParser) parseRolloutCommand(args []string, i int, cmd *KubectlCommand) int {
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-f", "--filename":
			if i+1 < len(args) {
				cmd.Filename = args[i+1]
				i += 2
				continue
			}
		case "--to-revision":
			if i+1 < len(args) {
				cmd.Options["to_revision"] = args[i+1]
				i += 2
				continue
			}
		}
		i++
	}

	// Get resource type and name
	if i < len(args) {
		arg := args[i]
		i++

		if strings.Contains(arg, "/") {
			parts := strings.SplitN(arg, "/", 2)
			cmd.Resource = parts[0]
			cmd.Name = parts[1]
		} else {
			cmd.Resource = arg
			if i < len(args) && !strings.HasPrefix(args[i], "-") {
				cmd.Name = args[i]
			}
		}
	}

	return i
}

// parseTopCommand parses top subcommands
func (k *KubectlParser) parseTopCommand(args []string, i int, cmd *KubectlCommand) int {
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-A", "--all-namespaces":
			cmd.AllNamespaces = true
			cmd.Options["all_namespaces"] = true
		case "-n", "--namespace":
			if i+1 < len(args) {
				cmd.Namespace = args[i+1]
				i += 2
				continue
			}
		}
		i++
	}

	// Get resource type
	if i < len(args) && !strings.HasPrefix(args[i], "-") {
		cmd.Resource = args[i]
		i++

		// Get resource name if present
		if i < len(args) && !strings.HasPrefix(args[i], "-") {
			cmd.Name = args[i]
		}
	}

	return i
}

// parseInfoCommand parses informational subcommands
func (k *KubectlParser) parseInfoCommand(args []string, i int, cmd *KubectlCommand) int {
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "--help":
			cmd.Options["help"] = true
			return i
		}
		i++
	}
	return i
}

// GetSemanticOperations implements CommandParser for kubectl commands
func (k *KubectlParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*KubectlCommand)
	if !ok {
		return nil, fmt.Errorf("invalid kubectl command type")
	}

	builder := k.utils.SemanticOperationBuilder()
	operations := make([]SemanticOperation, 0)

	// kubectl operations can modify cluster state
	switch cmd.SubCommand {
	case "apply", "create", "replace", "patch":
		operations = k.getModifyOperations(cmd, builder)
	case "delete":
		operations = k.getDeleteOperations(cmd, builder)
	case "edit":
		operations = k.getEditOperations(cmd, builder)
	case "exec":
		operations = k.getExecOperations(cmd, builder)
	case "logs":
		operations = k.getLogsOperations(cmd, builder)
	case "scale":
		operations = k.getScaleOperations(cmd, builder)
	case "rollout":
		operations = k.getRolloutOperations(cmd, builder)
	case "label", "annotate":
		operations = k.getLabelOperations(cmd, builder)
	case "port-forward":
		operations = k.getPortForwardOperations(cmd, builder)
	case "get", "describe":
		operations = k.getReadOperations(cmd, builder)
	default:
		// Default to read for informational commands
		builder.AddReadOperation("kubernetes:"+cmd.SubCommand, "kubectl_info")
		builder = builder.WithParameter("command", "kubectl")
		builder = builder.WithParameter("subcommand", cmd.SubCommand)
	}

	operations = builder.Build()
	return operations, nil
}

func (k *KubectlParser) getModifyOperations(cmd *KubectlCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	if cmd.Filename != "" {
		builder.AddReadOperation("kubernetes:manifest:"+cmd.Filename, "kubectl_apply_manifest")
		builder = builder.WithParameter("command", "kubectl")
		builder = builder.WithParameter("subcommand", cmd.SubCommand)
		builder = builder.WithParameter("filename", cmd.Filename)
		builder = builder.WithParameter("dangerous", true)
		builder = builder.WithParameter("high_risk", true)
		builder = builder.WithParameter("over_approximated", true)
	}

	// Apply creates/modifies resources
	resourceID := k.getResourceID(cmd)
	builder.AddWriteOperation("kubernetes:"+resourceID, "kubectl_apply")
	builder = builder.WithParameter("command", "kubectl")
	builder = builder.WithParameter("subcommand", cmd.SubCommand)
	builder = builder.WithParameter("dangerous", true)
	builder = builder.WithParameter("high_risk", true)
	builder = builder.WithParameter("namespace", cmd.Namespace)
	builder = builder.WithParameter("over_approximated", true)

	if cmd.Force {
		builder.AddWriteOperation("kubernetes:"+resourceID+"/force", "kubectl_force_apply")
		builder = builder.WithParameter("command", "kubectl")
		builder = builder.WithParameter("force", true)
		builder = builder.WithParameter("high_risk", true)
	}

	return builder.Build()
}

func (k *KubectlParser) getDeleteOperations(cmd *KubectlCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	resourceID := k.getResourceID(cmd)
	builder.AddWriteOperation("kubernetes:"+resourceID, "kubectl_delete")
	builder = builder.WithParameter("command", "kubectl")
	builder = builder.WithParameter("subcommand", "delete")
	builder = builder.WithParameter("dangerous", true)
	builder = builder.WithParameter("high_risk", true)
	builder = builder.WithParameter("namespace", cmd.Namespace)
	builder = builder.WithParameter("over_approximated", true)

	if cmd.Force {
		builder.AddWriteOperation("kubernetes:"+resourceID+"/force", "kubectl_force_delete")
		builder = builder.WithParameter("command", "kubectl")
		builder = builder.WithParameter("force", true)
		builder = builder.WithParameter("high_risk", true)
	}

	return builder.Build()
}

func (k *KubectlParser) getEditOperations(cmd *KubectlCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	resourceID := k.getResourceID(cmd)
	builder.AddReadOperation("kubernetes:"+resourceID, "kubectl_edit_read")
	builder = builder.WithParameter("command", "kubectl")
	builder = builder.WithParameter("subcommand", "edit")
	builder = builder.WithParameter("namespace", cmd.Namespace)

	builder.AddWriteOperation("kubernetes:"+resourceID, "kubectl_edit_write")
	builder = builder.WithParameter("command", "kubectl")
	builder = builder.WithParameter("subcommand", "edit")
	builder = builder.WithParameter("dangerous", true)
	builder = builder.WithParameter("high_risk", true)
	builder = builder.WithParameter("over_approximated", true)

	return builder.Build()
}

func (k *KubectlParser) getExecOperations(cmd *KubectlCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	resourceID := k.getResourceID(cmd)
	builder.AddWriteOperation("kubernetes:"+resourceID+"/exec", "kubectl_exec")
	builder = builder.WithParameter("command", "kubectl")
	builder = builder.WithParameter("subcommand", "exec")
	builder = builder.WithParameter("dangerous", true)
	builder = builder.WithParameter("high_risk", true)
	builder = builder.WithParameter("over_approximated", true)

	return builder.Build()
}

func (k *KubectlParser) getLogsOperations(cmd *KubectlCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	resourceID := k.getResourceID(cmd)
	builder.AddReadOperation("kubernetes:"+resourceID+"/logs", "kubectl_logs")
	builder = builder.WithParameter("command", "kubectl")
	builder = builder.WithParameter("subcommand", "logs")
	builder = builder.WithParameter("namespace", cmd.Namespace)
	builder = builder.WithParameter("over_approximated", true)

	return builder.Build()
}

func (k *KubectlParser) getScaleOperations(cmd *KubectlCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	resourceID := k.getResourceID(cmd)
	builder.AddWriteOperation("kubernetes:"+resourceID+"/scale", "kubectl_scale")
	builder = builder.WithParameter("command", "kubectl")
	builder = builder.WithParameter("subcommand", "scale")
	builder = builder.WithParameter("dangerous", true)
	builder = builder.WithParameter("high_risk", true)
	builder = builder.WithParameter("namespace", cmd.Namespace)

	return builder.Build()
}

func (k *KubectlParser) getRolloutOperations(cmd *KubectlCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	resourceID := k.getResourceID(cmd)
	builder.AddWriteOperation("kubernetes:"+resourceID+"/rollout", "kubectl_rollout")
	builder = builder.WithParameter("command", "kubectl")
	builder = builder.WithParameter("subcommand", "rollout")
	builder = builder.WithParameter("dangerous", true)
	builder = builder.WithParameter("high_risk", true)
	builder = builder.WithParameter("namespace", cmd.Namespace)
	builder = builder.WithParameter("over_approximated", true)

	return builder.Build()
}

func (k *KubectlParser) getLabelOperations(cmd *KubectlCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	resourceID := k.getResourceID(cmd)
	builder.AddWriteOperation("kubernetes:"+resourceID+"/labels", "kubectl_label")
	builder = builder.WithParameter("command", "kubectl")
	builder = builder.WithParameter("subcommand", cmd.SubCommand)
	builder = builder.WithParameter("dangerous", true)
	builder = builder.WithParameter("labels", cmd.Labels)
	builder = builder.WithParameter("namespace", cmd.Namespace)

	return builder.Build()
}

func (k *KubectlParser) getPortForwardOperations(cmd *KubectlCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	resourceID := k.getResourceID(cmd)
	builder.AddCreateOperation("kubernetes:"+resourceID+"/port-forward", "kubectl_port_forward")
	builder = builder.WithParameter("command", "kubectl")
	builder = builder.WithParameter("subcommand", "port-forward")
	builder = builder.WithParameter("dangerous", true)
	builder = builder.WithParameter("high_risk", true)
	builder = builder.WithParameter("over_approximated", true)

	return builder.Build()
}

func (k *KubectlParser) getReadOperations(cmd *KubectlCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	resourceID := k.getResourceID(cmd)
	builder.AddReadOperation("kubernetes:"+resourceID, "kubectl_get")
	builder = builder.WithParameter("command", "kubectl")
	builder = builder.WithParameter("subcommand", cmd.SubCommand)
	builder = builder.WithParameter("namespace", cmd.Namespace)
	builder = builder.WithParameter("selector", cmd.Selector)
	builder = builder.WithParameter("output", cmd.Output)

	if cmd.Selector != "" {
		builder = builder.WithParameter("over_approximated", true)
	}

	return builder.Build()
}

func (k *KubectlParser) getResourceID(cmd *KubectlCommand) string {
	resource := cmd.Resource
	if resource == "" {
		resource = "resource"
	}

	ns := cmd.Namespace
	if ns == "" {
		ns = "default"
	}

	name := cmd.Name
	if name == "" {
		name = "*"
	}

	return ns + "/" + resource + "/" + name
}

// GetOperationGraph implements the enhanced CommandParser interface for kubectl commands
func (p *KubectlParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*KubectlCommand)
	if !ok {
		return nil, fmt.Errorf("invalid kubectl command type")
	}

	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("kubectl", operations, []SemanticOperation{})

	return graph, nil
}
