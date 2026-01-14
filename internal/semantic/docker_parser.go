package semantic

import (
	"fmt"
	"strings"
)

// DockerCommand represents a parsed docker command
type DockerCommand struct {
	SubCommand  string
	Options     map[string]interface{}
	Image       string
	Container   string
	Tag         string
	Path        string
	Network     string
	Volume      []string
	Port        string
	Env         []string
	Detached    bool
	Interactive bool
	Remove      bool
	ForceRemove bool
	Prune       bool
	All         bool
	Filter      string
}

// DockerParser parses docker commands
type DockerParser struct {
	utils *ParserUtils
}

// NewDockerParser creates a new DockerParser
func NewDockerParser() *DockerParser {
	return &DockerParser{
		utils: ParserUtilsInstance,
	}
}

// ParseArguments implements CommandParser for docker commands
func (d *DockerParser) ParseArguments(args []string) (interface{}, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified for docker parser")
	}

	cmd := &DockerCommand{
		Options: make(map[string]interface{}),
	}

	i := 0

	// Parse global options (before subcommand)
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-D", "--debug":
			cmd.Options["debug"] = true
		case "-H", "--host":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing value after -H")
			}
			cmd.Options["host"] = args[i+1]
			i += 2
			continue
		case "-v", "--version":
			cmd.Options["version"] = true
			return cmd, nil
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
		return nil, fmt.Errorf("no docker subcommand specified")
	}

	// Parse subcommand options and arguments
	switch cmd.SubCommand {
	case "run", "container", "exec", "cp", "logs", "stop", "start", "restart", "kill", "rm", "inspect", "stats", "top":
		i = d.parseContainerCommand(args, i, cmd)
	case "image", "build", "pull", "push", "tag", "rmi", "history", "search":
		i = d.parseImageCommand(args, i, cmd)
	case "network", "volume", "plugin", "secret", "config", "swarm", "stack", "service":
		i = d.parseResourceCommand(args, i, cmd)
	case "-compose", "compose":
		i = d.parseComposeCommand(args, i, cmd)
	case "login", "logout", "info", "system", "events", "version":
		// These are informational commands
		i = d.parseInfoCommand(args, i, cmd)
	}

	return cmd, nil
}

// parseContainerCommand parses container-related subcommands
func (d *DockerParser) parseContainerCommand(args []string, i int, cmd *DockerCommand) int {
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-d", "--detach":
			cmd.Detached = true
			cmd.Options["detach"] = true
		case "-it", "-i", "--interactive":
			cmd.Interactive = true
			cmd.Options["interactive"] = true
		case "-t", "--tty":
			cmd.Options["tty"] = true
		case "--rm":
			cmd.Remove = true
			cmd.Options["remove"] = true
		case "--force-rm":
			cmd.ForceRemove = true
			cmd.Options["force_remove"] = true
		case "--network":
			if i+1 < len(args) {
				cmd.Network = args[i+1]
				cmd.Options["network"] = args[i+1]
				i += 2
				continue
			}
		case "-v", "--volume":
			if i+1 < len(args) {
				cmd.Volume = append(cmd.Volume, args[i+1])
				cmd.Options["volume"] = args[i+1]
				i += 2
				continue
			}
		case "-p", "--publish":
			if i+1 < len(args) {
				cmd.Port = args[i+1]
				cmd.Options["port"] = args[i+1]
				i += 2
				continue
			}
		case "-e", "--env":
			if i+1 < len(args) {
				cmd.Env = append(cmd.Env, args[i+1])
				cmd.Options["env"] = args[i+1]
				i += 2
				continue
			}
		case "-f", "--filter":
			if i+1 < len(args) {
				cmd.Filter = args[i+1]
				cmd.Options["filter"] = args[i+1]
				i += 2
				continue
			}
		case "-a", "--all":
			cmd.All = true
			cmd.Options["all"] = true
		case "--name":
			if i+1 < len(args) {
				cmd.Options["name"] = args[i+1]
				i += 2
				continue
			}
		}
		i++
	}

	// Parse remaining arguments
	if i < len(args) {
		if cmd.SubCommand == "run" || cmd.SubCommand == "exec" {
			cmd.Image = args[i]
			i++
			// Remaining are command/args
			if i < len(args) {
				cmd.Options["command"] = strings.Join(args[i:], " ")
			}
		} else if cmd.SubCommand == "cp" {
			if i+1 < len(args) {
				// Parse cp source:dest
				cpArgs := args[i]
				if strings.Contains(cpArgs, ":") {
					cmd.Container = strings.SplitN(cpArgs, ":", 2)[0]
					cmd.Path = strings.SplitN(cpArgs, ":", 2)[1]
				}
				i++
				if i < len(args) {
					cmd.Path = args[i]
				}
			}
		} else if cmd.SubCommand == "inspect" || cmd.SubCommand == "stats" ||
			cmd.SubCommand == "logs" || cmd.SubCommand == "stop" ||
			cmd.SubCommand == "start" || cmd.SubCommand == "restart" ||
			cmd.SubCommand == "kill" || cmd.SubCommand == "rm" {
			cmd.Container = args[i]
		}
	}

	return i
}

// parseImageCommand parses image-related subcommands
func (d *DockerParser) parseImageCommand(args []string, i int, cmd *DockerCommand) int {
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-f", "--file", "--filter":
			if i+1 < len(args) {
				cmd.Options["file"] = args[i+1]
				i += 2
				continue
			}
		case "-t", "--tag":
			if i+1 < len(args) {
				cmd.Tag = args[i+1]
				cmd.Options["tag"] = args[i+1]
				i += 2
				continue
			}
		case "-q", "--quiet":
			cmd.Options["quiet"] = true
		case "-a", "--all":
			cmd.All = true
			cmd.Options["all"] = true
		case "--no-trunc":
			cmd.Options["no_trunc"] = true
		}
		i++
	}

	if i < len(args) {
		cmd.Image = args[i]
	}

	return i
}

// parseResourceCommand parses network/volume/etc subcommands
func (d *DockerParser) parseResourceCommand(args []string, i int, cmd *DockerCommand) int {
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-f", "--filter":
			if i+1 < len(args) {
				cmd.Filter = args[i+1]
				cmd.Options["filter"] = args[i+1]
				i += 2
				continue
			}
		case "-a", "--all":
			cmd.All = true
			cmd.Options["all"] = true
		case "--format":
			if i+1 < len(args) {
				cmd.Options["format"] = args[i+1]
				i += 2
				continue
			}
		}
		i++
	}

	if i < len(args) {
		cmd.Path = args[i]
	}

	return i
}

// parseComposeCommand parses docker compose commands
func (d *DockerParser) parseComposeCommand(args []string, i int, cmd *DockerCommand) int {
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]

		switch opt {
		case "--":
			i++
			break
		case "-f", "--file":
			if i+1 < len(args) {
				cmd.Path = args[i+1]
				cmd.Options["file"] = args[i+1]
				i += 2
				continue
			}
		case "-d", "--detach":
			cmd.Detached = true
			cmd.Options["detach"] = true
		case "--remove-orphans":
			cmd.Options["remove_orphans"] = true
		case "--no-recreate":
			cmd.Options["no_recreate"] = true
		}
		i++
	}

	return i
}

// parseInfoCommand parses informational commands
func (d *DockerParser) parseInfoCommand(args []string, i int, cmd *DockerCommand) int {
	// These commands don't take many options
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		opt := args[i]
		switch opt {
		case "--format":
			if i+1 < len(args) {
				cmd.Options["format"] = args[i+1]
				i += 2
				continue
			}
		case "--help":
			cmd.Options["help"] = true
			return i
		}
		i++
	}
	return i
}

// GetSemanticOperations implements CommandParser for docker commands
func (d *DockerParser) GetSemanticOperations(parsed interface{}) ([]SemanticOperation, error) {
	cmd, ok := parsed.(*DockerCommand)
	if !ok {
		return nil, fmt.Errorf("invalid docker command type")
	}

	builder := d.utils.SemanticOperationBuilder()
	operations := make([]SemanticOperation, 0)

	// Docker operations are always potentially dangerous
	// Handle different subcommands
	switch cmd.SubCommand {
	case "run":
		operations = d.getRunOperations(cmd, builder)
	case "exec":
		operations = d.getExecOperations(cmd, builder)
	case "cp":
		operations = d.getCpOperations(cmd, builder)
	case "build":
		operations = d.getBuildOperations(cmd, builder)
	case "pull":
		operations = d.getPullOperations(cmd, builder)
	case "push":
		operations = d.getPushOperations(cmd, builder)
	case "rm", "rmi":
		operations = d.getRemoveOperations(cmd, builder)
	case "compose":
		operations = d.getComposeOperations(cmd, builder)
	case "image", "container", "network", "volume":
		operations = d.getListOperations(cmd, builder)
	default:
		// Default to read operations for informational commands
		builder.AddReadOperation("docker:"+cmd.SubCommand, "docker_info")
		builder = builder.WithParameter("command", "docker")
		builder = builder.WithParameter("subcommand", cmd.SubCommand)
	}

	operations = builder.Build()
	return operations, nil
}

func (d *DockerParser) getRunOperations(cmd *DockerCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	// Running a container involves multiple operations

	// Pull image if needed
	if cmd.Image != "" {
		builder.AddReadOperation("docker:image:"+cmd.Image, "docker_pull_image")
		builder = builder.WithParameter("command", "docker")
		builder = builder.WithParameter("subcommand", "run")
		builder = builder.WithParameter("operation", "pull")
		builder = builder.WithParameter("dangerous", true)
	}

	// Create container
	builder.AddCreateOperation("docker:container:"+cmd.Image, "docker_create_container")
	builder = builder.WithParameter("command", "docker")
	builder = builder.WithParameter("subcommand", "run")
	builder = builder.WithParameter("dangerous", true)
	builder = builder.WithParameter("over_approximated", true)

	// Handle volumes
	for _, vol := range cmd.Volume {
		builder.AddReadOperation("docker:volume:"+vol, "docker_volume_mount")
		builder = builder.WithParameter("command", "docker")
		builder = builder.WithParameter("subcommand", "run")
		builder = builder.WithParameter("volume", vol)
		builder = builder.WithParameter("dangerous", true)
	}

	// Handle network
	if cmd.Network != "" && cmd.Network != "host" {
		builder.AddReadOperation("docker:network:"+cmd.Network, "docker_network_connect")
		builder = builder.WithParameter("command", "docker")
		builder = builder.WithParameter("subcommand", "run")
		builder = builder.WithParameter("network", cmd.Network)
		builder = builder.WithParameter("dangerous", true)
	}

	// Start container
	builder.AddWriteOperation("docker:container:"+cmd.Image, "docker_start_container")
	builder = builder.WithParameter("command", "docker")
	builder = builder.WithParameter("subcommand", "run")
	builder = builder.WithParameter("operation", "start")
	builder = builder.WithParameter("dangerous", true)
	builder = builder.WithParameter("high_risk", true)

	return builder.Build()
}

func (d *DockerParser) getExecOperations(cmd *DockerCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	if cmd.Container != "" {
		builder.AddWriteOperation("docker:container:"+cmd.Container+"/exec", "docker_exec")
		builder = builder.WithParameter("command", "docker")
		builder = builder.WithParameter("subcommand", "exec")
		builder = builder.WithParameter("dangerous", true)
		builder = builder.WithParameter("high_risk", true)
		builder = builder.WithParameter("over_approximated", true)
	}
	return builder.Build()
}

func (d *DockerParser) getCpOperations(cmd *DockerCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	if cmd.Container != "" {
		// Copy from container
		builder.AddReadOperation("docker:container:"+cmd.Container+":"+cmd.Path, "docker_cp_from")
		builder = builder.WithParameter("command", "docker")
		builder = builder.WithParameter("subcommand", "cp")
		builder = builder.WithParameter("direction", "from")
		builder = builder.WithParameter("dangerous", true)
	}

	// Copy to container
	if cmd.Path != "" {
		builder.AddWriteOperation("docker:container:"+cmd.Container+":"+cmd.Path, "docker_cp_to")
		builder = builder.WithParameter("command", "docker")
		builder = builder.WithParameter("subcommand", "cp")
		builder = builder.WithParameter("direction", "to")
		builder = builder.WithParameter("dangerous", true)
	}
	return builder.Build()
}

func (d *DockerParser) getBuildOperations(cmd *DockerCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	// Build context
	if cmd.Path != "" {
		builder.AddReadOperation("docker:build:"+cmd.Path, "docker_build_context")
		builder = builder.WithParameter("command", "docker")
		builder = builder.WithParameter("subcommand", "build")
		builder = builder.WithParameter("dangerous", true)
		builder = builder.WithParameter("over_approximated", true)
	}

	// Create image
	builder.AddCreateOperation("docker:image:"+cmd.Tag, "docker_build_image")
	builder = builder.WithParameter("command", "docker")
	builder = builder.WithParameter("subcommand", "build")
	builder = builder.WithParameter("dangerous", true)
	builder = builder.WithParameter("high_risk", true)
	return builder.Build()
}

func (d *DockerParser) getPullOperations(cmd *DockerCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	if cmd.Image != "" {
		builder.AddReadOperation("docker:registry:"+cmd.Image, "docker_pull")
		builder = builder.WithParameter("command", "docker")
		builder = builder.WithParameter("subcommand", "pull")
		builder = builder.WithParameter("image", cmd.Image)
		builder = builder.WithParameter("dangerous", true)
		builder = builder.WithParameter("over_approximated", true)
	}
	return builder.Build()
}

func (d *DockerParser) getPushOperations(cmd *DockerCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	if cmd.Image != "" {
		builder.AddWriteOperation("docker:registry:"+cmd.Image, "docker_push")
		builder = builder.WithParameter("command", "docker")
		builder = builder.WithParameter("subcommand", "push")
		builder = builder.WithParameter("image", cmd.Image)
		builder = builder.WithParameter("dangerous", true)
		builder = builder.WithParameter("high_risk", true)
	}
	return builder.Build()
}

func (d *DockerParser) getRemoveOperations(cmd *DockerCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	if cmd.Image != "" {
		builder.AddWriteOperation("docker:image:"+cmd.Image, "docker_remove_image")
		builder = builder.WithParameter("command", "docker")
		builder = builder.WithParameter("subcommand", cmd.SubCommand)
		builder = builder.WithParameter("dangerous", true)
		builder = builder.WithParameter("high_risk", true)
	}
	if cmd.Container != "" {
		builder.AddWriteOperation("docker:container:"+cmd.Container, "docker_remove_container")
		builder = builder.WithParameter("command", "docker")
		builder = builder.WithParameter("subcommand", cmd.SubCommand)
		builder = builder.WithParameter("dangerous", true)
		builder = builder.WithParameter("high_risk", true)
	}
	if cmd.ForceRemove {
		builder.AddWriteOperation("docker:container:*", "docker_force_remove")
		builder = builder.WithParameter("command", "docker")
		builder = builder.WithParameter("over_approximated", true)
		builder = builder.WithParameter("dangerous", true)
	}
	return builder.Build()
}

func (d *DockerParser) getComposeOperations(cmd *DockerCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	if cmd.Path != "" {
		builder.AddReadOperation("docker:compose:"+cmd.Path, "docker_compose_file")
		builder = builder.WithParameter("command", "docker")
		builder = builder.WithParameter("subcommand", "compose")
		builder = builder.WithParameter("dangerous", true)
		builder = builder.WithParameter("over_approximated", true)
	}
	return builder.Build()
}

func (d *DockerParser) getListOperations(cmd *DockerCommand, builder *SemanticOperationBuilder) []SemanticOperation {
	builder.AddReadOperation("docker:"+cmd.SubCommand+"s", "docker_list")
	builder = builder.WithParameter("command", "docker")
	builder = builder.WithParameter("subcommand", cmd.SubCommand)
	builder = builder.WithParameter("filter", cmd.Filter)
	return builder.Build()
}

// GetOperationGraph implements the enhanced CommandParser interface for docker commands
func (p *DockerParser) GetOperationGraph(parsed interface{}) (*OperationGraph, error) {
	_, ok := parsed.(*DockerCommand)
	if !ok {
		return nil, fmt.Errorf("invalid docker command type")
	}

	operations, err := p.GetSemanticOperations(parsed)
	if err != nil {
		return nil, err
	}

	builder := &OperationGraphBuilder{}
	graph := builder.BuildOperationGraph("docker", operations, []SemanticOperation{})

	return graph, nil
}
