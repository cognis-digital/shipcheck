package dockerfile_parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Dockerfile represents a parsed Dockerfile with all instructions and metadata.
type Dockerfile struct {
	Name       string
	Path       string
	BaseImage  string
	Layers     []Layer
	Instructions []Instruction
	Errors     []string
}

// Layer represents a single layer operation in the build process.
type Layer struct {
	Command   string
	Args      []string
	SizeEst   int64 // bytes, approximate
	Type      LayerType
}

// Instruction type for categorizing Dockerfile commands.
type InstructionType int

const (
	TypeUnknown InstructionType = iota
	TypeBaseImage
	TypeCopy
	TypeAdd
	TypeRun
	TypeEnv
	TypeCmd
	TypeWorkdir
	TypeUser
	TypeExpose
	TypeVolumefrom
	TypeOnbuild
)

// LayerType represents the category of a layer operation.
type LayerCategory int

const (
	CatUnknown LayerCategory = iota
	CatBaseImage
	CatCopyAdd
	CatRunCommand
	CatEnvCmd
	CatWorkdirUser
	CatExposeVolumefromOnbuild
)

// Instruction represents a parsed Dockerfile instruction.
type Instruction struct {
	Type      InstructionType
	Original  string
	Args      []string
	LineNum   int
}

// Parse reads and parses a Dockerfile from the given path.
func Parse(path string, name ...string) (*Dockerfile, error) {
	var df Dockerfile
	if len(name) > 0 {
		df.Name = name[0]
	} else {
		base := filepath.Base(path)
		df.Name = strings.TrimSuffix(base, ".dockerfile")
	}

	file, err := os.Open(path)
	if err != nil {
		return &df, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var baseImage string
	var lineNum int

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		parts := splitInstruction(line)
		if len(parts) < 2 {
			df.Errors = append(df.Errors, fmt.Sprintf("line %d: malformed instruction", lineNum))
			continue
		}

		cmd := strings.ToUpper(parts[0])
		args := parts[1:]

		instr := Instruction{
			Type:      getType(cmd),
			Original:  line,
			Args:      args,
			LineNum:   lineNum,
		}

		switch cmd {
		case "FROM":
			baseImage = parts[1]
			df.BaseImage = baseImage
			l := Layer{Command: cmd, Args: args, SizeEst: 0, Type: CatBaseImage}
			df.Layers = append(df.Layers, l)

		case "COPY", "ADD":
			sizeEst := estimateCopySize(args)
			l := Layer{Command: cmd, Args: args, SizeEst: sizeEst, Type: CatCopyAdd}
			df.Layers = append(df.Layers, l)

		case "RUN":
			l := Layer{Command: cmd, Args: args, SizeEst: 0, Type: CatRunCommand}
			df.Layers = append(df.Layers, l)

		default:
			instr.Type = getType(cmd)
			df.Instructions = append(df.Instructions, instr)
		}
	}

	if err := scanner.Err(); err != nil {
		return &df, fmt.Errorf("error reading file: %w", err)
	}

	return &df, nil
}

// splitInstruction splits a Dockerfile line into command and arguments.
func splitInstruction(line string) []string {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) == 1 {
		return parts
	}

	cmd := strings.ToUpper(strings.TrimSpace(parts[0]))
	args := strings.Fields(parts[1])

	// Handle commands with colons (e.g., FROM node:18-alpine)
	if idx := strings.Index(cmd, ":"); idx != -1 {
		cmd = cmd[:idx]
	}

	return append([]string{cmd}, args...)
}

// getType returns the instruction type for a given command.
func getType(cmd string) InstructionType {
	switch cmd {
	case "FROM":
		return TypeBaseImage
	case "COPY", "ADD":
		return TypeCopy
	case "RUN":
		return TypeRun
	case "ENV", "ARG":
		return TypeEnv
	case "CMD":
		return TypeCmd
	case "WORKDIR":
		return TypeWorkdir
	case "USER":
		return TypeUser
	case "EXPOSE":
		return TypeExpose
	case "VOLUMEFROM":
		return TypeVolumefrom
	case "ONBUILD":
		return TypeOnbuild
	default:
		return TypeUnknown
	}
}

// estimateCopySize provides a rough size estimate for COPY/ADD operations.
func estimateCopySize(args []string) int64 {
	var total int64
	for _, arg := range args {
		if strings.HasPrefix(arg, "/") || strings.Contains(arg, ".tar") {
			total += 1024 // conservative estimate per file
		} else if !strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
			total += 512 // default estimate for unknown paths
		}
	}
	return total
}

// Summary returns a human-readable summary of the parsed Dockerfile.
func (df *Dockerfile) Summary() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("Name: %s\n", df.Name))
	if df.BaseImage != "" {
		b.WriteString(fmt.Sprintf("Base Image: %s\n", df.BaseImage))
	} else {
		b.WriteString("Base Image: <unknown>\n")
	}

	b.WriteString(fmt.Sprintf("Total Instructions: %d\n", len(df.Instructions)))
	b.WriteString(fmt.Sprintf("Total Layers: %d\n", len(df.Layers)))

	if len(df.Errors) > 0 {
		b.WriteString("\nErrors:\n")
		for _, e := range df.Errors {
			b.WriteString(fmt.Sprintf("  - %s\n", e))
		}
	}

	return b.String()
}

// PrintSummary prints the summary to stdout.
func (df *Dockerfile) PrintSummary() {
	fmt.Println(df.Summary())
}

// Main entry point for demonstration and testing.
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: shipcheck <dockerfile_path> [name]")
		os.Exit(1)
	}

	path := os.Args[1]
	name := ""
	if len(os.Args) > 2 {
		name = os.Args[2]
	}

	df, err := Parse(path, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Parsed Dockerfile:\n")
	fmt.Println(df.Summary())
}