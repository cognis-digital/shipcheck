package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// LayerInfo tracks size after each instruction
type LayerInfo struct {
	Command     string
	Cumulative  int64 // bytes
	Estimated   int64 // estimated layer size
}

// DockerfileState holds parsing context
type DockerfileState struct {
	Layers      []LayerInfo
	BaseImage    string
	CurrentSize  int64
	WorkingDir   string
	Args         map[string]string
	Env          map[string]string
	MultiLineCmd string
}

// Configurable thresholds for warnings
var (
	WarningThreshold = 100 * 1024 * 1024 // 100MB
	CriticalThreshold = 500 * 1024 * 1024 // 500MB
)

// ParseDockerfile reads and parses a Dockerfile path
func ParseDockerfile(path string) (*DockerfileState, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	state := &DockerfileState{
		Layers:    make([]LayerInfo, 0),
		Args:      make(map[string]string),
		Env:       make(map[string]string),
		MultiLineCmd: "",
	}

	scanner := bufio.NewScanner(f)
	lineNum := 1

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle multi-line commands (RUN | COPY --from=...)
		if strings.Contains(line, "|") && !strings.Contains(line, "FROM") {
			state.MultiLineCmd += line + "\n"
			continue
		} else if state.MultiLineCmd != "" {
			line = state.MultiLineCmd + line
			state.MultiLineCmd = ""
		}

		parts := parseInstruction(line)
		if parts == nil {
			continue
		}

		cmd, args, ok := parts[0], parts[1], true
		if !ok {
			cmd = line
			args = ""
		}

		// Update state for ARG/ENV
		if cmd == "ARG" {
			parts := strings.SplitN(args, "=", 2)
			if len(parts) == 2 {
				state.Args[parts[0]] = parts[1]
			}
			continue
		}

		if cmd == "ENV" {
			parts := strings.SplitN(args, "=", 2)
			if len(parts) == 2 {
				state.Env[parts[0]] = parts[1]
			}
			continue
		}

		// Handle FROM instruction
		if cmd == "FROM" {
			state.BaseImage = strings.TrimSpace(args)
			state.CurrentSize = 0 // Reset for new image
			state.Layers = []LayerInfo{}
			continue
		}

		// Handle WORKDIR
		if cmd == "WORKDIR" {
			state.WorkingDir = strings.TrimPrefix(strings.TrimSpace(args), "/")
			continue
		}

		// Calculate layer size for other instructions
		size := estimateLayerSize(cmd, args)
		state.CurrentSize += size
		
		layerInfo := LayerInfo{
			Command:     cmd,
			Cumulative:  state.CurrentSize,
			Estimated:   size,
		}

		// Add to layers slice (insert at beginning for chronological order)
		state.Layers = append([]LayerInfo{layerInfo}, state.Layers...)

		// Check thresholds
		if state.CurrentSize >= CriticalThreshold {
			fmt.Printf("CRITICAL: Layer %s now at %.2f MB\n", cmd, float64(state.CurrentSize)/1024/1024)
		} else if state.CurrentSize >= WarningThreshold {
			fmt.Printf("WARNING: Layer %s now at %.2f MB\n", cmd, float64(state.CurrentSize)/1024/1024)
		}

		// Handle multi-line continuation
		if strings.HasSuffix(args, "|") || strings.Contains(cmd, "RUN ") && strings.HasSuffix(strings.TrimSpace(args), "|") {
			state.MultiLineCmd = line + "\n"
			continue
		}
	}

	return state, scanner.Err()
}

// parseInstruction splits a Dockerfile instruction into command and arguments
func parseInstruction(line string) []string {
	line = strings.TrimPrefix(line, "#") // Remove inline comments
	parts := strings.SplitN(line, " ", 2)
	
	if len(parts) < 1 {
		return nil
	}

	cmd := parts[0]
	args := ""
	if len(parts) == 2 {
		args = parts[1]
	}

	// Normalize command name (remove trailing whitespace)
	cmd = strings.TrimSpace(cmd)

	return []string{cmd, args}
}

// estimateLayerSize calculates estimated size contribution of an instruction
func estimateLayerSize(cmd string, args string) int64 {
	switch cmd {
	case "FROM":
		if len(args) > 0 {
			// Estimate base image size (rough approximation)
			image := strings.ToLower(strings.TrimSpace(args))
			return estimateBaseImageSize(image)
		}
		return 1024 * 1024 // Default 1MB for unknown

	case "RUN":
		if len(args) == 0 {
			return 512 * 1024 // Default 512KB for empty RUN
		}
		
		// Parse command and estimate based on common patterns
		cmdParts := strings.Fields(args)
		if len(cmdParts) == 0 {
			return 512 * 1024
		}

		firstWord := cmdParts[0]
		
		// apt-get install/update
		if firstWord == "apt-get" && (strings.Contains(args, "install") || strings.Contains(args, "update")) {
			return estimateAPTSize(args)
		}

		// apk add
		if firstWord == "apk" && strings.Contains(args, "add") {
			return 512 * 1024 // Conservative estimate for Alpine packages
		}

		// yum/dnf install
		if (firstWord == "yum" || firstWord == "dnf") && strings.Contains(args, "install") {
			return 768 * 1024
		}

		// pip/pip3 install
		if firstWord == "pip" || firstWord == "pip3" {
			pkgCount := countPipPackages(args)
			return int64(pkgCount) * 50 * 1024 // ~50KB per package average
		}

		// npm install (node.js)
		if firstWord == "npm" && strings.Contains(args, "install") {
			deps := countNPMDependencies(args)
			return int64(deps) * 128 * 1024 // ~125KB per dependency average
		}

		// yarn install (node.js)
		if firstWord == "yarn" && strings.Contains(args, "install") {
			deps := countYARNDependencies(args)
			return int64(deps) * 96 * 1024 // ~95KB per dependency average
		}

		// curl/wget download (common in multi-stage builds)
		if firstWord == "curl" || firstWord == "wget" {
			return estimateDownloadSize(args)
		}

		// Copy from cache layers (--from=cache:tag)
		if strings.Contains(args, "--from=") && !strings.Contains(cmd, "COPY --") {
			return 256 * 1024 // Conservative for COPY with FROM
		}

		// Default estimate for RUN commands
		return 768 * 1024

	case "COPY":
		if len(args) == 0 {
			return 512 * 1024
		}

		// Check if copying from cache layer
		if strings.Contains(args, "--from=") && !strings.Contains(cmd, "COPY --") {
			cacheLayers := countCacheLayers(args)
			return int64(cacheLayers) * 512 * 1024 // ~500KB per cached layer
		}

		// Check if copying from current image (--from=...)
		if strings.Contains(args, "--from=") && strings.Contains(cmd, "COPY --") {
			return 768 * 1024
		}

		// Estimate file sizes based on patterns
		files := extractFilePaths(args)
		
		// Check for common large files
		largeFiles := countLargeFiles(files)
		if largeFiles > 0 {
			return int64(largeFiles) * 256 * 1024 // ~250KB per large file estimate
		}

		// Default estimate for regular COPY
		return 256 * 1024

	case "ADD":
		// ADD is similar to COPY but with additional features
		if len(args) == 0 {
			return 768 * 1024
		}

		files := extractFilePaths(args)
		
		// Check for tar archives (unpacked during build)
		tarFiles := countTarFiles(files)
		if tarFiles > 0 {
			return int64(tarFiles) * 512 * 1024 // ~500KB per archive estimate
		}

		// Check for URL downloads (--from-url=...)
		urls := countURLs(args)
		if urls > 0 {
			return int64(urls) * 1024 * 1024 // ~1MB per URL (conservative)
		}

		// Default estimate for ADD
		return 512 * 1024

	case "ENV", "ARG":
		// ENV and ARG have minimal size impact
		return 64 * 1024 // ~64KB for environment/argument metadata

	case "WORKDIR", "LABEL", "EXPOSE", "CMD", "ENTRYPOINT":
		// Minimal overhead instructions
		return 32 * 1024 // ~32KB

	default:
		// Unknown instruction - conservative estimate
		return 512 * 1024
	}
}

// estimateBaseImageSize returns estimated size for common base images
func estimateBaseImageSize(image string) int64 {
	image = strings.ToLower(strings.TrimSpace(image))

	switch image {
	case "alpine", "alpine:3.18", "alpine:latest":
		return 50 * 1024 * 1024 // ~50MB for Alpine
	case "debian", "debian:bullseye", "debian:buster":
		return 128 * 1024 * 1024 // ~128MB for Debian
	case "ubuntu", "ubuntu:focal", "ubuntu:jammy":
		return 768 * 1024 * 1024 // ~750MB for Ubuntu
	case "centos", "centos:stream9", "centos:latest":
		return 384 * 1024 * 1024 // ~380MB for CentOS
	case "rhel", "rockylinux", "almalinux":
		return 512 * 1024 * 1024 // ~500MB for RHEL family
	case "fedora", "fedora:latest":
		return 384 * 1024 * 1024 // ~380MB for Fedora
	case "suse", "opensuse", "opensuse-leap":
		return 256 * 1024 * 1024 // ~250MB for SUSE
	case "busybox", "busybox:latest":
		return 3 * 1024 * 1024 // ~3MB for BusyBox
	case "scratch":
		return 64 * 1024 // ~64KB for scratch (empty)
	default:
		// Default estimate for unknown images
		return 256 * 1024 * 1024 // ~250MB conservative default
	}
}

// estimateAPTSize estimates size for apt-get operations
func estimateAPTSize(args string) int64 {
	// Count packages being installed/updated
	pkgCount := countAPTPackages(args)
	
	if pkgCount > 0 {
		return int64(pkgCount) * 256 * 1024 // ~250KB per package average
	}

	// Default for apt-get update (no packages specified)
	return 512 * 1024
}

// countAPTPackages counts packages in apt-get commands
func countAPTPackages(args string) int {
	var count int
	
	// Match "package" or "packages" followed by names
	re := regexp.MustCompile(`(apt|apt-get)\s+(install|update|upgrade)\s+([^&\n]+)` + 
			regexp.QuoteMeta("&&") + `[^&\n]+`)
	
	matches := re.FindAllString(args, -1)
	for _, match := range matches {
		parts := strings.Fields(match)
		if len(parts) >= 3 {
			cmd := parts[0] + " " + parts[1]
			if cmd == "apt-get install" || cmd == "apt install" {
				count += countPackageNames(parts[2])
			} else if cmd == "apt-get update" || cmd == "apt update" {
				count++ // Update adds some overhead
			}
		}
	}

	return count
}

// countPackageNames counts individual package names
func countPackageNames(names string) int {
	parts := strings.Fields(names)
	var count int
	
	for _, part := range parts {
		if !strings.Contains(part, "&&") && 
		   !strings.Contains(part, ";") &&
		   !strings.Contains(part, "=") {
			count++
		}
	}

	return count
}

// countPipPackages counts pip packages in install commands
func countPipPackages(args string) int {
	var count int
	
	parts := strings.Fields(args)
	for i, part := range parts {
		if (part == "pip" || part == "pip3") && 
		   (parts[i+1] == "install" || parts[i+1] == "freeze") {
			count += countPackageNames(parts[i+2])
		}
	}

	return count
}

// countNPMDependencies counts npm dependencies in install commands
func countNPMDependencies(args string) int {
	var count int
	
	parts := strings.Fields(args)
	for i, part := range parts {
		if (part == "npm" || part == "yarn") && 
		   (parts[i+1] == "install" || parts[i+1] == "add") {
			count += countPackageNames(parts[i+2])
		}
	}

	return count
}

// countYARNDependencies counts yarn dependencies in install commands
func countYARNDependencies(args string) int {
	var count int
	
	parts := strings.Fields(args)
	for i, part := range parts {
		if (part == "yarn") && 
		   (parts[i+1] == "install" || parts[i+1] == "add") {
			count += countPackageNames(parts[i+2])
		}
	}

	return count
}

// estimateDownloadSize estimates size for curl/wget downloads
func estimateDownloadSize(args string) int64 {
	var total int64
	
	parts := strings.Fields(args)
	for i, part := range parts {
		if (part == "curl" || part == "wget") && 
		   (parts[i+1] == "-o" || parts[i+1] == "--output-dir=" || parts[i+1] == "-O") {
			total++ // Conservative estimate per download
		}
	}

	return total * 512 * 1024 // ~500KB per download (conservative)
}

// countCacheLayers counts --from= cache layers in COPY/ADD instructions
func countCacheLayers(args string) int {
	count := strings.Count(args, "--from=")
	return count
}

// extractFilePaths extracts file paths from COPY/ADD arguments
func extractFilePaths(args string) []string {
	var files []string
	
	// Remove flags and options
	cleanArgs := args
	for re := range map[string]func(string) string{
		`--from=`: func(s string) string {
			idx := strings.Index(s, "--from