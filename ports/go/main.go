// Go port of the SHIPCHECK Dockerfile linter — single binary, stdlib only.
//
// Mirrors the primary `shipcheck lint` command: parses a Dockerfile (merging
// backslash continuations + multi-stage builds) and emits the same finding
// codes (SC101/SC110/SC120/SC2xx/SC300/SC310) as the Python reference, in JSON.
//
//	go run main.go Dockerfile
//	go run main.go Dockerfile --format json
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type Finding struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Line        int    `json:"line"`
	Instruction string `json:"instruction"`
	Message     string `json:"message"`
	Hint        string `json:"hint"`
}

type instr struct {
	line int
	cmd  string
	args string
}

var severityRank = map[string]int{
	"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

// Offline EOL/CVE advisory table — matches the Python _CVE_TABLE.
var cveTable = map[string]string{
	"debian:8":    "EOL: Debian 8 (jessie) is end-of-life; no security updates",
	"debian:9":    "EOL: Debian 9 (stretch) is end-of-life",
	"ubuntu:16.04": "EOL: Ubuntu 16.04 reached end of standard support",
	"ubuntu:18.04": "EOL: Ubuntu 18.04 reached end of standard support",
	"node:10":     "EOL: Node 10 is end-of-life; many unpatched CVEs",
	"node:12":     "EOL: Node 12 is end-of-life; many unpatched CVEs",
	"python:3.6":  "EOL: Python 3.6 is end-of-life; no security fixes",
	"python:3.7":  "EOL: Python 3.7 is end-of-life; no security fixes",
	"alpine:3.9":  "EOL: Alpine 3.9 no longer receives security updates",
}

var heavyBases = map[string]string{
	"ubuntu":  "consider a -slim language image or distroless/alpine base",
	"debian":  "consider debian:<ver>-slim or distroless",
	"node":    "consider node:<ver>-slim or node:<ver>-alpine",
	"python":  "consider python:<ver>-slim",
	"openjdk": "consider an -slim or eclipse-temurin:<ver>-jre image",
}

var (
	slimHint   = regexp.MustCompile(`(?i)(slim|alpine|distroless|-jre|busybox|scratch)`)
	secretRe   = regexp.MustCompile(`(?i)(password|passwd|secret|api[_-]?key|access[_-]?key|token|aws_secret)\s*[=:]\s*\S+`)
	curlPipeSh = regexp.MustCompile(`(?i)\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash)\b`)
	asStage    = regexp.MustCompile(`(?i)\s+as\s+`)
	pipInstall = regexp.MustCompile(`pip3?\s+install`)
)

func parse(text string) []instr {
	var out []instr
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		start := i + 1
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		buf := line
		for strings.HasSuffix(strings.TrimRight(buf, " \t\r"), "\\") && i+1 < len(lines) {
			trimmed := strings.TrimRight(buf, " \t\r")
			buf = trimmed[:len(trimmed)-1] + " " + lines[i+1]
			i++
		}
		buf = strings.TrimSpace(buf)
		parts := strings.SplitN(buf, " ", 2)
		cmd := strings.ToUpper(parts[0])
		args := ""
		if len(parts) > 1 {
			args = strings.TrimSpace(parts[1])
		}
		out = append(out, instr{line: start, cmd: cmd, args: args})
	}
	return out
}

func splitBase(ref string) (string, string) {
	ref = strings.TrimSpace(ref)
	ref = asStage.Split(ref, 2)[0]
	ref = strings.TrimSpace(ref)
	if idx := strings.Index(ref, "@"); idx >= 0 {
		ref = ref[:idx]
	}
	name, tag := ref, ""
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		maybe := ref[i+1:]
		if !strings.Contains(maybe, "/") {
			name, tag = ref[:i], maybe
		}
	}
	segs := strings.Split(name, "/")
	image := strings.ToLower(segs[len(segs)-1])
	return image, tag
}

func lint(text string) []Finding {
	instrs := parse(text)
	var fs []Finding
	add := func(code, sev string, ln int, in, msg, hint string) {
		fs = append(fs, Finding{code, sev, ln, in, msg, hint})
	}
	lastRoot := true
	sawFrom := false
	runCount := 0
	copyDotSeen := false
	for _, in := range instrs {
		low := strings.ToLower(in.args)
		switch in.cmd {
		case "FROM":
			sawFrom = true
			lastRoot = true
			image, tag := splitBase(in.args)
			if tag == "" {
				add("SC101", "medium", in.line, in.cmd,
					fmt.Sprintf("base image '%s' has no explicit tag (defaults to :latest)", image),
					"pin a specific version for reproducible builds")
			} else if tag == "latest" {
				add("SC101", "medium", in.line, in.cmd,
					fmt.Sprintf("base image '%s' pinned to ':latest'", image),
					"pin a specific version; ':latest' is not reproducible")
			}
			if hint, ok := heavyBases[image]; ok && !slimHint.MatchString(in.args) {
				add("SC110", "info", in.line, in.cmd,
					fmt.Sprintf("'%s' is a large base image", image), hint)
			}
			if tag != "" {
				if adv, ok := cveTable[image+":"+tag]; ok {
					sev := "high"
					if strings.HasPrefix(adv, "EOL") {
						sev = "critical"
					}
					add("SC120", sev, in.line, in.cmd,
						fmt.Sprintf("%s:%s - %s", image, tag, adv),
						"upgrade to a supported, patched tag")
				}
			}
		case "USER":
			u := strings.ToLower(strings.TrimSpace(in.args))
			lastRoot = u == "root" || u == "0" || u == ""
		case "RUN":
			runCount++
			if strings.Contains(low, "apt-get update") && !strings.Contains(low, "install") {
				add("SC201", "high", in.line, in.cmd,
					"'apt-get update' in its own layer causes stale-cache installs",
					"chain 'apt-get update && apt-get install' in one RUN")
			}
			if strings.Contains(low, "apt-get install") && !strings.Contains(low, "--no-install-recommends") {
				add("SC202", "low", in.line, in.cmd,
					"apt-get install without --no-install-recommends",
					"add --no-install-recommends to shrink the image")
			}
			if strings.Contains(low, "apt-get install") && !strings.Contains(low, "rm -rf /var/lib/apt/lists") {
				add("SC203", "low", in.line, in.cmd,
					"apt lists not removed; package cache bloats the layer",
					"append '&& rm -rf /var/lib/apt/lists/*'")
			}
			if pipInstall.MatchString(low) && !strings.Contains(low, "--no-cache-dir") {
				add("SC210", "low", in.line, in.cmd,
					"pip install without --no-cache-dir leaves wheel cache", "add --no-cache-dir")
			}
			if regexp.MustCompile(`\bsudo\b`).MatchString(low) {
				add("SC220", "medium", in.line, in.cmd,
					"'sudo' used in RUN; builds run as root already",
					"remove sudo; use USER for privilege drops")
			}
			if curlPipeSh.MatchString(in.args) {
				add("SC221", "high", in.line, in.cmd,
					"piping a downloaded script straight into a shell",
					"download, verify a checksum, then execute")
			}
			if secretRe.MatchString(in.args) {
				add("SC230", "critical", in.line, in.cmd,
					"possible hard-coded secret in RUN layer",
					"use build secrets/args, never bake credentials into layers")
			}
		case "ADD":
			fields := strings.Fields(in.args)
			first := ""
			if len(fields) > 0 {
				first = fields[0]
			}
			isURL := strings.HasPrefix(first, "http://") || strings.HasPrefix(first, "https://")
			isTar := false
			for _, ext := range []string{".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"} {
				if strings.HasSuffix(first, ext) {
					isTar = true
				}
			}
			if !isURL && !isTar {
				add("SC240", "low", in.line, in.cmd,
					"ADD used for a plain file/dir",
					"prefer COPY; ADD has surprising URL/tar semantics")
			}
		case "COPY":
			toks := strings.Fields(in.args)
			if !copyDotSeen {
				for _, t := range toks {
					if t == "." || t == "./" {
						copyDotSeen = true
						add("SC250", "info", in.line, in.cmd,
							"COPY . . early invalidates cache on any source change",
							"copy dependency manifests + install first, then COPY .")
						break
					}
				}
			}
		case "EXPOSE":
			for _, p := range regexp.MustCompile(`\d+`).FindAllString(in.args, -1) {
				if p == "22" {
					add("SC260", "medium", in.line, in.cmd,
						"EXPOSE 22 hints at running sshd in a container",
						"avoid SSH in containers; use exec/attach instead")
				}
			}
		}
	}
	if sawFrom && lastRoot {
		ln := 1
		if len(instrs) > 0 {
			ln = instrs[len(instrs)-1].line
		}
		add("SC300", "high", ln, "USER",
			"container runs as root (no trailing USER directive)",
			"add a non-root 'USER' before the final CMD/ENTRYPOINT")
	}
	if runCount >= 5 {
		ln := instrs[len(instrs)-1].line
		add("SC310", "info", ln, "RUN",
			fmt.Sprintf("%d separate RUN layers detected", runCount),
			"combine related RUN steps with '&&' to reduce layers/size")
	}
	return fs
}

func maxSeverity(fs []Finding) string {
	best := ""
	for _, f := range fs {
		if best == "" || severityRank[f.Severity] > severityRank[best] {
			best = f.Severity
		}
	}
	return best
}

func main() {
	target := "Dockerfile"
	for _, a := range os.Args[1:] {
		if !strings.HasPrefix(a, "--") {
			target = a
		}
	}
	data, err := os.ReadFile(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	fs := lint(string(data))
	out, _ := json.MarshalIndent(map[string]any{
		"tool":         "shipcheck",
		"path":         target,
		"findings":     fs,
		"max_severity": maxSeverity(fs),
	}, "", "  ")
	fmt.Println(string(out))
	if r, ok := severityRank[maxSeverity(fs)]; ok && r >= severityRank["medium"] {
		os.Exit(1)
	}
}
