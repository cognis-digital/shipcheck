// Rust port of the SHIPCHECK Dockerfile linter — fast, single binary, std only.
//
// Mirrors `shipcheck lint`: parses a Dockerfile (continuations + multi-stage)
// and emits the same SC-code findings as the Python reference, in JSON.
//
//   cargo run -- Dockerfile
use std::env;
use std::fs;
use std::process;

#[derive(Clone)]
struct Finding {
    code: &'static str,
    severity: &'static str,
    line: usize,
    instruction: String,
    message: String,
    hint: &'static str,
}

struct Instr {
    line: usize,
    cmd: String,
    args: String,
}

fn sev_rank(s: &str) -> i32 {
    match s {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => -1,
    }
}

fn cve_advisory(key: &str) -> Option<&'static str> {
    match key {
        "debian:8" => Some("EOL: Debian 8 (jessie) is end-of-life; no security updates"),
        "debian:9" => Some("EOL: Debian 9 (stretch) is end-of-life"),
        "ubuntu:16.04" => Some("EOL: Ubuntu 16.04 reached end of standard support"),
        "ubuntu:18.04" => Some("EOL: Ubuntu 18.04 reached end of standard support"),
        "node:10" => Some("EOL: Node 10 is end-of-life; many unpatched CVEs"),
        "node:12" => Some("EOL: Node 12 is end-of-life; many unpatched CVEs"),
        "python:3.6" => Some("EOL: Python 3.6 is end-of-life; no security fixes"),
        "python:3.7" => Some("EOL: Python 3.7 is end-of-life; no security fixes"),
        "alpine:3.9" => Some("EOL: Alpine 3.9 no longer receives security updates"),
        _ => None,
    }
}

fn heavy_base(image: &str) -> Option<&'static str> {
    match image {
        "ubuntu" => Some("consider a -slim language image or distroless/alpine base"),
        "debian" => Some("consider debian:<ver>-slim or distroless"),
        "node" => Some("consider node:<ver>-slim or node:<ver>-alpine"),
        "python" => Some("consider python:<ver>-slim"),
        "openjdk" => Some("consider an -slim or eclipse-temurin:<ver>-jre image"),
        _ => None,
    }
}

fn has_slim_hint(s: &str) -> bool {
    let l = s.to_lowercase();
    ["slim", "alpine", "distroless", "-jre", "busybox", "scratch"]
        .iter()
        .any(|h| l.contains(h))
}

fn parse(text: &str) -> Vec<Instr> {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let start = i + 1;
        let s = lines[i].trim();
        if s.is_empty() || s.starts_with('#') {
            i += 1;
            continue;
        }
        let mut buf = lines[i].to_string();
        while buf.trim_end().ends_with('\\') && i + 1 < lines.len() {
            let trimmed = buf.trim_end();
            buf = format!("{} {}", &trimmed[..trimmed.len() - 1], lines[i + 1]);
            i += 1;
        }
        let buf = buf.trim().to_string();
        let (cmd, args) = match buf.find(char::is_whitespace) {
            Some(p) => (buf[..p].to_uppercase(), buf[p..].trim().to_string()),
            None => (buf.to_uppercase(), String::new()),
        };
        out.push(Instr { line: start, cmd, args });
        i += 1;
    }
    out
}

fn split_base(refin: &str) -> (String, Option<String>) {
    let mut r = refin.trim().to_string();
    // strip " AS stage"
    let lower = r.to_lowercase();
    if let Some(pos) = lower.find(" as ") {
        r = r[..pos].trim().to_string();
    }
    if let Some(at) = r.find('@') {
        r = r[..at].to_string();
    }
    let mut name = r.clone();
    let mut tag = None;
    if let Some(i) = r.rfind(':') {
        let maybe = &r[i + 1..];
        if !maybe.contains('/') {
            name = r[..i].to_string();
            tag = Some(maybe.to_string());
        }
    }
    let image = name.rsplit('/').next().unwrap_or(&name).to_lowercase();
    (image, tag)
}

fn lint(text: &str) -> Vec<Finding> {
    let instrs = parse(text);
    let mut fs: Vec<Finding> = Vec::new();
    let mut last_root = true;
    let mut saw_from = false;
    let mut run_count = 0;
    let mut copy_dot_seen = false;

    for it in &instrs {
        let low = it.args.to_lowercase();
        match it.cmd.as_str() {
            "FROM" => {
                saw_from = true;
                last_root = true;
                let (image, tag) = split_base(&it.args);
                match &tag {
                    None => fs.push(Finding {
                        code: "SC101", severity: "medium", line: it.line,
                        instruction: it.cmd.clone(),
                        message: format!("base image '{}' has no explicit tag (defaults to :latest)", image),
                        hint: "pin a specific version for reproducible builds",
                    }),
                    Some(t) if t == "latest" => fs.push(Finding {
                        code: "SC101", severity: "medium", line: it.line,
                        instruction: it.cmd.clone(),
                        message: format!("base image '{}' pinned to ':latest'", image),
                        hint: "pin a specific version; ':latest' is not reproducible",
                    }),
                    _ => {}
                }
                if let Some(h) = heavy_base(&image) {
                    if !has_slim_hint(&it.args) {
                        fs.push(Finding {
                            code: "SC110", severity: "info", line: it.line,
                            instruction: it.cmd.clone(),
                            message: format!("'{}' is a large base image", image), hint: h,
                        });
                    }
                }
                if let Some(t) = &tag {
                    if let Some(adv) = cve_advisory(&format!("{}:{}", image, t)) {
                        let sev = if adv.starts_with("EOL") { "critical" } else { "high" };
                        fs.push(Finding {
                            code: "SC120", severity: sev, line: it.line,
                            instruction: it.cmd.clone(),
                            message: format!("{}:{} - {}", image, t, adv),
                            hint: "upgrade to a supported, patched tag",
                        });
                    }
                }
            }
            "USER" => {
                let u = it.args.trim().to_lowercase();
                last_root = u == "root" || u == "0" || u.is_empty();
            }
            "RUN" => {
                run_count += 1;
                if low.contains("apt-get update") && !low.contains("install") {
                    fs.push(Finding { code: "SC201", severity: "high", line: it.line,
                        instruction: it.cmd.clone(),
                        message: "'apt-get update' in its own layer causes stale-cache installs".into(),
                        hint: "chain 'apt-get update && apt-get install' in one RUN" });
                }
                if low.contains("apt-get install") && !low.contains("--no-install-recommends") {
                    fs.push(Finding { code: "SC202", severity: "low", line: it.line,
                        instruction: it.cmd.clone(),
                        message: "apt-get install without --no-install-recommends".into(),
                        hint: "add --no-install-recommends to shrink the image" });
                }
                if low.contains("apt-get install") && !low.contains("rm -rf /var/lib/apt/lists") {
                    fs.push(Finding { code: "SC203", severity: "low", line: it.line,
                        instruction: it.cmd.clone(),
                        message: "apt lists not removed; package cache bloats the layer".into(),
                        hint: "append '&& rm -rf /var/lib/apt/lists/*'" });
                }
                if (low.contains("pip install") || low.contains("pip3 install"))
                    && !low.contains("--no-cache-dir") {
                    fs.push(Finding { code: "SC210", severity: "low", line: it.line,
                        instruction: it.cmd.clone(),
                        message: "pip install without --no-cache-dir leaves wheel cache".into(),
                        hint: "add --no-cache-dir" });
                }
                if low.split(|c: char| !c.is_alphanumeric()).any(|w| w == "sudo") {
                    fs.push(Finding { code: "SC220", severity: "medium", line: it.line,
                        instruction: it.cmd.clone(),
                        message: "'sudo' used in RUN; builds run as root already".into(),
                        hint: "remove sudo; use USER for privilege drops" });
                }
                if curl_pipe_sh(&it.args) {
                    fs.push(Finding { code: "SC221", severity: "high", line: it.line,
                        instruction: it.cmd.clone(),
                        message: "piping a downloaded script straight into a shell".into(),
                        hint: "download, verify a checksum, then execute" });
                }
                if secret_in(&it.args) {
                    fs.push(Finding { code: "SC230", severity: "critical", line: it.line,
                        instruction: it.cmd.clone(),
                        message: "possible hard-coded secret in RUN layer".into(),
                        hint: "use build secrets/args, never bake credentials into layers" });
                }
            }
            "ADD" => {
                let first = it.args.split_whitespace().next().unwrap_or("");
                let is_url = first.starts_with("http://") || first.starts_with("https://");
                let is_tar = [".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"]
                    .iter().any(|e| first.ends_with(e));
                if !is_url && !is_tar {
                    fs.push(Finding { code: "SC240", severity: "low", line: it.line,
                        instruction: it.cmd.clone(),
                        message: "ADD used for a plain file/dir".into(),
                        hint: "prefer COPY; ADD has surprising URL/tar semantics" });
                }
            }
            "COPY" => {
                if !copy_dot_seen
                    && it.args.split_whitespace().any(|t| t == "." || t == "./") {
                    copy_dot_seen = true;
                    fs.push(Finding { code: "SC250", severity: "info", line: it.line,
                        instruction: it.cmd.clone(),
                        message: "COPY . . early invalidates cache on any source change".into(),
                        hint: "copy dependency manifests + install first, then COPY ." });
                }
            }
            "EXPOSE" => {
                for tok in it.args.split(|c: char| !c.is_ascii_digit()) {
                    if tok == "22" {
                        fs.push(Finding { code: "SC260", severity: "medium", line: it.line,
                            instruction: it.cmd.clone(),
                            message: "EXPOSE 22 hints at running sshd in a container".into(),
                            hint: "avoid SSH in containers; use exec/attach instead" });
                    }
                }
            }
            _ => {}
        }
    }
    if saw_from && last_root {
        let ln = instrs.last().map(|i| i.line).unwrap_or(1);
        fs.push(Finding { code: "SC300", severity: "high", line: ln,
            instruction: "USER".into(),
            message: "container runs as root (no trailing USER directive)".into(),
            hint: "add a non-root 'USER' before the final CMD/ENTRYPOINT" });
    }
    if run_count >= 5 {
        let ln = instrs.last().map(|i| i.line).unwrap_or(1);
        fs.push(Finding { code: "SC310", severity: "info", line: ln,
            instruction: "RUN".into(),
            message: format!("{} separate RUN layers detected", run_count),
            hint: "combine related RUN steps with '&&' to reduce layers/size" });
    }
    fs
}

fn curl_pipe_sh(s: &str) -> bool {
    let l = s.to_lowercase();
    if let Some(pipe) = l.find('|') {
        let (left, right) = l.split_at(pipe);
        let has_dl = left.split(|c: char| !c.is_alphanumeric())
            .any(|w| w == "curl" || w == "wget");
        let right = right.trim_start_matches('|').trim();
        let runs_sh = right.starts_with("sh") || right.starts_with("bash")
            || right.starts_with("sudo");
        return has_dl && runs_sh;
    }
    false
}

fn secret_in(s: &str) -> bool {
    let l = s.to_lowercase();
    for kw in ["password", "passwd", "secret", "api_key", "api-key", "apikey",
               "access_key", "access-key", "token", "aws_secret"] {
        if let Some(pos) = l.find(kw) {
            let rest = &l[pos + kw.len()..];
            let rest = rest.trim_start();
            if rest.starts_with('=') || rest.starts_with(':') {
                let after = rest[1..].trim_start();
                if !after.is_empty() {
                    return true;
                }
            }
        }
    }
    false
}

fn max_severity(fs: &[Finding]) -> &'static str {
    let mut best = "";
    for f in fs {
        if best.is_empty() || sev_rank(f.severity) > sev_rank(best) {
            best = f.severity;
        }
    }
    best
}

fn json_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out
}

fn main() {
    let target = env::args().skip(1).find(|a| !a.starts_with("--"))
        .unwrap_or_else(|| "Dockerfile".into());
    let text = match fs::read_to_string(&target) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(2);
        }
    };
    let findings = lint(&text);
    let max = max_severity(&findings);
    let mut items = Vec::new();
    for f in &findings {
        items.push(format!(
            "    {{\"code\":\"{}\",\"severity\":\"{}\",\"line\":{},\"instruction\":\"{}\",\"message\":\"{}\",\"hint\":\"{}\"}}",
            f.code, f.severity, f.line, json_escape(&f.instruction),
            json_escape(&f.message), json_escape(f.hint)));
    }
    println!(
        "{{\n  \"tool\": \"shipcheck\",\n  \"path\": \"{}\",\n  \"max_severity\": \"{}\",\n  \"findings\": [\n{}\n  ]\n}}",
        json_escape(&target), max, items.join(",\n"));
    if sev_rank(max) >= sev_rank("medium") {
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_base() {
        assert_eq!(split_base("node:12"), ("node".to_string(), Some("12".to_string())));
        assert_eq!(split_base("python:3.11-slim AS build"),
                   ("python".to_string(), Some("3.11-slim".to_string())));
        assert_eq!(split_base("registry.io:5000/team/app:1.2"),
                   ("app".to_string(), Some("1.2".to_string())));
        assert_eq!(split_base("ubuntu"), ("ubuntu".to_string(), None));
    }

    #[test]
    fn test_eol_cve_critical() {
        let fs = lint("FROM node:12\nUSER app\nCMD [\"node\"]\n");
        assert!(fs.iter().any(|f| f.code == "SC120" && f.severity == "critical"));
    }

    #[test]
    fn test_root_user_flagged() {
        let fs = lint("FROM python:3.11-slim\nCMD [\"x\"]\n");
        assert!(fs.iter().any(|f| f.code == "SC300"));
    }

    #[test]
    fn test_root_dropped_ok() {
        let fs = lint("FROM python:3.11-slim\nUSER app\nCMD [\"x\"]\n");
        assert!(!fs.iter().any(|f| f.code == "SC300"));
    }

    #[test]
    fn test_secret_detection() {
        let fs = lint("FROM alpine:3.19\nRUN export AWS_SECRET=abc123 && build\nUSER app\n");
        assert!(fs.iter().any(|f| f.code == "SC230" && f.severity == "critical"));
    }

    #[test]
    fn test_curl_pipe_sh() {
        let fs = lint("FROM alpine:3.19\nRUN curl https://x.sh | sh\nUSER app\n");
        assert!(fs.iter().any(|f| f.code == "SC221"));
    }

    #[test]
    fn test_continuation_merge() {
        let fs = lint("FROM python:3.11-slim\nRUN apt-get update && \\\n    apt-get install -y --no-install-recommends curl && \\\n    rm -rf /var/lib/apt/lists/*\nUSER app\n");
        assert!(!fs.iter().any(|f| f.code == "SC201"));
    }
}
