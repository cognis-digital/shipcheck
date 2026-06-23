#!/usr/bin/env node
// JavaScript/Node port of the SHIPCHECK Dockerfile linter — stdlib only.
//
// Mirrors `shipcheck lint`: parses a Dockerfile (continuations + multi-stage)
// and emits the same SC-code findings as the Python reference, in JSON.
//
//   node index.js Dockerfile
//   node index.js Dockerfile --format json
import { readFileSync } from "fs";
import { pathToFileURL } from "url";

const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const CVE_TABLE = {
  "debian:8": "EOL: Debian 8 (jessie) is end-of-life; no security updates",
  "debian:9": "EOL: Debian 9 (stretch) is end-of-life",
  "ubuntu:16.04": "EOL: Ubuntu 16.04 reached end of standard support",
  "ubuntu:18.04": "EOL: Ubuntu 18.04 reached end of standard support",
  "node:10": "EOL: Node 10 is end-of-life; many unpatched CVEs",
  "node:12": "EOL: Node 12 is end-of-life; many unpatched CVEs",
  "python:3.6": "EOL: Python 3.6 is end-of-life; no security fixes",
  "python:3.7": "EOL: Python 3.7 is end-of-life; no security fixes",
  "alpine:3.9": "EOL: Alpine 3.9 no longer receives security updates",
};

const HEAVY_BASES = {
  ubuntu: "consider a -slim language image or distroless/alpine base",
  debian: "consider debian:<ver>-slim or distroless",
  node: "consider node:<ver>-slim or node:<ver>-alpine",
  python: "consider python:<ver>-slim",
  openjdk: "consider an -slim or eclipse-temurin:<ver>-jre image",
};

const SLIM = /(slim|alpine|distroless|-jre|busybox|scratch)/i;
const SECRET = /(password|passwd|secret|api[_-]?key|access[_-]?key|token|aws_secret)\s*[=:]\s*\S+/i;
const CURL_PIPE = /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash)\b/i;

export function parse(text) {
  const out = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const start = i + 1;
    const s = lines[i].trim();
    if (!s || s.startsWith("#")) continue;
    let buf = lines[i];
    while (buf.replace(/[ \t\r]+$/, "").endsWith("\\") && i + 1 < lines.length) {
      buf = buf.replace(/[ \t\r]+$/, "").slice(0, -1) + " " + lines[i + 1];
      i++;
    }
    buf = buf.trim();
    const sp = buf.indexOf(" ");
    const cmd = (sp < 0 ? buf : buf.slice(0, sp)).toUpperCase();
    const args = sp < 0 ? "" : buf.slice(sp + 1).trim();
    out.push({ line: start, cmd, args });
  }
  return out;
}

export function splitBase(refIn) {
  let ref = refIn.trim().split(/\s+as\s+/i)[0].trim();
  ref = ref.split("@")[0];
  let name = ref;
  let tag = null;
  const i = ref.lastIndexOf(":");
  if (i >= 0) {
    const maybe = ref.slice(i + 1);
    if (!maybe.includes("/")) {
      name = ref.slice(0, i);
      tag = maybe;
    }
  }
  const image = name.split("/").pop().toLowerCase();
  return [image, tag];
}

export function lint(text) {
  const instrs = parse(text);
  const fs = [];
  const add = (code, severity, line, instruction, message, hint = "") =>
    fs.push({ code, severity, line, instruction, message, hint });
  let lastRoot = true;
  let sawFrom = false;
  let runCount = 0;
  let copyDotSeen = false;

  for (const it of instrs) {
    const low = it.args.toLowerCase();
    if (it.cmd === "FROM") {
      sawFrom = true;
      lastRoot = true;
      const [image, tag] = splitBase(it.args);
      if (tag === null)
        add("SC101", "medium", it.line, it.cmd,
          `base image '${image}' has no explicit tag (defaults to :latest)`,
          "pin a specific version for reproducible builds");
      else if (tag === "latest")
        add("SC101", "medium", it.line, it.cmd,
          `base image '${image}' pinned to ':latest'`,
          "pin a specific version; ':latest' is not reproducible");
      if (HEAVY_BASES[image] && !SLIM.test(it.args))
        add("SC110", "info", it.line, it.cmd,
          `'${image}' is a large base image`, HEAVY_BASES[image]);
      if (tag !== null) {
        const adv = CVE_TABLE[`${image}:${tag}`];
        if (adv)
          add("SC120", adv.startsWith("EOL") ? "critical" : "high", it.line, it.cmd,
            `${image}:${tag} - ${adv}`, "upgrade to a supported, patched tag");
      }
    } else if (it.cmd === "USER") {
      const u = it.args.trim().toLowerCase();
      lastRoot = u === "root" || u === "0" || u === "";
    } else if (it.cmd === "RUN") {
      runCount++;
      if (low.includes("apt-get update") && !low.includes("install"))
        add("SC201", "high", it.line, it.cmd,
          "'apt-get update' in its own layer causes stale-cache installs",
          "chain 'apt-get update && apt-get install' in one RUN");
      if (low.includes("apt-get install") && !low.includes("--no-install-recommends"))
        add("SC202", "low", it.line, it.cmd,
          "apt-get install without --no-install-recommends",
          "add --no-install-recommends to shrink the image");
      if (low.includes("apt-get install") && !low.includes("rm -rf /var/lib/apt/lists"))
        add("SC203", "low", it.line, it.cmd,
          "apt lists not removed; package cache bloats the layer",
          "append '&& rm -rf /var/lib/apt/lists/*'");
      if (/pip3?\s+install/.test(low) && !low.includes("--no-cache-dir"))
        add("SC210", "low", it.line, it.cmd,
          "pip install without --no-cache-dir leaves wheel cache", "add --no-cache-dir");
      if (/\bsudo\b/.test(low))
        add("SC220", "medium", it.line, it.cmd,
          "'sudo' used in RUN; builds run as root already",
          "remove sudo; use USER for privilege drops");
      if (CURL_PIPE.test(it.args))
        add("SC221", "high", it.line, it.cmd,
          "piping a downloaded script straight into a shell",
          "download, verify a checksum, then execute");
      if (SECRET.test(it.args))
        add("SC230", "critical", it.line, it.cmd,
          "possible hard-coded secret in RUN layer",
          "use build secrets/args, never bake credentials into layers");
    } else if (it.cmd === "ADD") {
      const first = it.args.split(/\s+/)[0] || "";
      const isURL = first.startsWith("http://") || first.startsWith("https://");
      const isTar = [".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"].some((e) =>
        first.endsWith(e));
      if (!isURL && !isTar)
        add("SC240", "low", it.line, it.cmd, "ADD used for a plain file/dir",
          "prefer COPY; ADD has surprising URL/tar semantics");
    } else if (it.cmd === "COPY") {
      const toks = it.args.split(/\s+/);
      if (!copyDotSeen && toks.some((t) => t === "." || t === "./")) {
        copyDotSeen = true;
        add("SC250", "info", it.line, it.cmd,
          "COPY . . early invalidates cache on any source change",
          "copy dependency manifests + install first, then COPY .");
      }
    } else if (it.cmd === "EXPOSE") {
      for (const p of it.args.match(/\d+/g) || [])
        if (p === "22")
          add("SC260", "medium", it.line, it.cmd,
            "EXPOSE 22 hints at running sshd in a container",
            "avoid SSH in containers; use exec/attach instead");
    }
  }
  if (sawFrom && lastRoot) {
    const ln = instrs.length ? instrs[instrs.length - 1].line : 1;
    add("SC300", "high", ln, "USER",
      "container runs as root (no trailing USER directive)",
      "add a non-root 'USER' before the final CMD/ENTRYPOINT");
  }
  if (runCount >= 5) {
    const ln = instrs[instrs.length - 1].line;
    add("SC310", "info", ln, "RUN", `${runCount} separate RUN layers detected`,
      "combine related RUN steps with '&&' to reduce layers/size");
  }
  return fs;
}

export function maxSeverity(fs) {
  let best = null;
  for (const f of fs)
    if (best === null || SEV_RANK[f.severity] > SEV_RANK[best]) best = f.severity;
  return best;
}

const _isMain =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (_isMain) {
  const target = process.argv.slice(2).find((a) => !a.startsWith("--")) || "Dockerfile";
  let text;
  try {
    text = readFileSync(target, "utf8");
  } catch (e) {
    process.stderr.write(`error: ${e.message}\n`);
    process.exit(2);
  }
  const findings = lint(text);
  const max = maxSeverity(findings);
  console.log(JSON.stringify({ tool: "shipcheck", path: target, findings, max_severity: max }, null, 2));
  if (max && SEV_RANK[max] >= SEV_RANK.medium) process.exit(1);
}
